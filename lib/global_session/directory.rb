# Copyright (c) 2012 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require 'set'

module GlobalSession
  # The global session directory, which provides lookup and decision services
  # to instances of Session.
  #
  # The default implementation is simplistic, but should be suitable for most applications.
  # Directory is designed to be specialized via subclassing. To override the behavior to
  # suit your needs, simply create a subclass of Directory and add a configuration file
  # setting to specify the class name of your implementation:
  #
  #     common:
  #       directory:
  #         class: MyCoolDirectory
  #
  # == Key Management
  #
  # All key-related functionality has been delegated to the Keystore class as of
  # v3.1. Directory retains its key management hooks for downrev compatibility,
  # but mostly they are stubs for Keystore functionality.
  #
  # For more information about key mangement, please refer to the Keystore class.
  #
  class Directory
    # @return [Configuration] shared configuration object
    attr_reader :configuration

    # @return [Keystore] asymmetric crypto keys for signing authorities
    attr_reader :keystore

    # @return a representation of the object suitable for printing to the console
    def inspect
      "<#{self.class.name} @configuration=#{@configuration.inspect}>"
    end

    # Create a new Directory.
    #
    # @param [Configuration] shared configuration
    # @param optional [String] keystore_directory (DEPRECATED) if present, directory where keys can be found
    # @raise [ConfigurationError] if too many or too few keys are found, or if *.key/*.pub files are malformatted
    def initialize(configuration, keystore_directory=nil)
      @configuration = configuration
      @authorities = {}

      # Propagate a deprecated parameter
      # @deprecated remove for v4.0
      if keystore_directory.is_a?(String)
        all_files = Dir.glob(File.join(keystore_directory, '*'))
        public_keys = all_files.select { |kf| kf =~ /\.pub$/ }
        raise ConfigurationError, "No public keys (*.pub) found in #{keystore_directory}" if public_keys.empty?

        @configuration['common'] ||= {}
        @configuration['common']['keystore'] ||= {}
        @configuration['common']['keystore']['public'] = [keystore_directory]

        # Propagate a deprecated configuration option
        # @deprecated remove for v4.0
        if (private_key = @configuration['authority'])
          key_file = all_files.detect { |kf| kf =~ /#{private_key}\.key$/ }
          raise ConfigurationError, "Key file #{private_key}.key not found in #{keystore_directory}" unless key_file
          @configuration['common'] ||= {}
          @configuration['common']['keystore'] ||= {}
          @configuration['common']['keystore']['private'] = key_file
        end
      end

      @keystore = Keystore.new(configuration)
      @invalid_sessions = Set.new
    end

    # Create a new Session, initialized against this directory and ready to
    # be used by the app.
    #
    # DEPRECATED: If a cookie is provided, load an existing session from its
    # serialized form. You should use #load_session for this instead.
    #
    # @deprecated will be removed in GlobalSession v4; please use #load_session instead
    # @see load_session
    #
    # === Parameters
    # cookie(String):: DEPRECATED - Optional, serialized global session cookie. If none is supplied, a new session is created.
    #
    # === Return
    # session(Session):: the newly-initialized session
    #
    # ===Raise
    # InvalidSession:: if the session contained in the cookie has been invalidated
    # ExpiredSession:: if the session contained in the cookie has expired
    # MalformedCookie:: if the cookie was corrupt or malformed
    # SecurityError:: if signature is invalid or cookie is not signed by a trusted authority
    def create_session(cookie=nil)
      forced_version = configuration['cookie']['version']

      if cookie.nil?
        # Create a legitimately new session
        case forced_version
        when 3, nil
          Session::V3.new(self, cookie)
        when 2
          Session::V2.new(self, cookie)
        when 1
          Session::V1.new(self, cookie)
        else
          raise ArgumentError, "Unknown value #{forced_version} for configuration.cookie.version"
        end
      else
        warn "GlobalSession::Directory#create_session with an existing session is DEPRECATED -- use #load_session instead"
        load_session(cookie)
      end
    end

    # Unserialize an existing session cookie
    #
    # === Parameters
    # cookie(String):: Optional, serialized global session cookie. If none is supplied, a new session is created.
    #
    # === Return
    # session(Session):: the newly-initialized session
    #
    # ===Raise
    # InvalidSession:: if the session contained in the cookie has been invalidated
    # ExpiredSession:: if the session contained in the cookie has expired
    # MalformedCookie:: if the cookie was corrupt or malformed
    # SecurityError:: if signature is invalid or cookie is not signed by a trusted authority
    def load_session(cookie)
      Session.new(self, cookie)
    end

    # @return [Hash] map of String authority-names to OpenSSL::PKey public-keys
    # @deprecated will be removed in GlobalSession v4; please use Keystore instead
    # @see GlobalSession::Keystore
    def authorities
      @keystore.public_keys
    end

    # Determine the private key associated with this directory, to be used for signing.
    #
    # @return [nil,OpenSSL::PKey] local authority key if we are an authority, else nil
    # @deprecated will be removed in GlobalSession v4; please use Keystore instead
    # @see GlobalSession::Keystore
    def private_key
      @keystore.private_key || @private_key
    end

    # Determine the authority name associated with this directory's private session-signing key.
    #
    # @deprecated will be removed in GlobalSession v4; please use Keystore instead
    # @see GlobalSession::Keystore
    def local_authority_name
      @keystore.private_key_name
    end

    # Determine whether this system trusts a particular named authority based on
    # the settings specified in Configuration and/or the presence of public key
    # files on disk.
    #
    # === Parameters
    # authority(String):: The name of the authority
    #
    # === Return
    # trusted(true|false):: whether the local system trusts sessions signed by the specified authority
    def trusted_authority?(authority)
      if @configuration.has_key?('trust')
        # Explicit trust in just the authorities specified in the configuration
        @configuration['trust'].include?(authority)
      else
        # Implicit trust in any public key we found on disk
        @keystore.public_keys.keys.include?(authority)
      end
    end

    # Determine whether the given session UUID is valid. The default implementation only considers
    # a session to be invalid if its expired_at timestamp is in the past. Custom implementations
    # might want to consider other factors, such as whether the user has signed out of this node
    # or another node (perhaps using some sort of centralized lookup or single sign-out mechanism).
    #
    # === Parameters
    # uuid(String):: Global session UUID
    # expired_at(Time):: When the session expired (or will expire)
    #
    # === Return
    # valid(true|false):: whether the specified session is valid
    def valid_session?(uuid, expired_at)
      (expired_at > Time.now) && !@invalid_sessions.include?(uuid)
    end

    # Callback used by Session objects to report when the application code calls
    # #invalidate! on them. The default implementation of this method records
    # invalid session IDs using an in-memory data structure, which is not ideal
    # for most implementations.
    #
    # uuid(String):: Global session UUID
    # expired_at(Time):: When the session expired
    #
    # === Return
    # true:: Always returns true
    def report_invalid_session(uuid, expired_at)
      @invalid_sessions << uuid
    end
  end
end
