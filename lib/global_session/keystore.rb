# Copyright (c) 2014- RightScale Inc
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
require 'uri'

module GlobalSession
  # Keystore uses one or more filesystem directories as a backing store
  # for RSA keys of global session authorities. The directories should
  # contain one or more +*.pub+ files containing OpenSSH-format public
  # RSA keys. The name of the pub file determines the name of the
  # authority it represents.
  #
  # === The Local Authority
  # Directory will infer the name of the local authority (if any) by
  # looking for a private-key file in the keystore. If a +*.key+ file
  # is found, then its name is taken to be the name of the local
  # authority and all GlobalSessions created will be signed by that
  # authority's private key.
  #
  # If more than one private key file is found, Directory will raise
  # an error at initialization time.
  #
  class Keystore
    # @return [Configuration] shared configuration object
    attr_reader :configuration

    # @return [Hash] map of String authority-names to OpenSSL::PKey public-keys
    attr_reader :public_keys

    # @return [nil, String] name of local authority if we are one, else nil
    attr_reader :private_key_name

    # @return [nil,OpenSSL::PKey] local authority key if we are an authority, else nil
    attr_reader :private_key

    # @return a representation of the object suitable for printing to the console
    def inspect
      "<#{self.class.name} @configuration=#{@configuration.inspect}>"
    end

    def initialize(configuration)
      @configuration = configuration
      load
    end

    # Factory method to generate a new keypair for use with GlobalSession.
    #
    # @param [Integer,String] parameter keylength in bits (for RSA/DSA) or curve name (for EC)
    # @raise [ArgumentError] if cryptosystem is unknown to OpenSSL
    # @return [OpenSSL::PKey::PKey] a public/private keypair
    def self.create_keypair(cryptosystem=:RSA, parameter=nil)
      factory = OpenSSL::PKey.const_get(cryptosystem)
      # For earlier versions of Ruby, OpenSSL::PKey::EC did not have a
      # generate() method. For Ruby 2.5.8, which is what we upgraded to
      # for other GRS vulnerabilities, OpenSSL::PKey::EC now has a generate()
      # method, but it's different than the generate() method for other
      # cryptosystems. Therefore, exclude OpenSSL::PKey::EC below so it
      # continues to fall through the "else".
      if factory.respond_to?(:generate) && factory != OpenSSL::PKey::EC
        # parameter-free cryptosystem e.g. RSA, DSA. Default key length 1024,
        # which is really too small, but whose signatures are quite large.
        parameter ||= 1024
        factory.generate( parameter )
      else
        # parameterized family of cryptosystems (e.g. EC). Default curve is
        # compatible with JSON Web Signature (JWS) ES256 algorithm.
        parameter ||= 'prime256v1'
        alg = factory.new(parameter)
        alg.generate_key
      end
    rescue NameError => e
      raise ArgumentError, e.message
    end

    private

    # Load all public and/or private keys from location(s) specified in the configuration's
    # "keystore/public" and "keystore/private" directives.
    #
    # @raise [ConfigurationError] if some authority's public key has already been loaded
    def load
      locations = Array((configuration['keystore'] || {})['public'] || [])

      locations.each do |location|
        load_public_key(location)
      end

      location = (configuration['keystore'] || {})['private']
      location ||= ENV['GLOBAL_SESSION_PRIVATE_KEY']
      load_private_key(location) if location # then we must be an authority; load our key
    end

    # Load a single authority's public key, or an entire directory full of public keys. Assume
    # that the basenames of the key files are the authority names, e.g. "dev.pub" --> "dev".
    #
    # @param [String] path to file or directory to load
    # @raise [Errno::ENOENT] if path is neither a file nor a directory
    # @raise [ConfigurationError] if some authority's public key has already been loaded
    def load_public_key(path)
      @public_keys ||= {}

      if File.directory?(path)
        Dir.glob(File.join(path, '*')).each do |file|
          load_public_key(file)
        end
      elsif File.file?(path)
        name = File.basename(path, '.*')
        pem  = File.read(path)

        # Deal with modern ("BEGIN PUBLIC/PRIVATE KEY") and legacy ("BEGIN RSA PUBLIC KEY") formats
        if pem =~ /BEGIN RSA/
          key  = OpenSSL::PKey::RSA.new(pem)
        else
          key  = OpenSSL::PKey.read(pem)
        end

        # ignore private keys (which legacy config allowed to coexist with public keys)
        unless (key.private? rescue nil) || (key.private_key? rescue nil)
          if @public_keys.has_key?(name)
            raise ConfigurationError, "Duplicate public key for authority: #{name}"
          else
            @public_keys[name] = key
          end
        end
      else
        raise Errno::ENOENT.new("Path is neither a file nor a directory: " + path)
      end
    end

    # Load a private key. Assume that the basename of the key file is the local authority name,
    # e.g. "dev.key" --> "dev".
    #
    # @param [String] path to private-key file
    # @raise [Errno::ENOENT] if path is not a file
    # @raise [ConfigurationError] if some private key has already been loaded
    def load_private_key(path)
      if File.directory?(path)
        # Arbitrarily pick the first key file found in the directory
        path = Dir.glob(File.join(path, '*.key')).first
      end

      if File.file?(path)
        if @private_key.nil?
          name        = File.basename(path, '.*')
          pem         = File.read(path)
          private_key = OpenSSL::PKey.read(pem)

          raise ConfigurationError, "Expected #{key_file} to contain an RSA private key" unless (private_key.private? rescue nil) || (private_key.private_key? rescue nil)
          @private_key      = private_key
          @private_key_name = name
        else
          raise ConfigurationError, "Only one private key is allowed; already loaded #{@private_key_name}, cannot also load #{path}"
        end
      else
        raise Errno::ENOENT.new("Path is not a file: " + path)
      end
    end
  end
end
