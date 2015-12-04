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

require 'yaml'
require 'erb'

module GlobalSession
  # Central point of access for GlobalSession configuration information. This is
  # mostly a very thin wrapper around the serialized hash written to the YAML config
  # file.
  #
  # The configuration is stored as a set of nested hashes and accessed by the code
  # using hash lookup; for example, we might ask for +Configuration['cookie']['domain']+
  # if we wanted to know which domain the cookie should be set for.
  #
  # The following settings are supported:
  # * attributes
  #    * signed
  #    * insecure
  # * ephemeral
  # * timeout
  # * renew
  # * authority (optional - inferred from presence of private key file)
  # * trust (optional - inferred from presence/name of public key files)
  # * directory
  # * cookie
  #     * version
  #     * name
  #     * domain
  #
  # === Config Environments
  # The operational environment of global_session defines which section
  # of the configuration file it gets its settings from. When used with
  # a web app, the environment should be set to the same environment as
  # the web app. (If using Rails integration, this happens for you
  # automatically.)
  #
  # === Environment-Specific Settings
  # The top level of keys in the configuration hash are special; they provide different
  # sections of settings that apply in different environments. For instance, a Rails
  # application might have one set of settings that apply in the development environment;
  # these would appear under +Configuration['development']+. Another set of settings would
  # apply in the production environment and would appear under +Configuration['production']+.
  #
  # === Common Settings
  # In addition to having one section for each operating environment, the configuration
  # file can specify a 'common' section for settings that apply
  #
  # === Lookup Mechanism
  # When the code asks for +Configuration['foo']+, we first check whether the current
  # environment's config section has a value for foo. If one is found, we return that.
  #
  # If no environment-specific setting is found, we check the 'common' section and return
  # the value found there.
  #
  # === Config File Location
  # The name and location of the config file depend on the Web framework with which
  # you are integrating; see GlobalSession::Rails for more information.
  #
  class Configuration
    # @return a representation of the object suitable for printing to the console
    def inspect
      "<#{self.class.name} @environment=#{@environment.inspect}>"
    end

    def to_hash
      @config.dup
    end

    # Create a new Configuration object
    #
    # === Parameters
    # config(String|Hash):: Absolute filesystem path to the configuration file, or Hash containing configuration
    # environment(String):: Config file section from which to read settings
    #
    # === Raise
    # MissingConfiguration:: if config file is missing or unreadable
    # TypeError:: if config file does not contain a YAML-serialized Hash
    def initialize(config, environment)
      if config.is_a?(Hash)
        @config = config
      elsif File.file?(config)
        yaml = ERB.new(File.read(config)).result
        data = YAML.load(yaml)
        unless data.is_a?(Hash)
          raise TypeError, "Configuration file #{File.basename(config)} must contain a hash as its top-level element"
        end
        @config = data
      else
        raise MissingConfiguration, "Missing or unreadable configuration file #{config}"
      end

      @environment = environment
      validate
    end

    # Reader for configuration elements. The reader first checks
    # the current environment's settings section for the named
    # value; if not found, it checks the common settings section.
    #
    # === Parameters
    # key(String):: Name of configuration element to retrieve
    #
    # === Return
    # value(String):: the value of the configuration element
    def [](key)
      get(key, true)
    end

    # Writer for configuration elements. Writes to an environment-specific stanza if one is present,
    # else writes to the common stanza. DOES NOT OVERWRITE the key's value if it already has one!
    #
    # @param [String] key
    # @param optional [Object] the value to write, or empty-hash as a default
    def []=(key, value={})
      if @config.has_key?(@environment)
        @config[@environment][key] ||= value
      else
        @config['common'][key] ||= value
      end
    rescue NoMethodError
      raise MissingConfiguration, "Configuration key '#{key}' not found"
    end

    # Determine whether a given configuration key was specified.
    #
    # @return [Boolean] true if the key is present in the common or per-environment stanzas
    def has_key?(k)
      @config[@environment].has_key?(k) || @config['common'].has_key?(k)
    end

    alias key? has_key?

    def validate # :nodoc
      ['attributes/signed', 'cookie/name', 'timeout'].each {|k| validate_presence_of k}
    end

    protected

    # Helper method to check the presence of a key.  Used in #validate.
    #
    # === Parameters
    # key(String):: key name; for nested hashes, separate keys with /
    #
    # === Return
    # true always
    def validate_presence_of(key)
      elements = key.split '/'
      top_key = elements.shift
      object = get(top_key, true) # pretend we're validated in order to get inheritance
      if object.nil?
        msg = "Configuration does not specify required element '#{top_key}'"
        raise MissingConfiguration, msg
      end
      elements.each do |element|
        object = object[element] if object
        if object.nil?
          msg = "Configuration does not specify required element #{elements.map { |x| "['#{x}']"}.join('')}"
          raise MissingConfiguration, msg
        end
      end
      true
    end

    private

    # Get a configuration key.
    #
    # @return [Object] the value of the desired key
    # @raise [MissingConfiguration] if the key is not found
    # @param [String] key
    # @param [Boolean] if true, check both the common and per-environment stanzas for the key
    def get(key, validated) # :nodoc
      if validated
        # Fancy inheritance logic
        if ('common' == key) && @config.key?(key)
          # The common stanza itself
          @config[key]
        elsif (@environment == key) && @config.key?(key)
          # The environment-specific stanza itself
          @config[key]
        elsif @config.key?(@environment) && @config[@environment].key?(key)
          # Some key in the environment-specific stanza
          return @config[@environment][key]
        elsif @config.key?('common') && @config['common'].key?(key)
          # By process of elimination, some key in the common stanza
          @config['common'][key]
        end
      else
        # Fail sauce
        raise MissingConfiguration, "Configuration key '#{key}' not found"
      end
    end
  end
end
