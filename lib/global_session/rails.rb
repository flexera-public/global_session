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

basedir = File.dirname(__FILE__)

require 'rack/contrib/cookies'
require 'action_pack'
require 'action_controller'

#Require the files necessary for Rails integration
require 'global_session/rack'
require 'global_session/rails/action_controller_class_methods'
require 'global_session/rails/action_controller_instance_methods'

# Enable ActionController integration.
class <<ActionController::Base
  include GlobalSession::Rails::ActionControllerClassMethods
end

ActionController::Base.instance_eval do
  include GlobalSession::Rails::ActionControllerInstanceMethods
end

module GlobalSession
  module Rails
    class <<self
      # Single Configuration object used by entire Rails app
      attr_accessor :configuration

      # Single Directory object used by entire Rails app
      attr_accessor :directory
    end

    def self.activate(rails_config, &block)
      config_file = File.join(::Rails.root, 'config', 'global_session.yml')
      self.configuration = GlobalSession::Configuration.new(config_file, ::Rails.env)

      dir_name = self.configuration['directory'] || 'GlobalSession::Directory'
      begin
        dir_klass = dir_name.constantize
      rescue NameError => e
        raise GlobalSession::ConfigurationError,
              "Unknown/malformed directory class '#{dir_name}' in config file: #{e.message}"
      end

      unless dir_klass.ancestors.include?(GlobalSession::Directory)
        raise GlobalSession::ConfigurationError,
              "Specified directory class '#{dir_name}' does not inherit from GlobalSession::Directory"
      end

      # Override Rails ActionPack middleware to store rails session inside GlobalSession
      if self.configuration['local_session_integration']
        require 'global_session/rails/abstract_store_extension'
      end

      authorities_dir = File.join(::Rails.root, 'config', 'authorities')
      self.directory = dir_klass.new(self.configuration, authorities_dir)

      # Add our middleware to the stack.
      rails_config.middleware.use(::Rack::Cookies)
      rails_config.middleware.use(::Rack::GlobalSession,
                                    self.configuration,
                                    self.directory,
                                    &block)

      return true
    end
  end
end
