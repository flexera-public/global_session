RAILS_GEM_VERSION = '2.3.8' unless defined? RAILS_GEM_VERSION

require File.join(File.dirname(__FILE__), 'boot')
require 'global_session'

Rails::Initializer.run do |config|
  config.gem 'global_session'
  GlobalSession::Rails.activate(config)
  config.time_zone = 'UTC'
end
