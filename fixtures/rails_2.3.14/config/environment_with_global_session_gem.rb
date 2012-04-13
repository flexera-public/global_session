RAILS_GEM_VERSION = '2.3.14' unless defined? RAILS_GEM_VERSION

require File.join(File.dirname(__FILE__), 'boot')

Rails::Initializer.run do |config|
  config.gem 'global_session'
  config.time_zone = 'UTC'
end
