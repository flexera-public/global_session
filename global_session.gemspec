# -*- mode: ruby; encoding: utf-8 -*-

require 'rubygems'

spec = Gem::Specification.new do |s|
  s.required_rubygems_version = nil if s.respond_to? :required_rubygems_version=
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7")

  s.name    = 'global_session'
  s.version = '2.0.1'
  s.date    = '2012-01-04'

  s.authors = ['Tony Spataro']
  s.email   = 'support@rightscale.com'
  s.homepage= 'http://github.com/rightscale/global_session'

  s.summary = %q{Secure single-domain session sharing plugin for Rails.}
  s.description = %q{This plugin for Rails allows several web apps in an authentication domain to share session state, facilitating single sign-on in a distributed web app. It only provides session sharing and does not concern itself with authentication or replication of the user database.}

  s.add_runtime_dependency('right_support', ["~> 2.5"])

  s.add_runtime_dependency('simple_uuid', [">= 0.2.0"])
  s.add_runtime_dependency('json', ["~> 1.4"])
  s.add_runtime_dependency('msgpack', ["~> 0.4"])
  s.add_runtime_dependency('rack-contrib', ["~> 1.0"])

  basedir = File.dirname(__FILE__)
  candidates = ['global_session.gemspec', 'init.rb', 'LICENSE', 'README.rdoc'] +
            Dir['lib/**/*'] +
            Dir['rails/**/*'] +
            Dir['rails/**/*'] +
            Dir['rails_generators/**/*']
  s.files = candidates.sort
end
