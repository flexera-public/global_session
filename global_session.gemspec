# encoding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'global_session/version'

Gem::Specification.new do |spec|
  spec.name    = 'global_session'
  spec.version = GlobalSession::VERSION
  spec.authors = ['Tony Spataro']
  spec.email   = 'rubygems@rightscale.com'

  spec.summary = 'Reusable foundation code.'
  spec.description = 'A toolkit of useful, reusable foundation code created by RightScale.'
  spec.homepage = 'https://github.com/rightscale/right_support'
  spec.license = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").select { |f| f.match(%r{lib/|gemspec}) }
  spec.require_paths = ['lib']

  spec.required_ruby_version = Gem::Requirement.new('~> 2.1')

  spec.add_runtime_dependency('json', ['~> 1.4'])
  spec.add_runtime_dependency('rack-contrib', ['~> 1.0'])
  spec.add_runtime_dependency('right_support', ['< 4.0', '>= 2.8.2'])
  spec.add_runtime_dependency('simple_uuid', ['>= 0.2.0'])
end
