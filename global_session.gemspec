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

  # Bump json to ~> 2.3.0 to address [GitHub CVE-2020-10663](https://github.com/advisories/GHSA-jphg-qwrw-7w9g)
  spec.add_runtime_dependency('json', ['~> 2.3.0'])
  # Bump rack to ~> 2.1.4.1 to address:
  # * [GitHub CVE-2020-8161](https://github.com/advisories/GHSA-5f9h-9pjv-v6j7)
  # * [GitHub CVE-2020-8184](https://github.com/advisories/GHSA-j6w9-fv6q-3q52)
  # * [GitHub CVE-2022-30122](https://github.com/advisories/GHSA-hxqx-xwvh-44m2)
  # * [GitHub CVE-2022-30123](https://github.com/advisories/GHSA-wq4h-7r42-5hrr)
  spec.add_runtime_dependency('rack', ['~> 2.1.4.1'])
  spec.add_runtime_dependency('rack-contrib', ['~> 1.0'])
  spec.add_runtime_dependency('right_support', ['>= 2.14.1', '< 3.0'])
  spec.add_runtime_dependency('simple_uuid', ['>= 0.2.0'])
end
