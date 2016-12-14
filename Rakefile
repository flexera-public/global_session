# -*-ruby-*-
require 'rubygems'
require 'bundler/setup'
require 'bundler/gem_tasks'
require 'rake/clean'

require 'rspec/core/rake_task'

task :default => [:spec]

desc "Run unit tests"
RSpec::Core::RakeTask.new do |t|
  t.pattern = Dir['spec/**/*_spec.rb']
end

if defined?(Coveralls)
  Coveralls::RakeTask.new
end

CLEAN.include('pkg')
