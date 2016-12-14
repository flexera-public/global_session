# -*-ruby-*-
require 'rubygems'
require 'bundler/setup'
require 'bundler/gem_tasks'
require 'rake/clean'

require 'rspec/core/rake_task'
require 'cucumber/rake/task'

task :default => [:spec, :cucumber]

desc "Run unit tests"
RSpec::Core::RakeTask.new do |t|
  t.pattern = Dir['spec/**/*_spec.rb']
end

desc "Run functional tests"
Cucumber::Rake::Task.new do |t|
  t.cucumber_opts = %w{--color --format pretty}
end

if defined?(Coveralls)
  Coveralls::RakeTask.new
end

CLEAN.include('pkg')
