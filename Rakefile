# -*-ruby-*-
require 'rubygems'
require 'rake'
require 'right_support'
require 'spec/rake/spectask'
require 'rubygems/package_task'
require 'rake/clean'
require 'cucumber/rake/task'

task :default => [:spec, :cucumber]

desc "Run unit tests"
Spec::Rake::SpecTask.new do |t|
  t.spec_files = Dir['spec/**/*_spec.rb']
  t.spec_opts = lambda do
    IO.readlines(File.join(File.dirname(__FILE__), 'spec', 'spec.opts')).map {|l| l.chomp.split " "}.flatten
  end
end

desc "Run functional tests"
Cucumber::Rake::Task.new do |t|
  t.cucumber_opts = %w{--tags ~@slow --color --format pretty}
end

if require_succeeds? 'jeweler'
  Jeweler::Tasks.new do |gem|
    # gem is a Gem::Specification; see http://docs.rubygems.org/read/chapter/20 for more options
    gem.name = "global_session"
    gem.homepage = "https://github.com/rightscale/global_session"
    gem.license = "MIT"
    gem.summary = %Q{Secure single-domain session sharing plugin for Rack and Rails.}
    gem.description = %Q{This Rack middleware allows several web apps in an authentication domain to share session state, facilitating single sign-on in a distributed web app. It only provides session sharing and does not concern itself with authentication or replication of the user database.}
    gem.email = "support@rightscale.com"
    gem.authors = ['Tony Spataro']
    gem.required_ruby_version = '~> 2.0'
    gem.files.exclude 'Gemfile*'
    gem.files.exclude 'features/**/*'
    gem.files.exclude 'fixtures/**/*'
    gem.files.exclude 'features/**/*'
    gem.files.exclude 'spec/**/*'
  end
  Jeweler::RubygemsDotOrgTasks.new
end

CLEAN.include('pkg')
