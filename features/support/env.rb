#--
# Copyright: Copyright (c) 2010 RightScale, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# 'Software'), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWAsRE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#++

require 'rubygems'
require 'bundler/setup'

require 'tempfile'
require 'shellwords'
require 'thread'
require 'httpclient'
require 'spec/stubs/cucumber'
require 'spec/spec_helper'

#for String#to_const and other utility stuff
# require 'right_support'

$basedir = File.expand_path('../../..', __FILE__)
$libdir  = File.join($basedir, 'lib')
require File.join($libdir, 'global_session')

class RightRailsTestWorld
  class ShellCommandFailed < Exception; end
  include SpecHelper

  def initialize
    @app_console_mutex = Mutex.new
  end

  # Return the app's RAILS_ROOT (shared across all scenarios/features in a given run!)
  def app_root
    @@app_root ||= Dir.mktmpdir('global_session')

    unless File.directory?(@@app_root)
      FileUtils.mkdir_p(@@app_root)
    end

    @@app_root
  end

  # Construct a path relative to the app's RAILS_ROOT
  def app_path(*relative)
    File.join(app_root, *relative)
  end

  # Give the app's database name (shared across all scenarios/features in a given run!)
  def app_db_name
    @@database_name ||= "temp_global_session_#{Time.now.to_i}"
    @@database_name
  end

  # Run a shell command in app_dir, e.g. a rake task
  def app_shell(cmd, options={})
    ignore_errors = options[:ignore_errors] || false
    log = !!(Cucumber.logger)

    Cucumber.logger.debug("bash> #{cmd}\n") if log

    Dir.chdir(app_root) do
      IO.popen("#{cmd} 2>&1", 'r') do |output|
        output.sync = true
        done = false
        while !done
          begin
            Cucumber.logger.debug(output.readline + "\n") if log
          rescue EOFError
            done = true
          end
        end
      end
    end

    $?.success?.should(be_true) unless ignore_errors
  end

  def app_shell_with_log(cmd, options={})
    delete_log
    app_shell("#{cmd} > #{log_file}", options)
  end

  def log_file
    app_path('log', 'shell.log')
  end

  def delete_log
    FileUtils.rm(log_file) if File.exist?(log_file)
  end

  MAX_CONSOLE_TIME = 60.0

  # Run a console command using script/console
  def app_console(cmd, options={})
    repeat = options[:repeat] || 1
    thing_to_return = options[:return] || :output
    app_console = nil

    if options[:detach]
      Dir.chdir(app_root) do
        app_console = IO.popen('script/console', 'r+')
      end
    else
      @app_console_mutex.synchronize do
        unless @app_console
          Dir.chdir(app_root) do
            @app_console = IO.popen('script/console', 'r+')
          end
        end
        app_console = @app_console
      end
    end

    t0   = Time.now.to_f
    app_console.puts 'result = begin'
    repeat.times do
      app_console.puts cmd
    end
    app_console.puts 'rescue Exception => e'
    app_console.puts 'puts "--OH NOES-- - #{e.class.name} - #{e.message}"'
    app_console.puts 'end'
    app_console.puts 'puts "--KTHXBYE-- #{result.inspect}"'
    app_console.puts 'quit' if options[:detach]

    Cucumber.logger.debug("irb> #{cmd}")

    done = false

    output = []

    while (Time.now.to_f - t0) < MAX_CONSOLE_TIME && !done
      line = app_console.readline
      if line =~ /^--OH NOES--/
        error = line.gsub('--OH NOES-- - ', '').chomp
      elsif line =~ /^--KTHXBYE--/
        result = line.split(' ', 2).second.chomp
        done = true
      else
        output << line
        Cucumber.logger.debug(line)
      end
    end

    (Time.now.to_f - t0).should(be <= MAX_CONSOLE_TIME)

    if options[:expect].is_a?(Class) && options[:expect].ancestors.include?(Exception)
      error.should =~ Regexp.new("^#{Regexp.escape(options[:expect].name)} -")
    elsif !options[:ignore_errors]
      error.should(be_nil) unless options[:ignore_errors]
    end

    case options[:expect]
      when String
        result.should == options[:expect]
      when Regexp
        result.should =~ options[:expect]
      when NilClass
        #no expectation
    end

    case thing_to_return
      when :output
        return output
      when :result
        return result
      else
        raise ArgumentError, "Unknown :return #{thing_to_return}"
    end
  end

  # Set of methods to work with fixtures
  def load_fixtures(rails_version)
    rails_fixtures_path = File.join($basedir, 'fixtures', "rails_#{rails_version}", '.')
    raise ArgumentError, "Fixtures for rails #{rails_version} does not exist." unless File.exist?(rails_fixtures_path)
    FileUtils.cp_r(rails_fixtures_path, app_root)
  end

  def install_global_session_gem
    FileUtils.cp_r($basedir, app_path('vendor', 'plugins', 'global_session'))
  end

  def add_global_session_gem
    FileUtils.cp(app_path('config', 'environment_with_global_session_gem.rb'),
                 app_path('config', 'environment.rb'))
  end

  def add_global_session_middleware
    FileUtils.cp(app_path('config', 'environment_with_global_session_as_middleware.rb'),
                 app_path('config', 'environment.rb'))
  end

  def add_local_session_integration
    gbl_config_file = app_path('config', 'global_session.yml')

    config = YAML.load_file(gbl_config_file)
    config["common"]["local_session_integration"] = true

    File.open(gbl_config_file, 'w') do |f|
      YAML.dump(config, f)
    end
  end

  def prepare_to_create(rails_version)
    # clean from previous application
    stop_application
    clean_cookies
    FileUtils.rm_rf(@@app_root) if defined? @@app_root

    # export gemfile
    template_path = File.join($basedir, 'fixtures', "rails_#{rails_version}", 'Gemfile.tmpl')
    raise ArgumentError, "Gemfile for rails #{rails_version} does not exist." unless File.exist?(template_path)
    File.open(app_path('Gemfile'), 'w') do |f|
      f << File.read(template_path) + "gem 'global_session', :path => '#{$basedir}'\n"
    end

    # reassign path to gemfile and run bundle install
    ENV['BUNDLE_GEMFILE'] = app_path('Gemfile')
    Bundler.with_clean_env do
      app_shell('bundle install')
    end
  end

  # Run rails application
  def run_application_at(port)
    @@port = port
    app_shell("./script/server -p #{port} -d")
    loop do
      begin
        TCPSocket.new('localhost', port).close
        break
      rescue Errno::ECONNREFUSED
      end
    end
    @@server_pid = File.read(app_path('tmp', 'pids', 'server.pid')).to_i
  end

  def stop_application
    Process.kill("KILL", @@server_pid) if defined? @@server_pid
  end

  def restart_application
    stop_application
    clean_cookies
    run_application_at(@@port)
  end

  # http client
  def http_client
    @@client ||= HTTPClient.new
  end

  # Make request to our application
  def make_request(method, path, params = nil)
    http_client.request(method, "http://localhost:#{@@port}/#{path}", params)
  end

  def clean_cookies
    http_client.cookies.clear
  end

  at_exit do
    Process.kill("KILL", @@server_pid) if defined? @@server_pid
    FileUtils.rm_rf(@@app_root) if defined? @@app_root
  end

end

World do
  RightRailsTestWorld.new
end

After do
  @keystore.destroy if @keystore
end
