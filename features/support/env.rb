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

$: << File.expand_path('../../..', __FILE__)
# We're using Jeweler, so our Gemfile can't reference our gemspec
$: << File.expand_path('../../../lib', __FILE__)

require 'tempfile'
require 'shellwords'
require 'thread'
require 'httpclient'
require 'spec/stubs/cucumber'
require 'spec/spec_helper'

require 'global_session'

class RightRailsTestWorld
  class ShellCommandFailed < Exception;
  end
  include SpecHelper

  @app_root       = nil
  @@database_name ||= "temp_global_session_#{Time.now.to_i}"
  @@http_client   = nil

  @@app_roots   = Set.new
  @@server_pids = Set.new

  attr_accessor :server_pid, :rails_version

  def application_port
    11415
  end

  def initialize
    @app_console_mutex = Mutex.new
  end

  # Return the app's RAILS_ROOT (shared across all scenarios/features in a given run!)
  def app_root
    unless @app_root
      @app_root ||= Dir.mktmpdir("global_session_rails")
      @@app_roots << @app_root
    end

    @app_root
  end

  # Construct a path relative to the app's RAILS_ROOT
  def app_path(*relative)
    File.join(app_root, *relative)
  end

  # Give the app's database name (shared across all scenarios/features in a given run!)
  def app_db_name
    @@database_name
  end

  # Run a shell command in app_dir, e.g. a rake task
  def app_shell(cmd, options={})
    options       = {:ignore_errors => false, :bundle_exec => true}.merge(options)
    ignore_errors = options[:ignore_errors]
    bundle_exec   = options[:bundle_exec]
    log           = !!(Cucumber.logger)

    cmd = "bundle exec #{cmd}" if bundle_exec

    Cucumber.logger.debug("bash> #{cmd}\n") if log

    Bundler.with_clean_env do
      #Work around ActiveSupport 2.3.x bug where they use Mutex without requiring thread
      ENV['RUBYOPT'] = '-rthread'

      Dir.chdir(app_root) do
        IO.popen("#{cmd} 2>&1", 'r') do |output|
          output.sync = true
          done        = false
          while !done
            begin
              Cucumber.logger.debug(output.readline + "\n") if log
            rescue EOFError
              done = true
            end
          end
        end
      end
    end

    $?.success?.should(be_true) unless ignore_errors
  end

  def app_shell_with_log(cmd, options={})
    log = !!(Cucumber.logger)
    delete_log
    app_shell("#{cmd} > #{log_file}", options)
  rescue Exception => e
    File.readlines(log_file).each { |l| Cucumber.logger.debug(l) } if log
    raise
  end

  def log_file
    app_path('log', 'shell.log')
  end

  def delete_log
    FileUtils.rm(log_file) if File.exist?(log_file)
  end

  MAX_CONSOLE_TIME = 60.0
  BASEDIR          = File.expand_path('../../..', __FILE__)

  # Run a console command using script/console
  def app_console(cmd, options={})
    repeat          = options[:repeat] || 1
    thing_to_return = options[:return] || :output
    app_console     = nil

    Bundler.with_clean_env do
      #Work around ActiveSupport 2.3.x bug where they use Mutex without requiring thread
      ENV['RUBYOPT'] = '-rthread'

      if options[:detach]
        Dir.chdir(app_root) do
          app_console = IO.popen('bundle exec script/console', 'r+')
        end
      else
        @app_console_mutex.synchronize do
          unless @app_console
            Dir.chdir(app_root) do
              @app_console = IO.popen('bundle exec script/console', 'r+')
            end
          end
          app_console = @app_console
        end
      end
    end

    t0 = Time.now.to_f
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
        done   = true
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
  def load_fixtures
    rails_fixtures_path = File.join(BASEDIR, 'fixtures', "rails_#{rails_version}", '.')
    raise ArgumentError, "Fixtures for rails #{rails_version} does not exist." unless File.exist?(rails_fixtures_path)
    FileUtils.cp_r(rails_fixtures_path, app_root)
  end

  def add_global_session_gem
    FileUtils.cp(app_path('config', 'environment_with_global_session_gem.rb'),
                 app_path('config', 'environment.rb'))
  end

  def add_global_session_middleware
    FileUtils.cp(app_path('config', 'environment_with_global_session_as_middleware.rb'),
                 app_path('config', 'environment.rb'))
  end

  def create_rails_app
    # clean from previous application
    stop_application
    clean_cookies

    # export template gemfile with special global_session dependency
    template_path = File.join(BASEDIR, 'fixtures', "rails_#{rails_version}", 'Gemfile.tmpl')
    raise ArgumentError, "Gemfile for rails #{rails_version} does not exist." unless File.exist?(template_path)
    File.open(app_path('Gemfile'), 'w') do |f|
      f << File.read(template_path) + "gem 'global_session', :path => '#{BASEDIR}'\n"
    end

    # install all of the gems
    ENV['BUNDLE_GEMFILE'] = app_path('Gemfile')
    app_shell('bundle install --local || bundle install', :bundle_exec => false)

    # create Rails app
    app_shell("rails . -q")
  end

  # Run rails application
  def run_application
    app_shell("script/server -p #{application_port} -d")
    loop do
      begin
        TCPSocket.new('localhost', application_port).close
        break
      rescue Errno::ECONNREFUSED
        Thread.pass
      end
    end

    self.server_pid = File.read(app_path('tmp', 'pids', 'server.pid')).to_i
    @@server_pids << server_pid
  end

  def stop_application
    unless server_pid.nil?
      Process.kill("KILL", server_pid)
      self.server_pid = nil
    end
  end

  def restart_application
    stop_application
    clean_cookies
    run_application
  end

  # http client
  def http_client
    @@http_client ||= HTTPClient.new
  end

  # Make request to our application
  def make_request(method, path, params = nil)
    http_client.request(method, "http://localhost:#{application_port}/#{path}", params)
  end

  def clean_cookies
    http_client.cookies.clear
  end

  at_exit do
    @@server_pids.each do |pid|
      Process.kill("KILL", pid) rescue nil
    end
    @@app_roots.each do |root|
      FileUtils.rm_rf(root)
    end
  end

end

World do
  RightRailsTestWorld.new
end

After do
  @keystore.destroy if @keystore
end
