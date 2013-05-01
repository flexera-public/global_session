Given /^a Rails ([\d\.]+) application$/ do |rails_version|
  self.rails_version = rails_version
  create_rails_app
  load_fixtures
end

Given /^the app is configured to use global_session$/ do
  step "I run './script/generate' with 'global_session'"
  step "I run './script/generate' with 'global_session_authority'"
end

Given /^a database$/ do
  app_shell('rake db:drop', :ignore_errors=>true)
  app_shell('rake db:create')
  app_shell('rake db:sessions:create')
  app_shell('rake db:migrate')
end

Given /^the global_session gem is available$/ do
  add_global_session_gem
end

Given /^I use (.+) environment$/ do |env|
  @rails_env = env
end

Given /^I use (.+) as a domain$/ do |domain|
  @domain = domain
end

Given /^global_session added as a middleware$/ do
  add_global_session_middleware
end

Given /^I have a local session with data:$/ do |data|
  # Make sure that a local session exists in the DB
  step "I send a GET request to 'happy/index'"

  session = '{ ' + data.raw.map do |pair|
    "'#{pair.first}' => '#{pair.last}'"
  end.join(',') + ' }'

  app_console("@session = ActiveRecord::SessionStore::Session.last")
  app_console("(@session.data = #{session}) if @session")
  app_console("@session.save if @session")
end

Given /^I have an expired global session$/ do
  @global_session_origin = http_client.cookies.first.value
  http_client.cookies.clear
end

When /^I run \'.\/script\/generate\' with \'global_session_authority\'$/ do
  app_shell_with_log("./script/generate global_session_authority #{@rails_env}")
end

Then /^I should receive a message about about successful result$/ do
  File.read(log_file).match("Don't forget to delete config/authorities/development.key").should_not be_nil
end

Then /^my app should have the following files::$/ do |table|
  table.raw.map do |file|
    file = app_path(file)
    File.exist?(file).should be_true
  end
end

When /^I run '\.\/script\/generate' with 'global_session'$/ do
  app_shell_with_log("./script/generate global_session #{@domain}")
end

When /^I send a (.+) request to '(.+)'$/ do |method, path|
  @response = make_request(method.downcase.to_sym, path)
end

When /^I send a (.+) request to '(.+)' with parameters:$/ do |method, path, data|
  @response = make_request(method.downcase.to_sym, path, data.rows_hash)
end

When /^I launch my application$/ do
  run_application
end

Then /^I should receive a message about successful result$/ do
  File.read(log_file).match("create  config/global_session.yml").should_not be_nil
end

Then /^I should have my application up and running$/ do
  lambda {
    TCPSocket.new('localhost', application_port).close
  }.should_not raise_error(Errno::ECONNREFUSED)
end

Then /^I should receive a message "(.+)"$/ do |message|
  JSON::parse(@response.body)["message"].should match(message)
end

Then /^I have (\d+) cookies? named:$/ do |cookie_num, cookie_names|
  http_client.cookies.should have(cookie_num.to_i).items
  http_client.cookies.map(&:name).sort.should == cookie_names.raw.flatten.sort
end

Then /^I should be redirected to '(.+)'$/ do |redirect_path|
  @response.status.should be_equal(302)
  @response.headers["Location"].should match(redirect_path)
  @response = make_request(:get, redirect_path)
end

Then /^I should receive in session the following variables:$/ do |data|
  JSON::parse(@response.body)["session"].should == data.rows_hash
end

Then /^I should receive empty session$/ do
  JSON::parse(@response.body)["session"].should == {}
end

Then /^I should have new global_session generated$/ do
  http_client.cookies.first.value.should_not == @global_session_origin
end
