Given /^a Rails ([\d\.]+) application$/ do |rails_version|
  @rails_version = rails_version
  prepare_to_create(@rails_version)

  app_shell("rails _#{@rails_version}_ . -q")
end

Given /^configuration fixtures are loaded$/ do
  load_fixtures(@rails_version)
end

Given /^database created$/ do
  app_shell('rake db:drop', :ignore_errors=>true)
  app_shell('rake db:create')
  app_shell('rake db:sessions:create')
  app_shell('rake db:migrate')
end

Given /^global_session added as a gem$/ do
  add_global_session_gem
  install_global_session_gem
end

Given /^I use (.+) environment$/ do |env|
  @rails_env = env
end

When /^I run \'.\/script\/generate\' with \'global_session_authority\'$/ do
  app_shell_with_log("./script/generate global_session_authority #{@rails_env}")
end

Then /^I should receive message about about successful result$/ do
  File.read(log_file).match("Don't forget to delete config/authorities/development.key").should_not be_nil
end

Then /^I should have the following files generated:$/ do |table|
  table.raw.map do |file|
    file = app_path(file)
    File.exist?(file).should be_true
  end
end

Given /^I use (.+) as a domain$/ do |domain|
  @domain = domain
end

When /^I run '\.\/script\/generate' with 'global_session'$/ do
  app_shell_with_log("./script/generate global_session #{@domain}")
end

Then /^I should receive message about successful result$/ do
  File.read(log_file).match("create  config/global_session.yml").should_not be_nil
end

Given /^global_session added as a middleware$/ do
  add_global_session_middleware
end

When /^I lunch my application on (\d+) port$/ do |port|
  @port = port
  run_application_at(@port)
end

Then /^I should have my application up and running$/ do
  lambda {
    TCPSocket.new('localhost', @port).close
  }.should_not raise_error(Errno::ECONNREFUSED)
end

Given /^global_session configured with local session integration$/ do
  add_local_session_integration
  restart_application
end

When /^I send (.+) request '(.+)'$/ do |method, path|
  @response = make_request(method.downcase.to_sym, path)
end

Then /^I should receive message "(.+)"$/ do |message|
  JSON::parse(@response.body)["message"].should match(message)
end

Then /^I have (\d+) cookie variable called:$/ do |cookie_num, cookie_names|
  http_client.cookies.size.should be_equal(cookie_num.to_i)
  http_client.cookies.map(&:name).sort.should == cookie_names.raw.flatten.sort
end

When /^I send (.+) request '(.+)' with the following:$/ do |method, path, data|
  @response = make_request(method.downcase.to_sym, path, data.rows_hash)
end

Then /^I should be redirected to '(.+)'$/ do |redirect_path|
  @response.status.should be_equal(302)
  @response.headers["Location"].should match(redirect_path)
  @response = make_request(:get, redirect_path)
end

Then /^I should receive in session the following variables:$/ do |data|
  JSON::parse(@response.body)["session"].should == data.rows_hash
end

Given /^I have data stored in local session:$/ do |data|
  session = '{ ' + data.raw.map do |pair|
    "'#{pair.first}' => '#{pair.last}'"
  end.join(',') + ' }'

  app_console("@session = ActiveRecord::SessionStore::Session.last")
  app_console("@session.data = #{session}")
  app_console("@session.save")
end

Given /^I have global_session expired$/ do
  @global_session_origin = http_client.cookies.first.value
  http_client.cookies.clear
end

Then /^I should receive empty session$/ do
  JSON::parse(@response.body)["session"].should == {}
end

Then /^I should have new global_session generated$/ do
  http_client.cookies.first.value.should_not == @global_session_origin
end
