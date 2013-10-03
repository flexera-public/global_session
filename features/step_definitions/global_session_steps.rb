Given /^a keystore$/ do
  @keystore = KeyFactory.new
end

Given /^the following keys in my keystore:$/ do |data|
  data.raw.each do |keystore|
    @keystore.create(keystore.first, eval(keystore.last))
  end
end

Given /^I have the following mock_configs:$/ do |data|
  data.raw.each do |mock|
    mock_config(mock.first, eval(mock.last))
  end
end

Given /^a valid global session cookie$/ do
  @directory        = GlobalSession::Directory.new(mock_config, @keystore.dir)
  @original_session = GlobalSession::Session.new(@directory)
  @cookie           = @original_session.to_s
end

Given /^a valid V([0-9]+) cookie$/ do |n|
  @directory        = GlobalSession::Directory.new(mock_config, @keystore.dir)
  klass = GlobalSession::Session.const_get("V#{Integer(n)}".to_sym)
  @original_session = klass.new(@directory)
  @cookie           = @original_session.to_s
end

When /^a trusted signature is passed in$/ do
  @directory.authorities['authority1'].should_receive(:public_decrypt).never
end

When /^I have a valid digest$/ do
  @valid_digest = @original_session.signature_digest
end

When /^an insecure attribute has changed$/ do
  @cookie = tamper_with_insecure_attributes(@original_session.class, @cookie, {'favorite_color' => 'blue'})
end

Then /^everything is ok$/ do
  GlobalSession::Session.new(@directory, @cookie, @valid_digest).should be_a(GlobalSession::Session::Abstract)
end
