Given /^a KeyFactory is on$/ do
  @keystore = KeyFactory.new
end

Given /^I have the following keystores:$/ do |data|
  data.raw.each do |keystore|
    @keystore.create(keystore.first, eval(keystore.last))
  end
end

Given /^I have the following mock_configs:$/ do |data|
  data.raw.each do |mock|
    mock_config(mock.first, eval(mock.last))
  end
end

When /^I load it from cookie successful$/ do
  @directory        = GlobalSession::Directory.new(mock_config, @keystore.dir)
  @original_session = GlobalSession::Session.new(@directory)
  @cookie           = @original_session.to_s
end

Then /^everything is ok$/ do
  GlobalSession::Session.should === GlobalSession::Session.new(@directory, @cookie)
end

When /^a trusted signature is passed in$/ do
  @directory.authorities['authority1'].should_receive(:public_decrypt).never
end

When /^I have a valid digest$/ do
  @valid_digest = @original_session.signature_digest
end

Then /^I should not recompute the signature$/ do
  GlobalSession::Session.should === GlobalSession::Session.new(@directory, @cookie, @valid_digest)
end

When /^an insecure attribute has changed$/ do
  zbin = GlobalSession::Encoding::Base64Cookie.load(@cookie)
  json = Zlib::Inflate.inflate(zbin)
  hash = GlobalSession::Encoding::JSON.load(json)
  hash['dx'] = {'favorite_color' => 'blue'}
  json = GlobalSession::Encoding::JSON.dump(hash)
  zbin = Zlib::Deflate.deflate(json, Zlib::BEST_COMPRESSION)
  @cookie = GlobalSession::Encoding::Base64Cookie.dump(zbin)
end
