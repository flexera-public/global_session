source 'https://rubygems.org'

gemspec

group :test do
  gem 'flexmock'
  gem 'httpclient'
  gem 'jwt'
  gem 'msgpack'
  # Bumped rake to ~> 12.3.3 to address https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8130
  # https://github.com/ruby/rake/commit/5b8f8fc41a5d7d7d6a5d767e48464c60884d3aee
  gem 'rake', '~>12.3.3'
  gem 'rspec'
  # openssl ~> 2.2 is needed to gain access to the #public_to_pem
  # method to get the public key in PEM format.
  #
  # Though this issue calls out Ruby 2.7, similar behavior is seen on > Ruby 2.3:
  # https://github.com/ruby/openssl/issues/437
  #
  # Previously, creating an EC public/private key pair and then setting
  # private_key = nil would nil out the private key such that #to_pem
  # would return the public key.
  #
  # This no longer works for > Ruby 2.3. Something changed with Ruby or with
  # OpenSSL 1.1.1h that made setting the private_key attribute to nil a non-op,
  # as described in GitHub Issue #437.
  #
  # The workaround of installing the openssl gem ~>2.2 gives access to the
  # # public_to_pem method, which works to get the public key in PEM format.
  gem 'openssl', '~>2.2'
end

group :development do
  gem 'pry'
  gem 'pry-byebug'
end
