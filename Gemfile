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
end

group :development do
  gem 'pry'
  gem 'pry-byebug'
end
