require 'tempfile'

require 'rubygems'
require 'bundler/setup'
require 'flexmock'
require 'rspec'

require 'global_session'

begin
  require 'pry'
rescue LoadError
  # no-op; debugger is purposefully omitted from some environments
end

RSpec.configure do |config|
  config.mock_with :flexmock
end

class KeyFactory
  attr_reader :dir

  def initialize()
    @dir = File.join( Dir.tmpdir, "#{Process.pid}_#{rand(2**32)}" )
    FileUtils.mkdir_p(@dir)
  end

  def create(name, write_private, parameter:1024)
    case parameter
    when Integer
      new_key = GlobalSession::Keystore.create_keypair(:RSA, parameter)
      new_public  = new_key.public_key.to_pem
      new_private = new_key.to_pem
    when String
      new_key = GlobalSession::Keystore.create_keypair(:EC, parameter)
      new_public = OpenSSL::PKey::EC.new(new_key)
      new_public.private_key = nil
      new_public  = new_public.to_pem
      new_private = new_key.to_pem
    else
      raise ArgumentError, "Don't know what to do with parameter"
    end

    File.open(File.join(@dir, "#{name}.pub"), 'w') { |f| f.puts new_public }
    File.open(File.join(@dir, "#{name}.key"), 'w') { |f| f.puts new_private } if write_private
  end

  def reset()
    FileUtils.rm_rf(File.join(@dir, '*'))
  end

  def destroy()
    FileUtils.rm_rf(@dir)
  end
end

module SpecHelper
  # Getter for the GlobalSession::Configuration object
  # used by tests. It doubles as a mechanism for stuffing
  # config elements into said object.
  def mock_config(path=nil, value=nil)
    @mock_config ||= GlobalSession::Configuration.allocate
    @mock_config.instance_variable_set(:@environment, 'test')
    hash = @mock_config.instance_variable_get(:@config) || {}
    hash['common'] ||= {}
    hash['test'] ||= {}
    @mock_config.instance_variable_set(:@config, hash)

    if(path || value)
      path = path.split('/')
      first_keys = path[0...-1]
      last_key   = path.last
      first_keys.each do |key|
        hash[key] ||= {}
        hash = hash[key] if hash[key].is_a?(Hash)
      end
      hash[last_key] = value
    end

    return @mock_config
  end

  def reset_mock_config
    @mock_config = nil
  end

  def tamper_with_signed_attributes(klass, cookie, insecure_attributes)
    zbin = GlobalSession::Encoding::Base64Cookie.load(cookie)

    if klass == GlobalSession::Session::V3
      array, sig = GlobalSession::Session::V3.decode_cookie(cookie)
      array[5] = insecure_attributes
      json = GlobalSession::Encoding::JSON.dump(array)
      bin = GlobalSession::Session::V3.join_body(json, sig)
      zbin = bin
    elsif klass == GlobalSession::Session::V2
      bin = zbin
      array = GlobalSession::Encoding::Msgpack.load(bin)
      array[4] = insecure_attributes
      bin = GlobalSession::Encoding::Msgpack.dump(array)
      zbin = bin
    elsif klass == GlobalSession::Session::V1
      bin = Zlib::Inflate.inflate(zbin)
      hash = GlobalSession::Encoding::JSON.load(bin)
      hash['ds'] = insecure_attributes
      bin = GlobalSession::Encoding::JSON.dump(hash)
      zbin = Zlib::Deflate.deflate(bin, Zlib::BEST_COMPRESSION)
    else
      raise RuntimeError, "Don't know how to tamper with a #{described_class}"
    end

    GlobalSession::Encoding::Base64Cookie.dump(zbin)
  end

  def tamper_with_insecure_attributes(klass, cookie, insecure_attributes)
    zbin = GlobalSession::Encoding::Base64Cookie.load(cookie)

    if klass == GlobalSession::Session::V3
      array, sig = GlobalSession::Session::V3.decode_cookie(cookie)
      array[6] = insecure_attributes
      json = GlobalSession::Encoding::JSON.dump(array)
      bin = GlobalSession::Session::V3.join_body(json, sig)
      zbin = bin
    elsif klass == GlobalSession::Session::V2
      bin = zbin
      array = GlobalSession::Encoding::Msgpack.load(bin)
      array[5] = insecure_attributes
      bin = GlobalSession::Encoding::Msgpack.dump(array)
      zbin = bin
    elsif klass == GlobalSession::Session::V1
      bin = Zlib::Inflate.inflate(zbin)
      hash = GlobalSession::Encoding::JSON.load(bin)
      hash['dx'] = insecure_attributes
      bin = GlobalSession::Encoding::JSON.dump(hash)
      zbin = Zlib::Deflate.deflate(bin, Zlib::BEST_COMPRESSION)
    else
      raise RuntimeError, "Don't know how to tamper with a #{described_class}"
    end

    GlobalSession::Encoding::Base64Cookie.dump(zbin)
  end
end
