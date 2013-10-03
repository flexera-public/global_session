require 'rubygems'
$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib')))
require 'bundler/setup'
require 'spec'
require 'tempfile'
require 'flexmock'
require 'global_session'

Spec::Runner.configure do |config|
  config.mock_with :flexmock
end

class KeyFactory
  def initialize()
    @keystore = File.join( Dir.tmpdir, "#{Process.pid}_#{rand(2**32)}" )
    FileUtils.mkdir_p(@keystore)
  end

  def dir
    @keystore
  end

  def create(name, write_private)
    new_key     = OpenSSL::PKey::RSA.generate(1024)
    new_public  = new_key.public_key.to_pem
    new_private = new_key.to_pem
    File.open(File.join(@keystore, "#{name}.pub"), 'w') { |f| f.puts new_public }
    File.open(File.join(@keystore, "#{name}.key"), 'w') { |f| f.puts new_key } if write_private
  end

  def reset()
    FileUtils.rm_rf(File.join(@keystore, '*'))
  end

  def destroy()
    FileUtils.rm_rf(@keystore)
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
    @mock_config.instance_variable_set(:@config, hash)

    if(path || value)
      path = path.split('/')
      first_keys = path[0...-1]
      last_key   = path.last
      first_keys.each do |key|
        hash[key] ||= {}
        hash = hash[key]
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
