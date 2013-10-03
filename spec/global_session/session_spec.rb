require 'spec_helper'

describe GlobalSession::Session do
  include SpecHelper

  before(:all) do
    @keystore = KeyFactory.new
    @keystore.create('authority1', true)
    @keystore.create('authority2', false)
  end

  after(:all) do
    @keystore.destroy
  end

  before(:each) do
    mock_config('test/trust', ['authority1'])
    mock_config('test/authority', 'authority1')
    mock_config('common/attributes/signed', ['user'])
    mock_config('common/attributes/insecure', ['favorite_color'])
    mock_config('test/timeout', '60')
    @directory        = GlobalSession::Directory.new(mock_config, @keystore.dir)
  end

  [GlobalSession::Session::V1,GlobalSession::Session::V2,GlobalSession::Session::V3].each do |k|
    context "given a valid serialized #{k}" do
      before :each do
        @cookie = k.new(@directory).to_s
      end

      context :new do
        it 'creates a compatible session object' do
          @session = GlobalSession::Session.new(@directory, @cookie)
          @session.should be_a(k)
        end
      end

      context :decode_cookie do
        it 'returns useful debug info' do
          h = k.decode_cookie(@cookie)
          h.should respond_to(:each)
        end
      end
    end
  end

  context 'given garbage' do
    it 'raises ArgumentError'
  end
end
