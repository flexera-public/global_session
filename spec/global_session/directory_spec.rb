require File.expand_path(File.join(File.dirname(__FILE__), '..' , 'spec_helper'))

describe GlobalSession::Directory do
  include SpecHelper

  before(:all) do
    @keystore = KeyFactory.new
  end

  after(:all) do
    @keystore.destroy
  end  

  before(:each) do
    mock_config('test/timeout', 60)
    mock_config('test/cookie/name', 'session')
    mock_config('test/cookie/domain', 'example.com')
    mock_config('test/attributes/signed', ['user'])
    mock_config('test/attributes/insecure', ['favorite_color'])
  end

  after(:each) do
    @keystore.reset
    reset_mock_config
  end

  context :initialize do
    context 'given a configuration that specifies a local authority' do
      before(:each) do
        @authority_name = "authority#{rand(2**16)}"
        mock_config('test/authority', @authority_name)
      end

      context 'and a keystore with no private keys' do
        it 'raises ConfigurationError' do
          @keystore.create(@authority_name, false)
          lambda {
            GlobalSession::Directory.new(mock_config, @keystore.dir)
          }.should raise_error(GlobalSession::ConfigurationError)
        end
      end

      context 'and a keystore with an incorrectly-named private key' do
        it 'raises ConfigurationError' do
          @keystore.create('wrong_name', true)
          lambda {
            GlobalSession::Directory.new(mock_config, @keystore.dir)
          }.should raise_error(GlobalSession::ConfigurationError)
        end
      end

      context 'and a keystore with a correctly-named private key' do
        it 'succeeds' do
          @keystore.create(@authority_name, true)
          GlobalSession::Directory.should === GlobalSession::Directory.new(mock_config, @keystore.dir)
        end
      end
    end

    context 'given a configuration that does not specify a local authority' do
      it 'raises ConfigurationError' do
        lambda {
          GlobalSession::Directory.new(mock_config, @keystore.dir)
        }.should raise_error(GlobalSession::ConfigurationError)
      end
    end
  end

  context :create_session do
    before(:each) do
      @authority_name = "authority#{rand(2**16)}"
      mock_config('test/authority', @authority_name)
      @keystore.create(@authority_name, true)
      @directory = GlobalSession::Directory.new(mock_config, @keystore.dir)
    end

    context 'given a configuration that does not specify cookie/version' do
      it 'creates a V3 session' do
        @directory.create_session.should be_a(GlobalSession::Session::V3)
      end
    end

    context 'given a configuration that contains cookie/version=3' do
      before(:each) do
        mock_config('test/cookie/version', 3)
      end

      it 'creates a V3 session' do
        @directory.create_session.should be_a(GlobalSession::Session::V3)
      end
    end

    context 'given a configuration that contains cookie/version=2' do
      before(:each) do
        mock_config('test/cookie/version', 2)
      end

      it 'creates a V2 session' do
        @directory.create_session.should be_a(GlobalSession::Session::V2)
      end
    end

    context 'given a configuration that contains cookie/version=1' do
      before(:each) do
        mock_config('test/cookie/version', 1)
      end

      it 'creates a V1 session' do
        @directory.create_session.should be_a(GlobalSession::Session::V1)
      end
    end
  end
end