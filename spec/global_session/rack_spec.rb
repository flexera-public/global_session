require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

require 'global_session/rack'
require 'tempfile'

#Used in tests; see below
module Wacky
  class WildDirectory < GlobalSession::Directory; end
end

class FakeLogger
  def error(msg)
  end
end

describe GlobalSession::Rack::Middleware do
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
    @config = Tempfile.new("config")
  end

  after(:each) do
    @config.close(true)
    @keystore.reset
  end

  context :initialize do
    it 'uses a GlobalSession::Directory by default' do
      @config << <<EOS
  common:
    attributes:
      signed: [user]
      insecure: [favorite_color]
    timeout: 60
    cookie:
      name: global_session_cookie
      domain: foobar.com
    trust: [authority1]
    authority: authority1
EOS
      @config.close

      @app = GlobalSession::Rack::Middleware.new(@inner_app, @config.path, @keystore.dir)
      @app.instance_variable_get(:@directory).kind_of?(GlobalSession::Directory).should be_true
    end

    it 'uses a custom directory class if specified' do
      @config << <<EOS
  common:
    directory: Wacky::WildDirectory
    attributes:
      signed: [user]
      insecure: [favorite_color]
    timeout: 60
    cookie:
      name: global_session_cookie
      domain: foobar.com
    trust: [authority1]
    authority: authority1
EOS
      @config.close

      @app = GlobalSession::Rack::Middleware.new(@inner_app, @config.path, @keystore.dir)
      @app.instance_variable_get(:@directory).kind_of?(Wacky::WildDirectory).should be_true
    end
  end
end

describe GlobalSession::Rack::Middleware do
  include SpecHelper

  before(:all) do
    @keystore = KeyFactory.new
    @keystore.create('authority1', true)
    @keystore.create('authority2', false)
    mock_config('common/attributes/signed', ['user'])
    mock_config('common/attributes/insecure', ['favorite_color'])
    mock_config('test/timeout', '60')
    mock_config('test/cookie/name', 'global_session_cookie')
    mock_config('test/trust', ['authority1'])
    mock_config('test/authority', 'authority1')
  end

  after(:all) do
    @keystore.destroy
  end

  before(:each) do
    @config    = mock_config
    @directory = GlobalSession::Directory.new(@config, @keystore.dir)

    @inner_app = flexmock('Rack App')
    @inner_app.should_receive(:call).once.by_default
    @app = GlobalSession::Rack::Middleware.new(@inner_app, @config, @directory)

    @cookie_jar = flexmock('cookie jar')
    @cookie_jar.should_receive(:has_key?).with('global_session_cookie').and_return(false).by_default
    @cookie_jar.should_receive(:[]).with('global_session_cookie').and_return(nil).by_default
    @cookie_jar.should_receive(:[]=).with('global_session_cookie', Hash).by_default

    @env = {'rack.cookies' => @cookie_jar, 'SERVER_NAME' => 'baz.foobar.com'}
  end

  after(:each) do
    @keystore.reset
    reset_mock_config
  end

  context :renew_cookie do
    context 'when session is not expiring soon' do
      before(:each) do
        mock_config('test/renew', '15')
        @original_session = GlobalSession::Session.new(@directory)
        @cookie = @original_session.to_s
        @cookie_jar.should_receive(:has_key?).with('global_session_cookie').and_return(true)
        @cookie_jar.should_receive(:[]).with('global_session_cookie').and_return(@cookie)
      end

      it 'does not renew the cookie' do
        @app.call(@env)
        @env.should have_key('global_session')
        @env['global_session'].to_s.should == @cookie
      end
    end

    context 'when session is about to expire' do
      before(:each) do
        @original_session = GlobalSession::Session.new(@directory)
        @original_session.renew!(Time.at(Time.now.to_i + 15))
        @cookie = @original_session.to_s
        @cookie_jar.should_receive(:has_key?).with('global_session_cookie').and_return(true)
        @cookie_jar.should_receive(:[]).with('global_session_cookie').and_return(@cookie)
      end

      it 'auto-renews the cookie if requested' do
        mock_config('test/renew', '15')
        @app.call(@env)
        @env.should have_key('global_session')
        @env['global_session'].to_s.should_not == @cookie
      end

      context 'when the app disables renewal' do
        before(:each) do
          @env['global_session.req.renew'] = false
        end

        it 'does not update the cookie' do
          @cookie_jar.should_receive(:[]=).never
          @app.call(@env)
        end
      end
    end
  end

  context :wipe_cookie do
    before(:each) do
      flexmock(@app).should_receive(:read_cookie).once.and_raise(GlobalSession::ClientError)
    end

    it 'wipes the cookie' do
      #First we'll wipe the old cookie
      @cookie_jar.should_receive(:[]=).with('global_session_cookie',
                                            FlexMock.hsh(:value=>nil, :domain=>'baz.foobar.com'))
      #Then we'll set a new cookie
      @cookie_jar.should_receive(:[]=).with('global_session_cookie',
                                            FlexMock.on { |x| x[:value] != nil && x[:domain] == 'baz.foobar.com' })
      @app.call(@env)
    end
    
    context 'when the local system is not an authority' do
      before(:each) do
        mock_config('test/authority', nil)
      end

      it 'does not wipe the cookie' do
        @cookie_jar.should_receive(:[]=).never
        @app.call(@env)
      end
    end
  end

  context :update_cookie do
    before(:each) do
      @env['SERVER_NAME'] = 'baz.foobar.com'
    end

    it 'uses the server name associated with the HTTP request' do
      @cookie_jar.should_receive(:[]=).with('global_session_cookie', FlexMock.hsh(:domain=>'baz.foobar.com'))
      @app.call(@env)
    end

    context 'when the configuration specifies a cookie domain' do
      before(:each) do
        mock_config('test/cookie/domain', 'foobar.com')
      end

      it 'sets cookies with the domain specified in the configuration' do
        @cookie_jar.should_receive(:[]=).with('global_session_cookie', FlexMock.hsh(:domain=>'foobar.com'))
        @app.call(@env)
      end
    end

    context 'when the app disables updates' do
      before(:each) do
        @env['global_session.req.update'] = false
      end

      it 'does not update the cookie' do
        @cookie_jar.should_receive(:[]=).never
        @app.call(@env)
      end
    end

    context 'when the session becomes invalid during a request' do
      before(:each) do
        @inner_app.should_receive(:call).and_return { |env| env['global_session'].invalidate!; [] }
      end

      it 'generates a new session and saves it to a cookie' do
        @cookie_jar.should_receive(:[]=).with('global_session_cookie', FlexMock.on { |x| x[:value] != nil && x[:domain] == 'baz.foobar.com' })
        @app.call(@env)
      end

      it 'sends session_invalidated message to the directory' do
        flexmock(@directory).should_receive(:session_invalidated).once.and_return(true)
        @app.call(@env)
      end
    end

    context 'when the local system is not an authority' do
      before(:each) do
        mock_config('test/authority', nil)        
      end

      it 'does not update the cookie' do
        @cookie_jar.should_receive(:[]=).never
        @app.call(@env)
      end
    end
  end

  context :read_cookie do
    context 'with no cookie' do
      it 'populates the env with a new session' do
        @app.call(@env)
        @env.should have_key('global_session')
      end
    end

    context 'with a valid cookie' do
      before(:each) do
        @original_session = GlobalSession::Session.new(@directory)
        @cookie = @original_session.to_s
        @cookie_jar.should_receive(:has_key?).with('global_session_cookie').and_return(true)
        @cookie_jar.should_receive(:[]).with('global_session_cookie').and_return(@cookie)
      end

      it 'populates the env with a session object' do
        @app.call(@env)
        @env.should have_key('global_session')
        @env['global_session'].to_s.should == @cookie
      end
    end

    context 'with errors' do
      before(:each) do
        @cookie_jar.should_receive(:[]).with('global_session_cookie') #any number of times
        @fresh_session = GlobalSession::Session.new(@directory)
      end

      it 'swallows client errors' do
        flexmock(GlobalSession::Session).should_receive(:new).once.and_raise(GlobalSession::ClientError)
        flexmock(GlobalSession::Session).should_receive(:new).once.and_return(@fresh_session)
        @app.call(@env)
        @env.should have_key('global_session')
        @env.should have_key('global_session.error')
        @env['global_session.error'].should be_a(GlobalSession::ClientError)
      end

      it 'swallows configuration errors' do
        flexmock(GlobalSession::Session).should_receive(:new).once.and_raise(GlobalSession::ConfigurationError)
        flexmock(GlobalSession::Session).should_receive(:new).once.and_return(@fresh_session)
        @app.call(@env)
        @env.should have_key('global_session')
        @env.should have_key('global_session.error')
        @env['global_session.error'].should be_a(GlobalSession::ConfigurationError)
      end

      it 'raises other errors' do
        flexmock(GlobalSession::Session).should_receive(:new).once.and_raise(StandardError)
        flexmock(GlobalSession::Session).should_receive(:new).once.and_return(@fresh_session)
        @inner_app.should_receive(:call).never
        lambda { @app.call(@env) }.should raise_error(StandardError)
      end
      
      it "does not include the backtrace for expired session exceptions" do
        flexmock(GlobalSession::Session).should_receive(:new).once.and_raise(GlobalSession::ExpiredSession)
        flexmock(GlobalSession::Session).should_receive(:new).once.and_return(@fresh_session)
        @env["rack.logger"] = FakeLogger.new
        flexmock(@env["rack.logger"]).should_receive(:error).with("GlobalSession::ExpiredSession while reading session cookie: GlobalSession::ExpiredSession")
        @app.call(@env)
        @env.should have_key('global_session')
        @env.should have_key('global_session.error')
        @env['global_session.error'].should be_a(GlobalSession::ExpiredSession)
      end
    end
  end
end
