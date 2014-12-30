require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

require 'global_session/rack'
require 'tempfile'

module Wacky
  # Stub directory used for nothing important
  class WildDirectory < GlobalSession::Directory
  end

  # Stub directory used in tests to overcome stupid flexmock behavior
  class FakeDirectory < GlobalSession::Directory
    attr_accessor :configuration, :keystore, :create_error, :load_error, :cookie

    def initialize(configuration=nil, keystore=nil, load_error=nil, cookie=nil)
      super(configuration, keystore)
      @configuration = configuration
      @keystore = keystore
      @load_error = load_error
      @cookie = cookie
    end

    def load_session(cookie)
      if @load_error
        le = @load_error
        @load_error = nil
        raise le
      else
        super(cookie)
      end
    end

    def create_session
      if @create_error
        le = @create_error
        @create_error = nil
        raise @create_error
      else
        super(@cookie)
      end
    end
  end
end

class FakeLogger
  def error(msg)
  end
end

describe GlobalSession::Rack::Middleware do
  include SpecHelper

  before(:all) do
    @key_factory = KeyFactory.new
    @key_factory.create('authority1', true)
    @key_factory.create('authority2', false)
    mock_config('common/attributes/signed', ['user'])
    mock_config('common/attributes/insecure', ['favorite_color'])
    mock_config('test/timeout', '60')
    mock_config('test/cookie/name', 'global_session_cookie')
    mock_config('test/trust', ['authority1'])
    mock_config('test/authority', 'authority1')
    mock_config('test/keystore/public', "file:///#{@key_factory.dir}")
    mock_config('test/keystore/private', "file:///#{@key_factory.dir}")
    @keystore = GlobalSession::Keystore.new(mock_config)
  end

  after(:all) do
    @key_factory.destroy
  end

  before(:each) do
    @config    = mock_config
    @directory = GlobalSession::Directory.new(@config, @key_factory.dir)

    @inner_app = flexmock('Rack App')
    @app = GlobalSession::Rack::Middleware.new(@inner_app, @config, @directory)

    @cookie_jar = flexmock('cookie jar')
    @cookie_jar.should_receive(:has_key?).with('global_session_cookie').and_return(false).by_default
    @cookie_jar.should_receive(:[]).with('global_session_cookie').and_return(nil).by_default
    @cookie_jar.should_receive(:[]=).with('global_session_cookie', Hash).by_default

    @env = {'rack.cookies' => @cookie_jar, 'SERVER_NAME' => 'baz.foobar.com'}
  end

  after(:each) do
    @key_factory.reset
    @directory = nil
    reset_mock_config
  end

  context :initialize do
    before(:each) do
      @inner_app.should_receive(:call).never
    end

    it 'uses a GlobalSession::Directory by default' do
      app = GlobalSession::Rack::Middleware.new(@inner_app, @config, @key_factory.dir)
      app.instance_variable_get(:@directory).kind_of?(GlobalSession::Directory).should be_true
    end

    it 'uses a custom directory class (classic notation)' do
      mock_config('common/directory', 'Wacky::WildDirectory')
      app = GlobalSession::Rack::Middleware.new(@inner_app, @config, @key_factory.dir)
      app.instance_variable_get(:@directory).kind_of?(Wacky::WildDirectory).should be_true
    end

    it 'uses a custom directory class (modern notation)' do
      mock_config('common/directory/class', 'Wacky::WildDirectory')
      app = GlobalSession::Rack::Middleware.new(@inner_app, @config, @key_factory.dir)
      app.instance_variable_get(:@directory).kind_of?(Wacky::WildDirectory).should be_true
    end
  end

  context :call do
    context 'reading the cookie' do
      before(:each) do
        @inner_app.should_receive(:call)
      end

      it 'reads the authorization header' do
        flexmock(@app).should_receive(:read_authorization_header).and_return(true)
        flexmock(@app).should_receive(:read_cookie).never
        flexmock(@app).should_receive(:create_session).never
        @app.call(@env)
      end

      it 'falls back to reading a cookie' do
        flexmock(@app).should_receive(:read_authorization_header).and_return(false)
        flexmock(@app).should_receive(:read_cookie).and_return(true)
        flexmock(@app).should_receive(:create_session).never
        @app.call(@env)
      end

      it 'falls back to creating a new session' do
        flexmock(@app).should_receive(:read_authorization_header).and_return(false)
        flexmock(@app).should_receive(:read_cookie).and_return(false)
        flexmock(@app).should_receive(:create_session).and_return(true)
        @app.call(@env)
      end
    end

    context 'when the session becomes invalid during a request' do
      before(:each) do
        @inner_app.should_receive(:call).and_return { |env| env['global_session'].invalidate!; [] }
      end

      it 'generates a new session and saves it to a cookie' do
        @cookie_jar.should_receive(:[]=).with('global_session_cookie', FlexMock.on { |x| x[:value] != nil && x[:domain] == 'foobar.com' })
        @app.call(@env)
      end
    end

    context 'when an error happens' do
      before(:each) do
        @directory = Wacky::FakeDirectory.new(@config, @keystore)
        @app.directory = @directory # since the app was already initialized
        @fresh_session = GlobalSession::Session.new(@directory)
        @directory.cookie = @fresh_session.to_s
        mock_config('common/directory', @directory)
        @inner_app.should_receive(:call)
        @cookie_jar.should_receive(:has_key?).with('global_session_cookie').and_return(true)
        @cookie_jar.should_receive(:[]).with('global_session_cookie').and_return('a cookie')
      end

      it 'swallows client errors' do
        @directory.load_error = GlobalSession::ClientError.new
        @app.call(@env)
        @env.should have_key('global_session')
        @env.should have_key('global_session.error')
        @env['global_session.error'].should be_a(GlobalSession::ClientError)
      end

      it 'swallows configuration errors' do
        @directory.load_error = GlobalSession::ConfigurationError.new
        @app.call(@env)
        @env.should have_key('global_session')
        @env.should have_key('global_session.error')
        @env['global_session.error'].should be_a(GlobalSession::ConfigurationError)
      end

      it 'raises other errors' do
        @directory.load_error = StandardError.new
        @inner_app.should_receive(:call).never
        expect { @app.call(@env) }.to raise_error(StandardError)
      end

      it "does not include the backtrace for expired session exceptions" do
        @directory.load_error = GlobalSession::ExpiredSession.new
        @env["rack.logger"] = FakeLogger.new
        flexmock(@env["rack.logger"]).should_receive(:error).with("GlobalSession::ExpiredSession while reading session cookie: GlobalSession::ExpiredSession")
        @app.call(@env)
        @env.should have_key('global_session')
        @env.should have_key('global_session.error')
        @env['global_session.error'].should be_a(GlobalSession::ExpiredSession)
      end
    end
  end

  context :renew_cookie do
    before(:each) do
      mock_config('test/renew', '15')
      @session = flexmock('global session')
      @env['global_session'] = @session
    end

    context 'when session is not expiring soon' do
      before(:each) do
        @session.should_receive(:expired_at).and_return(Time.at(Time.now.to_i + 15*3*60))
      end

      it 'does not renew the cookie' do
        @session.should_receive(:renew!).never
        @app.renew_cookie(@env)
      end
    end

    context 'when session is about to expire' do
      before(:each) do
        @session.should_receive(:expired_at).and_return(Time.at(Time.now.to_i + 5))
      end

      it 'auto-renews the cookie if requested' do
        @session.should_receive(:renew!).once
        @app.renew_cookie(@env)
      end

      context 'when the app disables renewal' do
        before(:each) do
          @env['global_session.req.renew'] = false
        end

        it 'does not update the cookie' do
          @cookie_jar.should_receive(:[]=).never
          @session.should_receive(:renew!).never
          @app.renew_cookie(@env)
        end
      end
    end
  end

  context :wipe_cookie do
    it 'wipes the cookie' do
      #First we'll wipe the old cookie
      @cookie_jar.should_receive(:[]=).with('global_session_cookie',
                                            FlexMock.hsh(:value=>nil, :domain=>'foobar.com'))
      #Then we'll set a new cookie
      @cookie_jar.should_receive(:[]=).with('global_session_cookie',
                                            FlexMock.on { |x| x[:value] != nil && x[:domain] == 'foobar.com' })
      @app.wipe_cookie(@env)
    end
    
    context 'when the local system is not an authority' do
      before(:each) do
        mock_config('test/authority', nil)
      end

      it 'does not wipe the cookie' do
        @cookie_jar.should_receive(:[]=).never
        @app.wipe_cookie(@env)
      end
    end
  end

  context :update_cookie do
    it 'uses the domain name associated with the HTTP request' do
      @cookie_jar.should_receive(:[]=).with('global_session_cookie', FlexMock.hsh(:domain=>'foobar.com'))
      @app.update_cookie(@env)
    end

    context 'when the configuration specifies a cookie domain' do
      before(:each) do
        mock_config('test/cookie/domain', 'foobar.com')
      end

      it 'sets cookies with the domain specified in the configuration' do
        @cookie_jar.should_receive(:[]=).with('global_session_cookie', FlexMock.hsh(:domain=>'foobar.com'))
        @app.update_cookie(@env)
      end
    end

    context 'when the app disables updates' do
      before(:each) do
        @env['global_session.req.update'] = false
      end

      it 'does not update the cookie' do
        @cookie_jar.should_receive(:[]=).never
        @app.update_cookie(@env)
      end
    end

    context 'when the local system is not an authority' do
      before(:each) do
        mock_config('test/authority', nil)
        @inner_app.should_receive(:call)
      end

      it 'does not update the cookie' do
        @cookie_jar.should_receive(:[]=).never
        @app.call(@env)
      end
    end
  end

  context :read_cookie do
    context 'with no cookie' do
      it 'returns false' do
        @app.read_cookie(@env).should be_false
        @env.should_not have_key('global_session')
      end
    end

    context 'with a cookie' do
      before(:each) do
        @original_session = GlobalSession::Session.new(@directory)
        @cookie = @original_session.to_s
      end

      it 'parses valid cookies and populates the env' do
        @cookie_jar.should_receive(:has_key?).with('global_session_cookie').and_return(true)
        @cookie_jar.should_receive(:[]).with('global_session_cookie').and_return(@cookie)
        @app.read_cookie(@env).should == true
        @env.should have_key('global_session')
        @env['global_session'].to_s.should == @cookie
      end

      it 'raises on malformed cookies' do
        @cookie_jar.should_receive(:has_key?).with('global_session_cookie').and_return(true)
        @cookie_jar.should_receive(:[]).with('global_session_cookie').and_return('mwahahaha')
        expect {
          @app.read_cookie(@env)
        }.to raise_error(GlobalSession::MalformedCookie)
      end
    end
  end

  context :read_authorization_header do
    context 'with no header' do
      it 'returns false' do
        @app.read_authorization_header(@env).should be_false
        @env.should_not have_key('global_session')
      end
    end

    context 'with an authorization header' do
      before(:each) do
        @original_session = GlobalSession::Session.new(@directory)
        @cookie = @original_session.to_s
      end

      it 'parses X-HTTP-Authorization and populates the env' do
        @env['X-HTTP_AUTHORIZATION'] = "Bearer #{@cookie}"
        @app.read_authorization_header(@env).should be_true
        @env.should have_key('global_session')
        @env['global_session'].to_s.should == @cookie
      end

      it 'parses HTTP-Authorization and populates the env' do
        @env['HTTP_AUTHORIZATION'] = "Bearer #{@cookie}"
        @app.read_authorization_header(@env).should be_true
        @env.should have_key('global_session')
        @env['global_session'].to_s.should == @cookie
      end

      it 'ignores non-bearer headers' do
        @env['HTTP_AUTHORIZATION'] = 'Banana 12345'
        @app.read_authorization_header(@env).should be_false
        @env.should_not have_key('global_session')
      end

      it 'raises on malformed bearer headers' do
        @env['HTTP_AUTHORIZATION'] = 'Bearer abcde'
        expect {
          @app.read_authorization_header(@env)
        }.to raise_error(GlobalSession::MalformedCookie)
        @env.should_not have_key('global_session')
      end
    end
  end
end
