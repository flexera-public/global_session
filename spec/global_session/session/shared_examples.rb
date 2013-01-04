require 'spec_helper'

shared_examples_for 'all subclasses of Session::Abstract' do
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
    mock_config('common/attributes/signed', ['user'])
    mock_config('common/attributes/insecure', ['favorite_color'])
    mock_config('test/timeout', '60')
  end

  after(:each) do
    @keystore.reset
    reset_mock_config
  end

  context :initialize do
    before(:each) do
      mock_config('test/trust', ['authority1'])
      mock_config('test/authority', 'authority1')
      @directory        = GlobalSession::Directory.new(mock_config, @keystore.dir)
      @original_session = described_class.new(@directory)
      @cookie           = @original_session.to_s
    end

    context 'when everything is copacetic' do
      it 'succeeds' do
        described_class.new(@directory, @cookie).should be_a(GlobalSession::Session::Abstract)
      end
    end

    context 'when an insecure attribute changes' do
      before do
        @cookie = tamper_with_insecure_attributes(described_class, @cookie, {'favorite_color' => 'blue'})
      end
      it 'succeeds' do
        described_class.new(@directory, @cookie).should be_a(GlobalSession::Session::Abstract)
      end
    end

    context 'when a secure attribute is tampered with' do
      before do
        @cookie = tamper_with_signed_attributes(described_class, @cookie, {'evil_haxor' => 'mwahaha'})
      end
      it 'raises SecurityError' do
        lambda {
          described_class.new(@directory, @cookie)
        }.should raise_error(SecurityError)
      end
    end

    context 'when the signer is not trusted' do
      before do
        mock_config('test/trust', ['authority1'])
        mock_config('test/authority', 'authority1')
        @directory2 = GlobalSession::Directory.new(mock_config, @keystore.dir)
        @cookie = described_class.new(@directory2).to_s
        mock_config('test/trust', ['authority2'])
        mock_config('test/authority', nil)
      end
      it 'raises SecurityError' do
        lambda {
          described_class.new(@directory, @cookie)
        }.should raise_error(SecurityError)
      end
    end

    context 'when the session is expired' do
      before do
        fake_now = Time.at(Time.now.to_i + 3600)
        flexmock(Time).should_receive(:now).and_return(fake_now)
      end
      it 'raises ExpiredSession' do
        lambda {
          described_class.new(@directory, @cookie)
        }.should raise_error(GlobalSession::ExpiredSession)
      end
    end

    context 'when an empty cookie is supplied' do
      it 'creates a new valid session' do
        described_class.new(@directory, '').valid?.should be_true
      end

      context 'and there is no local authority' do
        before(:each) do
          flexmock(@directory).should_receive(:local_authority_name).and_return(nil)
          flexmock(@directory).should_receive(:private_key).and_return(nil)
        end

        it 'creates a new invalid session' do
          described_class.new(@directory, '').valid?.should be_false
        end
      end
    end

    context 'when malformed cookies are supplied' do
      bad_cookies = [ '#$(%*#@%^&#!($%*#', rand(2**256).to_s(16) ]

      bad_cookies.each do |cookie|
        it 'copes' do
          lambda {
            described_class.new(@directory, cookie)
          }.should raise_error(GlobalSession::MalformedCookie)
        end
      end
    end
  end

  context 'given a valid session' do
    before(:each) do
      mock_config('test/trust', ['authority1'])
      mock_config('test/authority', 'authority1')
      @directory = GlobalSession::Directory.new(mock_config, @keystore.dir)
      @session   = described_class.new(@directory)
    end

    context :renew! do
      it 'updates created_at' do
        old = @session.created_at
        future_time = Time.at(Time.now.to_i + 5)
        flexmock(Time).should_receive(:now).and_return future_time
        @session.renew!
        @session.created_at.should_not == old
      end

      it 'updates expired_at' do
        old = @session.expired_at
        future_time = Time.at(Time.now.to_i + 5)
        flexmock(Time).should_receive(:now).and_return future_time
        @session.renew!
        @session.expired_at.should_not == old
      end
    end

    context :new_record? do
      it 'returns true when the session was just created' do
        @session.new_record?.should be_true
      end

      it 'returns false when the session was loaded from a cookie' do
        loaded_session = described_class.new(@directory, @session.to_s)
        loaded_session.new_record?.should be_false
      end
    end
  end
end