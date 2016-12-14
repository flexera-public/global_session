require 'spec_helper'

# Depends on the following lets:
#     signature_method: either :private_encrypt or :sign
shared_examples_for 'all subclasses of Session::Abstract' do
  include SpecHelper

  before(:all) do
    @key_factory = KeyFactory.new
    @key_factory.create('authority1', true, parameter:key_generation_parameter)
    @key_factory.create('authority2', false, parameter:key_generation_parameter)
  end

  after(:all) do
    @key_factory.destroy
  end

  before(:each) do
    mock_config('common/attributes/signed', ['user'])
    mock_config('common/attributes/insecure', ['favorite_color'])
    mock_config('test/timeout', '60')
  end

  after(:each) do
    @key_factory.reset
    reset_mock_config
  end

  context :initialize do
    before(:each) do
      mock_config('test/trust', ['authority1'])
      mock_config('test/authority', 'authority1')
      @directory        = GlobalSession::Directory.new(mock_config, @key_factory.dir)
      @original_session = subject.new(@directory)
      @cookie           = @original_session.to_s
    end

    context 'when everything is copacetic' do
      it 'succeeds' do
        subject.new(@directory, @cookie).should be_a(GlobalSession::Session::Abstract)
      end
    end

    context 'when an insecure attribute changes' do
      before do
        @cookie = tamper_with_insecure_attributes(subject, @cookie, {'favorite_color' => 'blue'})
      end
      it 'succeeds' do
        subject.new(@directory, @cookie).should be_a(GlobalSession::Session::Abstract)
      end
    end

    context 'when a secure attribute is tampered with' do
      before do
        @cookie = tamper_with_signed_attributes(subject, @cookie, {'evil_haxor' => 'mwahaha'})
      end
      it 'raises SecurityError' do
        lambda {
          subject.new(@directory, @cookie)
        }.should raise_error(SecurityError)
      end
    end

    context 'when the signer is not trusted' do
      before do
        mock_config('test/trust', ['authority1'])
        mock_config('test/authority', 'authority1')
        @directory2 = GlobalSession::Directory.new(mock_config, @key_factory.dir)
        @cookie = subject.new(@directory2).to_s
        mock_config('test/trust', ['authority2'])
        mock_config('test/authority', nil)
      end
      it 'raises SecurityError' do
        lambda {
          subject.new(@directory, @cookie)
        }.should raise_error(SecurityError)
      end
    end

    context 'when the session is expired' do
      before do
        fake_now = Time.at(Time.now.to_i + 3_600*2)
        flexmock(Time).should_receive(:now).and_return(fake_now)
      end
      it 'raises ExpiredSession' do
        lambda {
          subject.new(@directory, @cookie)
        }.should raise_error(GlobalSession::ExpiredSession)
      end
    end

    context 'when an empty cookie is supplied' do
      it 'creates a new valid session' do
        subject.new(@directory, '').valid?.should be_true
      end

      context 'and there is no local authority' do
        before(:each) do
          flexmock(@directory).should_receive(:local_authority_name).and_return(nil)
          flexmock(@directory).should_receive(:private_key).and_return(nil)
        end

        it 'creates a new invalid session' do
          subject.new(@directory, '').valid?.should be_false
        end
      end
    end

    context 'when malformed cookies are supplied' do
      bad_cookies = [ '#$(%*#@%^&#!($%*#', rand(2**256).to_s(16) ]

      bad_cookies.each do |cookie|
        it 'copes' do
          lambda {
            subject.new(@directory, cookie)
          }.should raise_error(GlobalSession::MalformedCookie)
        end
      end
    end
  end

  context 'given a valid session' do
    before(:each) do
      mock_config('test/trust', ['authority1'])
      mock_config('test/authority', 'authority1')
      @directory = GlobalSession::Directory.new(mock_config, @key_factory.dir)
      @session   = subject.new(@directory)
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
        loaded_session = subject.new(@directory, @session.to_s)
        loaded_session.new_record?.should be_false
      end
    end

    context 'given a valid session received over the network' do
      let(:cookie) { @session.to_s }

      before do
        # force signature + reload + non-new-record
        @session = subject.new(@directory, cookie)
      end

      context :dirty? do
        it 'returns true when secure attributes change' do
          @session.dirty?.should be_false
          @session['user'] = rand(2**32-1)
          @session.dirty?.should be_true
        end

        it 'returns true when insecure attributes change' do
          @session.dirty?.should be_false
          @session['favorite_color'] = 'thistle'
          @session.dirty?.should be_true
        end
      end

      context :to_s do
        it 'reuses signature when nothing has changed' do
          flexmock(@directory.private_key).should_receive(signature_method).never
          @session.to_s
        end

        it 'reuses signature when insecure attributes change' do
          flexmock(@directory.private_key).should_receive(signature_method).never
          @session['favorite_color'] = 'mauve'
          @session.to_s
        end

        it 'computes signature when timestamps change' do
          flexmock(@directory.private_key).should_receive(signature_method).once.and_return('signature')
          @session.renew!
          @session.to_s
        end

        it 'computes signature when secure secure attributes change' do
          flexmock(@directory.private_key).should_receive(signature_method).once.and_return('signature')
          @session['user'] = rand(2**32-1)
          @session.to_s
        end
      end
    end
  end
end
