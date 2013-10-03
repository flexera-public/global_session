require 'spec_helper'
require File.expand_path('../shared_examples', __FILE__)

describe GlobalSession::Session::Abstract do
  include SpecHelper

  before(:all) do
    @keystore = KeyFactory.new
    @keystore.create('authority1', true)
    @keystore.create('authority2', false)
  end

  after(:all) do
    @keystore.destroy
  end

  # Abstract#initialize can't be invoked directly, so we test its subclasses
  # instead.
  GlobalSession::Session::Abstract.subclasses.each do |klass|
    context "given a valid serialized #{klass}" do
      let(:subclass) { klass.to_const }
      before(:each) do
        mock_config('test/trust', ['authority1'])
        mock_config('test/authority', 'authority1')
        mock_config('test/timeout', 60)
        mock_config('test/attributes/signed', ['user'])
        mock_config('test/attributes/unsigned', ['account'])
        @directory = GlobalSession::Directory.new(mock_config, @keystore.dir)
        @session = subclass.new(@directory)
      end

      context :to_hash do
        before(:each) do
          @hash = @session.to_hash
        end

        it 'includes metadata' do
          @hash[:metadata][:id].should == @session.id
          @hash[:metadata][:created_at].should == @session.created_at
          @hash[:metadata][:expired_at].should == @session.expired_at
          @hash[:metadata][:authority].should == @session.authority
          @hash[:signed].each_pair { |k, v| @session[k].should == v }
          @hash[:insecure].each_pair { |k, v| @session[k].should == v }
        end
      end
    end
  end
end
