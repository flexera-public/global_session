require 'spec_helper'
require File.expand_path('../shared_examples', __FILE__)

describe GlobalSession::Session::Abstract do
  include SpecHelper

  before(:all) do
    @key_factory = KeyFactory.new
    @key_factory.create('authority1', true)
    @key_factory.create('authority2', false)
  end

  after(:all) do
    @key_factory.destroy
  end

  # Abstract#initialize can't be invoked directly, so we test its subclasses
  # instead. We do the reflection ourselves to avoid relying on ActiveSupport (Class#subclasses)
  descendants = []
  ObjectSpace.each_object(Class) do |k|
    descendants.unshift k if k < GlobalSession::Session::Abstract
  end
  descendants.each do |klass|
    context "given a valid serialized #{klass}" do
      let(:subclass) { klass }
      before(:each) do
        mock_config('test/trust', ['authority1'])
        mock_config('test/authority', 'authority1')
        mock_config('test/timeout', 60)
        mock_config('test/attributes/signed', ['user'])
        mock_config('test/attributes/unsigned', ['account'])
        @directory = GlobalSession::Directory.new(mock_config, @key_factory.dir)
        @session = subclass.new(@directory)
      end

      context :to_hash do
        before(:each) do
          @hash = @session.to_hash
        end

        it 'includes metadata' do
          expect(@hash[:metadata][:id]).to eq(@session.id)
          expect(@hash[:metadata][:created_at]).to eq(@session.created_at)
          expect(@hash[:metadata][:expired_at]).to eq(@session.expired_at)
          expect(@hash[:metadata][:authority]).to eq(@session.authority)

          @hash[:signed].each_pair { |k, v| expect(@session[k]).to eq(v) }
          @hash[:insecure].each_pair { |k, v| expect(@session[k]).to eq(v) }
        end
      end
    end
  end
end
