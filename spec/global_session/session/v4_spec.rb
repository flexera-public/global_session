require 'spec_helper'
require File.expand_path('../shared_examples', __FILE__)

describe GlobalSession::Session::V4 do
  subject { GlobalSession::Session::V4 }

  include SpecHelper

  context 'given an EC key' do
    let(:key_generation_parameter) { 'prime256v1' }
    let(:signature_method) { :dsa_sign_asn1 }
    let(:approximate_token_size) { 210 }
    it_should_behave_like 'all subclasses of Session::Abstract'

    let(:algorithm_identifier) { 'ES256' }
    it_should_behave_like 'JWT compatible subclasses of Session::Abstract'
  end

  context 'given an RSA key' do
    let(:key_generation_parameter) { 1024 }
    let(:signature_method) { :dsa_sign_asn1 }
    let(:approximate_token_size) { 280 }
    it_should_behave_like 'all subclasses of Session::Abstract'

    let(:algorithm_identifier) { 'RS256' }
    it_should_behave_like 'JWT compatible subclasses of Session::Abstract'
  end

  # tests related to accepting flexeraIAM-generated tokens
  context 'decode_cookie' do
    let(:token_subject) { "my_okta_user" }
    let(:now) { Time.now }
    let(:expire_at) { now + 60 }
    let(:trusted_issuer) { "my-RS256" }
    let(:key_generation_parameter) { 1024 }
    let(:configuration) do
      {
        'attributes' => {
          'signed' => ['sub']
        },
        'keystore' => {
          'public' => key_factory.dir,
          'private' => File.join(key_factory.dir, "#{trusted_issuer}.key"),
        },
        'timeout' => 60,
      }
    end
    let(:directory) { GlobalSession::Directory.new(configuration) }

    let(:key_factory) { KeyFactory.new }
    before do
      key_factory.create(trusted_issuer, true, parameter: key_generation_parameter)
      key_factory.create('untrusted', true, parameter: key_generation_parameter)
      FileUtils.rm(File.join(key_factory.dir, 'untrusted.pub'))
    end
    after do
      key_factory.destroy
    end

    context 'when the typ=JWT header is ommitted' do
      let(:valid_jwt) do
        algorithm = 'RS256'
        header = { 'alg' => algorithm }
        encoded_header = JWT.base64url_encode(JWT.encode_json(header))

        payload = {
          'iat' => now.to_i,
          'exp' => expire_at.to_i,
          'iss' => trusted_issuer,
          'sub' => token_subject
        }

        segments = []
        segments << encoded_header
        segments << JWT.encoded_payload(payload)
        segments << JWT.encoded_signature(segments.join('.'), directory.private_key, algorithm)
        segments.join('.')
      end

      it 'should parse properly' do
        session = subject.new(directory, valid_jwt)
        expect(session['sub']).to eq(token_subject)
      end
    end

    context 'when the issuer is a flexeraiam endpoint, and the issuer is present in the kid header' do
      let(:valid_jwt) do
        algorithm = 'RS256'
        header = { 'kid' => trusted_issuer, 'alg' => algorithm }
        encoded_header = JWT.base64url_encode(JWT.encode_json(header))

        payload = {
          'iat' => now.to_i,
          'exp' => expire_at.to_i,
          'iss' => "https://secure.flexeratest.com/oauth/something",
          'sub' => token_subject
        }

        segments = []
        segments << encoded_header
        segments << JWT.encoded_payload(payload)
        segments << JWT.encoded_signature(segments.join('.'), directory.private_key, algorithm)
        segments.join('.')
      end

      it 'should parse properly' do
        session = subject.new(directory, valid_jwt)
        expect(session['sub']).to eq(token_subject)
      end 
    end
  end
end
