require 'spec_helper'
require File.expand_path('../shared_examples', __FILE__)

describe 'GlobalSession::Session::V2' do
  subject { GlobalSession::Session::V2 }

  let(:key_generation_parameter) { 1024 }
  let(:signature_method) { :private_encrypt }
  let(:approximate_token_size) { 260 }
  it_should_behave_like 'all subclasses of Session::Abstract'
end
