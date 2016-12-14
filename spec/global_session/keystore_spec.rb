require File.expand_path(File.join(File.dirname(__FILE__), '..' , 'spec_helper'))

describe GlobalSession::Keystore do
  include SpecHelper

  context '.create_keypair' do
    [:RSA, :DSA, :EC].each do |alg|
      it "makes #{alg} keys" do
        key = GlobalSession::Keystore.create_keypair(alg)
      end
    end
  end
end
