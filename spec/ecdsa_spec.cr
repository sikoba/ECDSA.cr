require "./spec_helper"

describe ECDSA do
  describe "Signing and verification" do
    it do
      secp256k1 = ECDSA.get_group(:secp256k1)
      key_pair  = secp256k1.create_key_pair
      message   = "Hello, Bob"

      signature = secp256k1.sign(key_pair[:secret_key], message)
      verify    = secp256k1.verify(key_pair[:public_key], message, signature)

      verify.should eq true
    end
  end
end