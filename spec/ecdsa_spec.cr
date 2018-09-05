require "./spec_helper"

describe ECDSA do
  describe "Signing and verification" do
    it do
      message   = "Hello, Bob"
      secp256k1 = ECDSA.get_group(:secp256k1)
      key_pair  = secp256k1.create_key_pair

      signature = secp256k1.sign(key_pair[:secret_key], message)
      verify    = secp256k1.verify(key_pair[:public_key], message, signature)

      verify.should eq true
    end
  end

  describe "Signing" do
    it "secp256k1" do
      message     = "Life is great"
      secp256k1   = ECDSA.get_group(:secp256k1)
      secret_key  = BigInt.new(100)

      signature = secp256k1.sign(secret_key, message, BigInt.new(200))

      signature.s.should eq BigInt.new("62147387284982819000624868082324333411518046001506373700808611097526682119507")
    end
  end
end