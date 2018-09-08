require "./../spec_helper"

describe ECDSA::Group do
  describe "#create_key_pair" do
    it do
      secret_key  = BigInt.new(1238503840)
      group       = ECDSA.get_group(:secp256k1)

      key_pair = group.create_key_pair(secret_key)

      key_pair[:secret_key].should eq secret_key
      key_pair[:public_key].should eq ECDSA::Point.new(
        group,
        BigInt.new("c3da9c0e67011b7b72172259e5184719f6ac1c01e7649fd6a898afb001a95a18", base: 16),
        BigInt.new("54bdbfebb31b270f816ddba928cc7c4bde69555738861ca9512d3a9ce1fa1db6", base: 16)
      )
    end
  end

  describe "#sign" do
    it do
      message     = "Some payload"
      group       = ECDSA.get_group(:secp256k1)
      secret_key  = BigInt.new("28948022309329048855892746252171976963209391069768726095651290785379540373584")
      temp_key    = BigInt.new("57896044618658097711785492504343953926418782139537452191302581570759080747168")

      signature = group.sign(secret_key, message, temp_key)

      signature.should eq ECDSA::Signature.new(
        s: BigInt.new("19731188594578979699733042519230633392796177483436570075145644842953643616619"),
        r: BigInt.new("86918276961810349294276103416548851884759982251107")
      )
    end
  end

  describe "#verify" do
    it "returns true for valid signature" do
      message   = "Some payload"
      group     = ECDSA.get_group(:secp256k1)
      signature = ECDSA::Signature.new(
        s: BigInt.new("19731188594578979699733042519230633392796177483436570075145644842953643616619"),
        r: BigInt.new("86918276961810349294276103416548851884759982251107")
      )
      public_key = ECDSA::Point.new(
        group: group,
        x: BigInt.new("75404758482970552478342687949548602789701733940509850780379145804275702033212"),
        y: BigInt.new("51231939447366605701190019263228486011330128519473004560491454193878655241557")
      )

      group.verify(public_key, message, signature).should eq true
    end

    it "returns false for invalid signature" do
      message   = "Some payload"
      group     = ECDSA.get_group(:secp256k1)
      signature = ECDSA::Signature.new(
        s: BigInt.new("144"),
        r: BigInt.new("1050")
      )
      public_key = ECDSA::Point.new(
        group: group,
        x: BigInt.new("75404758482970552478342687949548602789701733940509850780379145804275702033212"),
        y: BigInt.new("51231939447366605701190019263228486011330128519473004560491454193878655241557")
      )

      group.verify(public_key, message, signature).should eq false
    end
  end
end