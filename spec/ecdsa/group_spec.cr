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
end