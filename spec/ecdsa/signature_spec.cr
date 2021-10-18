require "./../spec_helper"

describe ECDSA::Signature do
  describe "#==" do
    describe "true when @s and @r are same" do
      it "false" do
        sign1 = ECDSA::Signature.new(r: BigInt.new(100), s: BigInt.new(200), v: 0)
        sign2 = ECDSA::Signature.new(r: BigInt.new(0), s: BigInt.new(200), v: 0)

        (sign1 == sign2).should eq false
      end

      it "false" do
        sign1 = ECDSA::Signature.new(r: BigInt.new(100), s: BigInt.new(100), v: 0)
        sign2 = ECDSA::Signature.new(r: BigInt.new(100), s: BigInt.new(100), v: 1)

        (sign1 == sign2).should eq false
      end

      it "true" do
        sign1 = ECDSA::Signature.new(r: BigInt.new(100), s: BigInt.new(100), v: 0)
        sign2 = ECDSA::Signature.new(r: BigInt.new(100), s: BigInt.new(100), v: 0)

        (sign1 == sign2).should eq true
      end
    end
  end
end