require "./../spec_helper"

describe ECDSA::Math do
  describe ".mod_inverse" do
    it "3^(-1) mod 26 = 9" do
      ECDSA::Math.mod_inverse(3.to_big_i, 26.to_big_i).should eq 9
    end

    it "2^(-1) mod 26 = 9" do
      expect_raises(ECDSA::NotInvertible) do
        ECDSA::Math.mod_inverse(2.to_big_i, 26.to_big_i).should eq 9
      end
    end

    it "13^(-1) mod 137 = 116" do
      ECDSA::Math.mod_inverse(13.to_big_i, 137.to_big_i).should eq 116
    end

    it "113^(-1) mod 24593856 = 8488145" do
      ECDSA::Math.mod_inverse(113.to_big_i, 24_593_856.to_big_i).should eq 8_488_145
    end
  end

  it ".sha3_256" do
    message = "Hello world"
    hash = "369183d3786773cef4e56c7b849e7ef5f742867510b676d6b38f8e38a222d8a2"

    ECDSA::Math.sha3_256(message).should eq hash
  end

  it ".hash" do
    message = "Hello world"
    hash = "369183d3786773cef4e56c7b849e7ef5f742867510b676d6b38f8e38a222d8a2"

    ECDSA::Math.hash(message).should eq hash
  end

  it ".bit_length" do
    number = 107

    ECDSA::Math.bit_length(number).should eq 7
  end

  it ".normalize_digest" do
    hexdigest = 108.to_s(16) # 7 bits
    bit_length = 5

    ECDSA::Math.normalize_digest(hexdigest, bit_length).should eq 13
  end
end
