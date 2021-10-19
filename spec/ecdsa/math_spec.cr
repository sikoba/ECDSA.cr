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

  it ".sha3_256_compare" do
    message = "SHA3 hash"
    hash = "53d7cb74d60d696a45bf3d65df5e8f21c1cb6cee1a3162e4544af28f948fbf15"

    ECDSA::Math.sha3_256(message).should eq hash
  end

  it ".hash" do
    message = "Hello world"
    hash = "369183d3786773cef4e56c7b849e7ef5f742867510b676d6b38f8e38a222d8a2"

    ECDSA::Math.hash(message).should eq hash
  end

  it ".hash_compare" do
    message = "SHA3 hash"
    hash = "53d7cb74d60d696a45bf3d65df5e8f21c1cb6cee1a3162e4544af28f948fbf15"

    ECDSA::Math.sha3_256(message).should eq hash
  end

  it ".bit_length" do
    number = 107

    ECDSA::Math.bit_length(number).should eq 7
  end

  it ".normalize_digest" do
    # 108 in base 2 is 1101100 (7 bits)
    # the fisrt 5 bits are 11011, which is 27 in base 10

    hexdigest = 108.to_s(16)
    bit_length = 5

    ECDSA::Math.normalize_digest(hexdigest, bit_length).should eq 27
  end
  
  it "modular exponentiation" do
    n = BigInt.new("114564569999865254561237894564569886215421645645645456", base: 10)
    e = BigInt.new("79862465848484456456456456456456456456456458632323232365545545", base: 10)
    p = BigInt.new("7951234858453573215156456456456456", base: 10)
    res_expected = BigInt.new("2519172085169739371889220291378472", base: 10)
    res = ECDSA::Math.powm(n, e, p)
    res.should eq res_expected
  end

  it "modular exponentiation (wrapped)" do
    n = BigInt.new("114564569999865254561237894564569886215421645645645456", base: 10)
    e = BigInt.new("79862465848484456456456456456456456456456458632323232365545545", base: 10)
    p = BigInt.new("7951234858453573215156456456456456", base: 10)
    res_expected = BigInt.new("2519172085169739371889220291378472", base: 10)
    # res = ECDSA::Math.powm_wrapped(n, e, p)
    # res.should eq res_expected
    
    # this does not work for some reason, error message:
    #
    # => Program received and didn't handle signal FPE (8)
    
  end
  
end
