require "./../spec_helper"
require "./../support/group_spec_macros"

describe ECDSA::Group do

  describe "#sign" do
    [
      {
        group_name: :secp256k1,
        message:    BigInt.new("747eadeb6c62ec0a15875deacb33611ef9e176fe7b2bf14ca88f7b40a18f7a7b", base: 16),
        secret_key: BigInt.new("a75c71811e2d4c969682309760f75b98b56ad74fd6cabd4026f19b7c90b145fc", base: 16),
        temp_key:   BigInt.new("530b6cea047239963332936bbb97440e5c833210d589d490151bdb659b593588", base: 16),
        r:          BigInt.new("f2d2ada1f74c03e0639b756b16ec0780ef6964cb6bf80fdf2513e0271580d9b2", base: 16),
        s:          BigInt.new("54c5d843a694edfdad8bcb07f8463535849cbdb005669afe8bb747c28826e023", base: 16),
        v: 1
      },
    ].each do |spec|
      sign_spec(spec[:group_name], spec[:message], spec[:secret_key], spec[:temp_key], spec[:r], spec[:s], spec[:v])
    end
  end

end
