require "./../spec_helper"
require "./../support/group_spec_macros"

describe ECDSA do

  it "generate Ethereum address" do
    
    # https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html

    g = ECDSA.get_group :secp256k1
    sec = BigInt.new("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", base: 16)
    public_key = g.create_key_pair(sec)[:public_key]
  
    ECDSA.eth_address(public_key).should eq "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9"

  end

end
