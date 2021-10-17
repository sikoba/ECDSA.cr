require "./../spec_helper"
require "./../support/group_spec_macros"

describe ECDSA do

  it "generate Ethereum address" do
    
    # https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html

    g = ECDSA.get_group :secp256k1
    sec = BigInt.new("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", base: 16)
    public_key = g.create_key_pair(sec)[:public_key]
  
    ECDSA.eth_address(public_key).should eq "0x001d3F1ef827552Ae1114027BD3ECF1f086bA0F9"
    ECDSA.eth_address(public_key).downcase.should eq "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9"
  end

  it "convert Ethereum address to mixed-case" do

    address = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".downcase
    ECDSA.eth_address_to_mixed_case(address).should eq "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
  end

  it "verify Ethereum signed message #1" do
    data = "Hello, world!"
    signature = "0x643372b9c0636aa8757703ebfdd59d149ac1f9c2cdb66ee569812fe89ee963cb56e4d5d28843edeb0e529431bf724419987002302955979e92b64b6b6683817e1c"
    eth_account = "0xeB61E703DB916935A9B435eeaFa132cA59dc0BbB"
    ECDSA.verify_ethereum_signature(data, signature, eth_account).should eq true
  end

  it "verify Ethereum signed message #2" do
    data = "Hello, world!"
    signature = "0x1038030f8b327e0ceb7a92b9047fa3bdf43cde80f90f3593478de1796d898b4c2b409adf536062205fb68aa68f842c5c4e163e7228d47999e12af47f128c2a931c"
    eth_account = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9"
    ECDSA.verify_ethereum_signature(data, signature, eth_account).should eq true
  end

  it "verify Ethereum signed message #3" do
    data = "Hello, world!"
    signature = "0x7c34d821ff8a6ca0b5c7cc080551994151ca3e4a0ac655deb659bc9aabaab0ca0027d20f7c9affb3e915d1be3b9b6ef28544f6ff771bd88d4627323a8adfd3e001"
    eth_account = "0x2172B6F29d1F594A66424D4261efe2604934f25e"
    ECDSA.verify_ethereum_signature(data, signature, eth_account).should eq true
  end

  it "verify Ethereum signed message #4" do
    data = "Hello, world!!"
    signature = "0xc59477104ff48738c4f2b81b4028a950e3c22ded6698d60f884b34a3c216ad0a381f66099702dd99dd6d601cd1c32e4d35c158cbad8c150aa95ecc07855ac8bc00"
    eth_account = "0x2172B6F29d1F594A66424D4261efe2604934f25e"
    ECDSA.verify_ethereum_signature(data, signature, eth_account).should eq true
  end

end
