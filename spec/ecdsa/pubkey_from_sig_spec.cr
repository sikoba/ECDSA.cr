require "./../spec_helper"
require "./../support/group_spec_macros"

describe ECDSA::Group do

  it "recover public key from signature" do
    
    # data taken from group_verify_spec.cr

    g = ECDSA.get_group :secp256k1

    h = BigInt.new("3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F", base: 16)
    s = BigInt.new("BC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB", base: 16)
    r = BigInt.new("A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089", base: 16)
    
    public_key_x = BigInt.new("3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF", base: 16)
    public_key_y = BigInt.new("E4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A", base: 16)

    pub_even = g.recover_public_key(h, r, s, true)
    puts "Recovered even key:"
    puts pub_even.x.to_s(16).upcase
    puts pub_even.y.to_s(16).upcase
    puts "----"

    pub_odd = g.recover_public_key(h, r, s, false)
    puts "Recovered odd key:"
    puts pub_odd.x.to_s(16).upcase
    puts pub_odd.y.to_s(16).upcase
    puts "----"

    (public_key_x == pub_even.x).should eq false
    (public_key_y == pub_even.y).should eq false

    (public_key_x == pub_odd.x).should eq true
    (public_key_y == pub_odd.y).should eq true
  end
end
