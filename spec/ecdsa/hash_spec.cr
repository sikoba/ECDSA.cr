require "./../spec_helper"

# http://emn178.github.io/online-tools/


describe Digest::SHA256 do
  it "SHA256" do
    res = Digest::SHA256.hexdigest "https://www.sikoba.com"
    res.should eq "aa82cded6e98f4b2616dc7910df4623f5856bea617eb18c651cf932f0ee24f27"
  end
end

describe Digest::SHA3 do
  it "hash with SHA3-256" do
    res = Digest::SHA3.hexdigest "https://www.sikoba.com"
    res.should eq "93adc6708e6c5d53c6dcab13ffd31d695b5bfd49282cf457d4ed4f323a83c751"
  end
end

describe Digest::Keccak do
  it "hash with Keccak-256" do
    res = Digest::Keccak.hexdigest "https://www.sikoba.com"
    res.should eq "957124317724f7b2d7acc95e8cbc59265ff6ec6c2aabfd91deac65fef457c093"
  end
end