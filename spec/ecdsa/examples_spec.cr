require "./../spec_helper"

# examples from README

g = ECDSA.get_group :secp256k1
sec = BigInt.new("181819889614099500139968055079267329034062173137940193777846146779387277", base: 10)
key_pair = g.create_key_pair(sec)
pub = key_pair.[:public_key]

message = "http://www.sikoba.com"
sig = g.sign(sec, message)
sig_sha3 = g.sign_sha3_256(sec, message)
sig_keccak = g.sign_keccak_256(sec, message)

it "generates the correct key pair" do
  x = key_pair.[:public_key].x
  y = key_pair.[:public_key].y
  x.should eq BigInt.new("85178987611776079650687100736630225395836133315679241448696142401730235065445")
  y.should eq BigInt.new("42655463775677901349476176253478345062189292709218709770749313858929229563957")
end

# verify signatures using a signature object

it "verifies signature (SHA256)" do
  g.verify(pub, message, sig)
end

it "verifies signature (SHA3-256)" do
  g.verify_sha3_256(pub, message, sig_sha3)
end

it "verifies signature (Keccak-256)" do
  g.verify_keccak_256(pub, message, sig_keccak)
end

# verify signatures using r and s values

it "verifies signature r,s (SHA256)" do
  g.verify(pub, message, sig.r, sig.s)
end

it "verifies signature r,s (SHA3-256)" do
  g.verify_sha3_256(pub, message, sig_sha3.r, sig_sha3.s)
end

it "verifies signature (Keccak-256)" do
  g.verify_keccak_256(pub, message, sig_keccak.r, sig_keccak.s)
end


# sign using own random number

it "sign using own random number" do
  k = BigInt.new("5846704604701277839882806211944760658860225489638225087703968849823566991145", base: 10)
  signature = g.sign(sec, message, k)
  signature.r.should eq BigInt.new("46936881718680924751941056637981176854079153858678292484057701054143224621739")
  signature.s.should eq BigInt.new("15388841714363266238741664615371033802507768290858669287200605203375882181899")
end
