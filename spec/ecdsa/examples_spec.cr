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
  puts signature.s
  signature.r.should eq BigInt.new("46936881718680924751941056637981176854079153858678292484057701054143224621739")
  signature.s.should eq BigInt.new("42507202904294831473043827888972920123911013848678782904101976367383198565269")
end


# other tests

it "should reproduce test vector1" do

  # https://crypto.stackexchange.com/questions/41316/complete-set-of-test-vectors-for-ecdsa-secp256k1
  #  
  # 1. private key: D30519BCAE8D180DBFCC94FE0B8383DC310185B0BE97B4365083EBCECCD75759
  # 2. public key x-coordinate: 3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF  
  # 3. public key y-coordinate: E4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A  
  # 4. hash: 3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F  
  # 5. secure random integer k: CF554F5F4224223D52DC9CA784478FAC3C1A0D0419FDEEF27849A81846C71BA3  
  # 6. r signature: A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089  
  # 7. s signature: BC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB
  

  s1 = BigInt.new("D30519BCAE8D180DBFCC94FE0B8383DC310185B0BE97B4365083EBCECCD75759", base:16)
  h1 = BigInt.new("3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F", base:16)
  k1 = BigInt.new("CF554F5F4224223D52DC9CA784478FAC3C1A0D0419FDEEF27849A81846C71BA3", base:16)
  
  sig1 = g.sign(s1, h1, k1)
  puts "\n---test-vector1---"
  puts sig1.r.to_s(16)
  puts sig1.s.to_s(16)
end

it "should reproduce test vector2" do
  
  # https://bitcointalk.org/index.php?topic=285142.msg3150733
  #
  # expecting signature:
  # 7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c
  # a72033e1ff5ca1ea8d0c99001cb45f0272d3be7525d3049c0d9e98dc7582b857
  #
  # s value below n/2 is:
  # 58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea

  # "I had an issue with your last test vector. After some investigation, I noticed 
  # that the problem came from the parity of 'S'. The 'S' component is odd in your 
  # last test vector. I think that going forward, new code should produce fully valid 
  # and canonical signatures, which includes making the 'S' component even."

  s1 = BigInt.new("f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181", base:16)
  k1 = BigInt.new("525A82B70E67874398067543FD84C83D30C175FDC45FDEEE082FE13B1D7CFDF1", base:16)
  
  sig1 = g.sign(s1, "Alan Turing", k1)
  puts "\n---test-vector1---"
  puts sig1.r.to_s(16)
  puts sig1.s.to_s(16)
end


it "should read and write compact keys" do

  g = ECDSA.get_group(:secp256k1)
  compact_key = "03a0cd348c223c14f552ef6265042bd82a74bfb58a566cd64d2b0d0b9be9f7ded2"
  message = "Message"
  r = BigInt.new("f563e75c2f6b0fbe3697fd3b12fdc42df981c0f9ce4128c2075ce5c9ee39f415", base: 16)
  s = BigInt.new("25688ca063c9d49b0f31829ee1a2417186e402516fb4fff15eb62a2e7e9000dd", base: 16)

  public_key = g.read_compact_key(compact_key)

  puts g.p
  puts public_key

  compact2 = g.get_compact_key(public_key)

  res = g.verify_sha3_256(public_key, message, r, s)

  res.should eq true
  compact2.should eq compact_key
end