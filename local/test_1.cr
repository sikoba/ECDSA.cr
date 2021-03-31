require "../src/ecdsa.cr"


puts "################################### For README start ########################\n\n"

# 

puts "\nSHA3"

message = "https://www.sikoba.com"
res = Digest::SHA3.hexdigest message
puts res #=> 93adc6708e6c5d53c6dcab13ffd31d695b5bfd49282cf457d4ed4f323a83c751

# 

puts "\nInitialising a group"

g = ECDSA.get_group :secp256k1
puts "g.name: #{g.name}" #=> secp256k1
puts "g.p: #{g.p}" #=> 115792089237316195423570985008687907853269984665640564039457584007908834671663
puts "g.a: #{g.a}" #=> 0
puts "g.b: #{g.b}" #=> 7
puts "g.gx: #{g.gx}" #=> 55066263022277343669578718895168534326250603453777594175500187360389116729240
puts "g.gy: #{g.gy}" #=> 32670510020758816978083085130507043184471273380659243275938904335757337482424
puts "g.n: #{g.n}" #=> 115792089237316195423570985008687907852837564279074904382605163141518161494337
puts "g.d: #{g.d}" #=> 256

#

puts "\nCreating a key pair"

key_pair = g.create_key_pair()
puts "Secret key: #{key_pair.[:secret_key]}"
puts "Public key (x): #{key_pair.[:public_key].x}"
puts "Public key (y): #{key_pair.[:public_key].y}"

#

puts "\nComputing a public key"

sec = BigInt.new("181819889614099500139968055079267329034062173137940193777846146779387277", base: 10)

key_pair = g.create_key_pair(sec)
puts "Public key (x): #{key_pair.[:public_key].x}"
#=> 85178987611776079650687100736630225395836133315679241448696142401730235065445
puts "Public key (y): #{key_pair.[:public_key].y}"
#=> 42655463775677901349476176253478345062189292709218709770749313858929229563957

#

puts "\nSigning"

signature = g.sign(sec, message)
puts signature.r
puts signature.s

puts "\signing using own random number\n"

k = BigInt.new("5846704604701277839882806211944760658860225489638225087703968849823566991145", base: 10)
signature = g.sign(sec, message, k)
puts signature.r #=> 46936881718680924751941056637981176854079153858678292484057701054143224621739
puts signature.s #=> 18442110116601975958734127083110648061233993479485730263351699466754248595366

#

puts "\nVerifying signature"

verify = g.verify(key_pair[:public_key], message, signature)
puts "Result of verification: #{verify}"

puts "\n\n################################### For README end ########################\n\n"



k = ECDSA::Math.random(BigInt.new(1), g.n-1)
puts "k: #{k}"
puts


message = "Hello world"
sec = BigInt.new("45088181819889614099500139968055079267329034062173137940193777846146779387277", base: 10)
sec = BigInt.new("181819889614099500139968055079267329034062173137940193777846146779387277", base: 10)




# not precomputed
puts "\n=== not precomputed"

elapsed_time = Time.measure do
    group1 = ECDSA.get_group :secp256k1
    key_pair1 = group1.create_key_pair(sec)
    puts "Secret key: #{key_pair1.[:secret_key]}"
    puts "Public key (x): #{key_pair1.[:public_key].x}"
    puts "Public key (y): #{key_pair1.[:public_key].y}"
    signature1 = group1.sign(sec, message, k)
    puts signature1.inspect
    verify1 = group1.verify(key_pair1[:public_key], message, signature1)
    puts "Result of first verification: #{verify1}"
end
puts elapsed_time

# precomputed
puts "\n=== precomputed"

elapsed_time = Time.measure do
    group2 = ECDSA.get_group :secp256k1_PRE
    key_pair2 = group2.create_key_pair(sec)
    puts "Secret key: #{key_pair2.[:secret_key]}"
    puts "Public key (x): #{key_pair2.[:public_key].x}"
    puts "Public key (y): #{key_pair2.[:public_key].y}"
    signature2 = group2.sign(sec, message, k)
    puts signature2.inspect
    verify2 = group2.verify(key_pair2[:public_key], message, signature2)
    puts "Result of second verification: #{verify2}"
end
puts elapsed_time