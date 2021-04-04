require "../src/ecdsa.cr"

##########

message = "https://www.sikoba.com"
sec = BigInt.new("181819889614099500139968055079267329034062173137940193777846146779387277", base: 10)

# 

g = ECDSA.get_group(:secp256k1)
kp = g.create_key_pair

#

publickey = [kp[:public_key].x, kp[:public_key].y]
signature = g.sign(kp[:secret_key], message)

##########

g0 = ECDSA.get_group(:secp256k1, false) # no caching
g1 = ECDSA.get_group(:secp256k1)
g2 = ECDSA.get_group(:secp256k1)

#

puts "\nprecomputed?"

puts "g0.use_pre: #{g0.use_pre}" #=> false
puts "g1.use_pre: #{g1.use_pre}" #=> true
puts "g2.use_pre: #{g2.use_pre}" #=> true

#
# the points corresponding to a public key need to be created for each curve

pt0 = ECDSA::Point.new(g0, publickey[0], publickey[1])
pt1 = ECDSA::Point.new(g1, publickey[0], publickey[1])
pt2 = ECDSA::Point.new(g2, publickey[0], publickey[1])

#

puts "\ngenrating key pairs"

key_pair0 = g0.create_key_pair(sec)
key_pair1 = g1.create_key_pair(sec)
key_pair2 = g2.create_key_pair(sec)

puts
puts "key_pair0[:public_key].x: #{key_pair0[:public_key].x}"
puts "key_pair1[:public_key].x: #{key_pair1[:public_key].x}"
puts "key_pair2[:public_key].x: #{key_pair2[:public_key].x}"

#

puts "\nsigning"

k = BigInt.new("5846704604701277839882806211944760658860225489638225087703968849823566991145", base: 10)

sig0 = g0.sign(sec, message, k)
sig1 = g1.sign(sec, message, k)
sig2 = g2.sign(sec, message, k)

#

puts "\nadding to cache (for g2)"
g2.add_to_cache(pt2)

#

puts "\ncache size"

puts "g0.cached.size: #{g0.cached.size}"
puts "g1.cached.size: #{g1.cached.size}"
puts "g2.cached.size: #{g2.cached.size}"

puts
puts "cached for g2"
puts g2
g2.cached.keys.each do |pt|
    puts
    puts pt.group
    puts pt.x
    puts pt.y
end 

#

puts "\ninspect signatures"

puts sig1.inspect
puts sig2.inspect

#

puts "\nverify signatures"

verify0 = g0.verify(key_pair0[:public_key], message, signature)
verify1 = g1.verify(key_pair1[:public_key], message, signature)
verify2 = g2.verify(key_pair2[:public_key], message, signature)



##########




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
puts "g.use_pre: #{g.use_pre}" #=> true

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

puts "\nSigning using SHA3"

signature = g.sign(sec, message)
puts signature.r
puts signature.s

puts "\nsigning using own random number\n"

k = BigInt.new("5846704604701277839882806211944760658860225489638225087703968849823566991145", base: 10)
signature = g.sign(sec, message, k)
puts signature.r #=> 46936881718680924751941056637981176854079153858678292484057701054143224621739
puts signature.s #=> 18442110116601975958734127083110648061233993479485730263351699466754248595366

#

puts "\nVerifying signature"

verify = g.verify(key_pair[:public_key], message, signature)
puts "Result of verification: #{verify}" #=> true

#

puts "\nSigning and verifying using other hashing functions (e.g. SHA256)"

hash256 = Digest::SHA256.hexdigest message
puts hash256 #=> aa82cded6e98f4b2616dc7910df4623f5856bea617eb18c651cf932f0ee24f27
e = BigInt.new(hash256, base: 16)
puts e #=> 77124295636732202635904343699324840500329162892545761296514851474479234830119

signature = g.sign(sec, e)
verify = g.verify(key_pair[:public_key], e, signature)
puts "Result of verification: #{verify}" #=> true

exit 0

#

puts "\n\n################################### For README end ########################\n\n"

#

k = ECDSA::Math.random(BigInt.new(1), g.n-1)
puts "k: #{k}"
puts

#

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