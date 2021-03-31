require "../src/ecdsa.cr"


# testing sha3

s = "Tea time!"
Digest::SHA3.new(512)
res = Digest::SHA3.hexdigest s
puts res


# try :secp256r1

g = ECDSA.get_group :secp256k1
puts g.d
n = g.n
k = ECDSA::Math.random(BigInt.new(1), n-1)

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
    puts "now verify"
    verify2 = group2.verify(key_pair2[:public_key], message, signature2)
    puts "Result of second verification: #{verify2}"
end
puts elapsed_time