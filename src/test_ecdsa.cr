require "./ecdsa.cr"

c = SKO::ECDSA.get_group(:Secp256k1)

x = BigInt.new("74011014024632309201919250499840047707197506903174481043386877877509365703566")

keypair = c.create_key_pair(x)
pri = keypair["secret_key"]
pub = keypair["public_key"]
puts pri
puts pub.inspect
puts "****"

# puts "hash:"
# message = "one-two-three"
# puts SKO::Math.sha256("one-two-three")
# puts SKO::Math.hash("one-two-three")

puts "========="

ary = c.sign(pri, "one-two-three")
puts "signature"
puts ary[0].to_s(16)
puts ary[1].to_s(16)

puts c.verify(pub, "one-two-three", ary[0], ary[1])



