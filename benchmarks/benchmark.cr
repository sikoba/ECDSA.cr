require "benchmark"
require "./../src/ecdsa.cr"

# generate some keys

g = ECDSA.get_group(:secp256k1)

pair_a = g.create_key_pair
sec_a = pair_a[:secret_key]
pub_a = pair_a[:public_key]

########################################
#
# G : cached generating point
# P : cached public key of sender (useful for repeated signature verification) 
# C : skipping signature verification sanity check (when public key is known)
#
########################################

g0 = ECDSA.get_group(:secp256k1, false) # X
g1 = ECDSA.get_group(:secp256k1)        # G
g2 = ECDSA.get_group(:secp256k1)        # GP

pub_a0 = ECDSA::Point.new(g0, pub_a.x, pub_a.y)
pub_a1 = ECDSA::Point.new(g1, pub_a.x, pub_a.y)
pub_a2 = ECDSA::Point.new(g2, pub_a.x, pub_a.y)

g2.add_to_cache(pub_a2) # ! point needs to be in the correct group

message = Random::Secure.hex(200)
message2000 = Random::Secure.hex(2000)

signature = g.sign(sec_a, message)


########################################

puts "\n== Hashing 200-byte messages\n"

Benchmark.ips do |x|

  x.report("      SHA256 :") do
    Digest::SHA256.hexdigest message
  end

  x.report("    SHA3_256 :") do
    Digest::SHA3.hexdigest message
  end

end

# # # # # # # # # #

puts "\n== Hashing 2000-byte messages\n"

Benchmark.ips do |x|

  x.report("      SHA256 :") do
    Digest::SHA256.hexdigest message2000
  end

  x.report("    SHA3_256 :") do
    Digest::SHA3.hexdigest message2000
  end

end

# # # # # # # # # #

puts "\n== Generating key-pairs\n"

Benchmark.ips do |x|

  x.report("    key-pair :") do
    g0.create_key_pair
  end

  x.report("  key-pair G :") do
    g1.create_key_pair
  end

end

# # # # # # # # # #

puts "\n== Signing\n"

Benchmark.ips do |x|

  x.report("        sign :") do
    g0.sign(sec_a, message)
  end

  x.report("      sign G :") do
    g1.sign(sec_a, message)
  end

end

# # # # # # # # # #

puts "\n== Verifying\n"

Benchmark.ips do |x|

  x.report("      verify :") do
    g0.verify(pub_a0, message, signature)
  end

  x.report("    verify G :") do
    g1.verify(pub_a1, message, signature)
  end

  x.report("   verify GP :") do
    g2.verify(pub_a2, message, signature)
  end

end


# # # # # # # # # #

puts "\n== Verifying without sanity checks\n"

Benchmark.ips do |x|

  x.report("    verify C :") do
    g0.verify(pub_a0, message, signature, false)
  end

  x.report("   verify GC :") do
    g1.verify(pub_a1, message, signature, false)
  end

  x.report("  verify GPC :") do
    g2.verify(pub_a2, message, signature, false)
  end

end
########################################