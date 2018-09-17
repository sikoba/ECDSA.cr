require "big"

p = BigInt.new("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", base: 16)
puts p
puts p.to_s(16).bytesize


x = Random::Secure.hex(64)
puts "--"
puts x.inspect
