require "benchmark"

require "./../src/ecdsa.cr"

iterations = 1000

secp256k1 = ECDSA.get_group :secp256k1

message    = Random::Secure.hex(256)
key_pair   = secp256k1.create_key_pair

signature = secp256k1.sign(key_pair[:secret_key], message)
verify    = secp256k1.verify(key_pair[:public_key], message, signature)

Benchmark.bm do |x|
  x.report("key-pair generation:") do
    secp256k1.create_key_pair
  end

  x.report("sign:") do
    secp256k1.sign(key_pair[:secret_key], message)
  end

  x.report("verify:") do
    secp256k1.verify(key_pair[:public_key], message, signature)
  end
end

