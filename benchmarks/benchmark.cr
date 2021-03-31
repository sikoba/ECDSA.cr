require "benchmark"

require "./../src/ecdsa.cr"

secp256k1 = ECDSA.get_group :secp256k1
secp256k1_PRE = ECDSA.get_group :secp256k1_PRE

message = Random::Secure.hex(256)

key_pair = secp256k1.create_key_pair
key_pair_PRE = secp256k1_PRE.create_key_pair

signature = secp256k1.sign(key_pair[:secret_key], message)
verify    = secp256k1.verify(key_pair[:public_key], message, signature)

signature_PRE = secp256k1_PRE.sign(key_pair_PRE[:secret_key], message)
verify_PRE = secp256k1_PRE.verify(key_pair_PRE[:public_key], message, signature_PRE)

Benchmark.ips do |x|
  x.report("key-pair generation:") do
    secp256k1.create_key_pair
  end

  x.report("sign:") do
    secp256k1.sign(key_pair[:secret_key], message)
  end

  x.report("verify:") do
    secp256k1.verify(key_pair[:public_key], message, signature)
  end

  x.report("key-pair generation PRE:") do
    secp256k1_PRE.create_key_pair
  end

  x.report("sign_PRE:") do
    secp256k1_PRE.sign(key_pair_PRE[:secret_key], message)
  end

  x.report("verify_PRE:") do
    secp256k1_PRE.verify(key_pair_PRE[:public_key], message, signature_PRE)
  end
end

