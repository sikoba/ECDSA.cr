## Installation

To use this shard, start by adding it to your shard.yml like so:

```
dependencies:
  ecdsa:
    github: sikoba/ECDSA.cr
    version: ~> 1.0
```

This requires Crystal 0.36 or higher. An older version, which works with Crystal 0.35, is available as branch "legacy-crystal-0.35"

## Improving Performance

#### Caching multiples of the generating point

In order to speed up signing and signature verification, multiples of the generating point of the form g * 2^n are cached by default when initialising a curve (there is an optional flag to disable this).

For the curve :secp256k1, these values are precomputed in ecdsa/precomputed.cr. Precomputing only provides a very slight gain when a curve is initialised, while increasing the overall size of the shard quite significantly, so we did not add precomputed values for other curves. More precomputed values can be added using local/precompute_gen.cr.

#### Caching public keys

Signature verification requires multiplying the sender's public key. If you know that you will need to verify several messages from the same sender, you can cache the public key multiplications, which will significantly speed up subsequent verifications:  

```
g.add_to_cache(public_key)
```

This public_key must be a point of the curve. Note that it is possible to also remove a public key from the cache.

#### Removing verification sanity checks

Another performance improvement can be obtained by removing certain sanity checks when verifying a signature, which can be done if the public key is known already:

```
g.verify(public_key, message, signature, false)
```

## Usage Examples

#### SHA3 and Keccak
We have implemented SHA3-256 and Keccak-256 in this shard. 

```
res = Digest::SHA3.hexdigest "https://www.sikoba.com"
puts res #=> 93adc6708e6c5d53c6dcab13ffd31d695b5bfd49282cf457d4ed4f323a83c751

res = Digest::Keccak.hexdigest "https://www.sikoba.com"
puts res #=> 957124317724f7b2d7acc95e8cbc59265ff6ec6c2aabfd91deac65fef457c093
```

#### Initialising a group

Here is how to initialise the group secp256k1, which is the one used by Bitcoin, Ethereum and many other cryptocurrencies. The list of predefined groups is provided in "curves.cr". Note that it is possible to use any curve as long as h = 1.

```
g = ECDSA.get_group :secp256k1
puts "g.name: #{g.name}" #=> secp256k1
puts "g.p: #{g.p}" #=> 115792089237316195423570985008687907853269984665640564039457584007908834671663
puts "g.a: #{g.a}" #=> 0
puts "g.b: #{g.b}" #=> 7
puts "g.gx: #{g.gx}" #=> 55066263022277343669578718895168534326250603453777594175500187360389116729240
puts "g.gy: #{g.gy}" #=> 32670510020758816978083085130507043184471273380659243275938904335757337482424
puts "g.n: #{g.n}" #=> 115792089237316195423570985008687907852837564279074904382605163141518161494337
puts "g.d: #{g.d}" #=> 256
```

#### Creating a key pair

Here is how to create a new key pair for a given group g: 

```
key_pair = g.create_key_pair()
puts "Secret key: #{key_pair.[:secret_key]}"
puts "Public key (x): #{key_pair.[:public_key].x}"
puts "Public key (y): #{key_pair.[:public_key].y}"
```

#### Computing a public key

Here is how to get the public key from a private key "sec": 

```
sec = BigInt.new("181819889614099500139968055079267329034062173137940193777846146779387277", base: 10)

key_pair = g.create_key_pair(sec)
puts "Public key (x): #{key_pair.[:public_key].x}"
#=> 85178987611776079650687100736630225395836133315679241448696142401730235065445
puts "Public key (y): #{key_pair.[:public_key].y}"
#=> 42655463775677901349476176253478345062189292709218709770749313858929229563957
```

#### r values returned by the signatue 

Given a signature (r, s), the pair (r, n - s) is also a valid signatiure. In the current version, signing will always output the smaller value of s.

#### Signing using SHA256 (default)

The default signature starts by hashing the message using SHA256, then signs using a random integer:

```
signature = g.sign(sec, message)
puts signature.r
puts signature.s
```

You can also use your own random number:

```
k = BigInt.new("5846704604701277839882806211944760658860225489638225087703968849823566991145", base: 10)
signature = g.sign(sec, message, k)
puts signature.r #=> 46936881718680924751941056637981176854079153858678292484057701054143224621739
puts signature.s #=> 73284886333021363950527157119714987728926550430396121478503186774134962929068
```

#### Verify signature

Assuming the public key has the components pub_x and pub_y:

```
public_key = ECDSA::Point.new(g, pub_x, pub_y)
verify = g.verify(public_key, message, signature)
puts "Result of verification: #{verify}" #=> true
```

If you only have the compacted version of the key, which is a string of 66 characters, you can get the full public key like this:

```
g = ECDSA.get_group(:secp256k1)
public_key = g.read_compact_key(compact_key)
```

#### Signing and verifying using SHA3-256 or Keccak-256

```
signature_sha3 = g.sign_sha3_256(sec, message)
verify = g.verify(public_key, message, signature_sha3)
puts "Result of verification: #{verify}" #=> true

signature_keccak = g.sign_keccak_256(sec, message)
verify = g.verify(public_key, message, signature_keccak)
puts "Result of verification: #{verify}" #=> true

```

### Signing a number

You can also sign a BigInt directly, cf "src/ecdsa/group.cr".


### Recovering a public key from a signature

If you have a signature, and you know what number has been signed, candidates for the corresponding public key can be computed. There are generally 2 candidates, one with an even y value, the other with an odd one. In some extremely rare cases (probability 10^-38) there may be 4 candidates, but we don't deal with it. Cf for example on stackexchange: [60218](https://crypto.stackexchange.com/questions/60218/recovery-public-key-from-secp256k1-signature-and-message) [18105](https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work)

An example is given in spec/ecdsa/pubkey_from_sig_spec.cr:

```
g = ECDSA.get_group :secp256k1

h = BigInt.new("3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F", base: 16)
s = BigInt.new("BC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB", base: 16)
r = BigInt.new("A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089", base: 16)
    
pub_even = g.recover_public_key(h, r, s, true)
pub_odd = g.recover_public_key(h, r, s, false)
```

## To Do

* [ ] benchmark against implementations in other languages

* [ ] test against ECDSA implementations in other langauges

* [ ] add SHA3 for 224, 384 and 512 bits

* [ ] provide more usage examples, e.g. generating an Ethereum address from a private key, generating a Bitcoin address etc.

* [ ] add h to group.cr, add ability to sign and verify signatures when h > 1

## Current benchmark (secp256k1) using SHA3

We use the following codes for benchmarking: 

```
# G : cached generating point
# P : cached public key of sender (useful for repeated signature verification) 
# C : skipping signature verification sanity check (when public key is known)
```

The benchmarks were done on a laptop with a Xeon E3-1505M @ 3.00GHz processor running Ubuntu on Windows. This seems to be somewhat slower than running it natively on Linux, but it should give an idea of the relative performances. 

```
== Hashing 200-byte messages
      SHA256 : 530.28k (  1.89µs) (± 7.08%)  224B/op        fastest
    SHA3_256 : 350.25k (  2.86µs) (± 3.23%)  992B/op   1.51× slower

== Hashing 2000-byte messages
      SHA256 :  97.78k ( 10.23µs) (± 5.00%)    224B/op        fastest
    SHA3_256 :  44.97k ( 22.23µs) (± 4.10%)  5.73kB/op   2.17× slower

== Generating key-pairs
    key-pair :  55.40  ( 18.05ms) (±12.13%)  10.4MB/op   3.19× slower
  key-pair G : 176.83  (  5.66ms) (± 3.30%)   3.4MB/op        fastest

== Signing
        sign :  56.50  ( 17.70ms) (± 8.12%)  10.4MB/op   3.04× slower
      sign G : 171.69  (  5.82ms) (± 3.48%)  3.46MB/op        fastest

== Verifying
      verify :  18.28  ( 54.71ms) (± 4.48%)  32.8MB/op   2.69× slower
    verify G :  23.12  ( 43.25ms) (± 3.74%)  25.8MB/op   2.13× slower
   verify GP :  49.16  ( 20.34ms) (± 3.08%)  12.1MB/op        fastest

== Verifying without sanity checks
    verify C :  27.26  ( 36.69ms) (± 9.30%)  20.8MB/op   3.14× slower
   verify GC :  43.16  ( 23.17ms) (± 3.62%)  13.9MB/op   1.98× slower
  verify GPC :  85.56  ( 11.69ms) (± 4.71%)   7.0MB/op        fastest
```