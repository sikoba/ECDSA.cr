## Installation

To use this shard, start by adding it to your shard.yml like so:

```
dependencies:
  ecdsa:
    github: sikoba/ECDSA.cr
    version: ~> 0.1
```

This requires Crystal 0.36 or higher. An older version, which works with Crystal 0.35 and uses SHA256 for hashing, is available as branch "legacy-crystal-0.35"

## Usage Examples

#### SHA3

We have implemented SHA3_256 in this shard. 

```
res = Digest::SHA3.hexdigest "https://www.sikoba.com"
puts res #=> 93adc6708e6c5d53c6dcab13ffd31d695b5bfd49282cf457d4ed4f323a83c751
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
key_pair = g1.create_key_pair()
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

#### Signing

The default signature start by hasing the message using SHA3, then signs using a random integer:

```
signature = g.sign(sec, message)
puts signature.r #=> 41299063418692046109627559638328395711492145286793497389846134068804323840081
puts signature.s #=> 75335275323898069941217967781306232505574825015382438464958146008911188316568
```

You can also use your own random number:

```
k = BigInt.new("5846704604701277839882806211944760658860225489638225087703968849823566991145", base: 10)
signature = g.sign(sec, message, k)
puts signature.r #=> 46936881718680924751941056637981176854079153858678292484057701054143224621739
puts signature.s #=> 18442110116601975958734127083110648061233993479485730263351699466754248595366
```

You can also use another hashing sunction, in which case you will need to sign a number. See "group.cr" for more ways to sign.

#### Verify signature

```
verify = g.verify(key_pair[:public_key], message, signature)
puts "Result of verification: #{verify}" #=> true
```

#### Precomputed curves

To speed up signing (significantly) and verification (a bit), you can use the curves :secp256k1_PRE and :secp256r1_PRE, for which values of g * 2^n are precomputed.


## To Do

* [ ] benchmark against implementations in other languages

* [ ] test against ECDSA implementations in other langauges

* [ ] so far only SHA3_256 is implemented. Add SHA3 for 224, 384 and 512

* [ ] implement keccack 224, 256, 384, 512

* [ ] add precomputed g * 2^n for more curves

* [ ] provide more usage examples, e.g. generating an Ethereum address from a private key (one Keccak is implemented), genrating a Bitcoin address etc.

* [ ] add h to group.cr, use to verify signatures when h > 1

## Current benchmark (secp256k1) using SHA3
```
                           user     system      total        real
key-pair generation:   0.022889   0.000033   0.022922 (  0.019881)
sign:                  0.023829   0.000049   0.023878 (  0.021340)
verify:                0.064223   0.008755   0.072978 (  0.065146)
```
If turn of 1 param check in verify method:
```
                           user     system      total        real
key-pair generation:   0.050000   0.000000   0.050000 (  0.049207)
sign:                  0.050000   0.000000   0.050000 (  0.042136)
verify:                0.090000   0.010000   0.100000 (  0.084240)
```
Ruby ecdsa implementation:
```
                          user     system      total        real
key-pair generation:  0.110000   0.000000   0.110000 (  0.105881)
sign:                 0.110000   0.000000   0.110000 (  0.107868)
verify:               0.210000   0.000000   0.210000 (  0.214049)
```
