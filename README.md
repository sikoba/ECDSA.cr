## TODO

* [ ] documentation

* [ ] provide various usage examples, e.g. generating an Ethereum address from a private key, signing a string, verifying a signature (also in cases where h > 1)

* [ ] add h to group.cr, use to verify signatures when h > 1

* [ ] test using ecdsa implementations in other langauges than just Ruby

* [ ] once Secure Random is added to Bigint in a future Crystal release, ECDSA::Math::random will no longer be necessary (cf https://github.com/crystal-lang/crystal/pull/6687)

* [ ] improve performance, either by adding precomputed g * 2^n to the package, or by precomputing these points when a curve is first initialised

* [ ] code lint

* [ ] benchmarking against implementations in other languages

* [x] allowing BigInt initialisations with underscore like this: BigInt.new("FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFEE37", base: 16). Done: https://github.com/crystal-lang/crystal/pull/7107


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
