
## Current benchmark (secp256k1)
```
                           user     system      total        real
key-pair generation:   0.050000   0.010000   0.060000 (  0.046845)
sign:                  0.060000   0.000000   0.060000 (  0.046259)
verify:                0.140000   0.010000   0.150000 (  0.140880)
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

## TODO
0) test all **done**
1) add param check **done**
2) test random? **not needed**
3) code lint?
4) doc?
5) benchmark?
