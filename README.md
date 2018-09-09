## Current benchmark
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

## TODO
0) test all
1) add param check
2) #sign signature != nil
3) test random?
4) code lint?
5) doc?
6) benchmark?