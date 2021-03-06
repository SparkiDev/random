Hash Algorithms
===============

Open Source Random Algorithms Implementation

Written by Sean Parkinson (sparkinson@iprimus.com.au)

For information on copyright see: COPYRIGHT.md

Contents of Repository
----------------------

This code implements the HashDRBG using a number of hash algorithms including:
 - SHA-1
 - SHA-224, SHA-256, SHA-384, SHA-512
 - SHA-512_224 SHA-512_256

There is a common API with which to chose and use a random algorithm.

The code is fast C.
The library requires the hash implementation found at:
  https://github.com/SparkiDev/hash

Building
--------

First download and build the hash code from:
   https://github.com/SparkiDev/hash

The two repositories, hash and random, must be in the same directory.
For example:
cryptography --- hash
             |
             --- random

Then build, in the directory random, with the command:

  make

Testing
-------

Run all algorithms and calculate speed: t_random -speed

Performance
-----------

Examples of t_random output on a 3.4 GHz Intel Ivy Bridge CPU:

```
./t_random

Cycles/sec: 3400289382
Hash_DRBG SHA1
    Op      ops  secs     c/op   ops/s      c/B       B/s     mB/s
     1: 1240528 0.653     1790 1899603  1790.70   1898859    1.899
    32: 1562632 1.006     2188 1554062    68.39  49717722   49.718
    64: 1059280 1.007     3232 1052069    50.51  67312952   67.313
  1024:  120830 0.973    27385  124166    26.74 127143215  127.143
  8192:   16300 0.982   204778   16604    25.00 136025828  136.026
 16384:    8236 0.989   408423    8325    24.93 136403446  136.403
Hash_DRBG SHA224
    Op      ops  secs     c/op   ops/s      c/B       B/s     mB/s
     1: 1003627 0.999     3385 1004516  3385.37   1004407    1.004
    32:  772441 1.002     4411  770865   137.87  24662423   24.662
    64:  627128 1.003     5437  625398    84.95  40024872   40.025
  1024:   85256 1.002    39976   85058    39.04  87098750   87.099
  8192:   11210 0.990   300184   11327    36.64  92793525   92.794
 16384:    5538 0.974   598155    5684    36.51  93136946   93.137
Hash_DRBG SHA256
    Op      ops  secs     c/op   ops/s      c/B       B/s     mB/s
     1: 1036673 1.004     3292 1032894  3292.38   1032775    1.033
    32: 1041117 1.003     3274 1038573   102.34  33224979   33.225
    64:  786194 0.999     4319  787286    67.49  50384123   50.384
  1024:   97029 1.007    35284   96369    34.46  98680614   98.681
  8192:   12477 0.984   268050   12685    32.72 103917478  103.917
 16384:    6242 0.988   538131    6318    32.84 103525523  103.526
Hash_DRBG SHA384
    Op      ops  secs     c/op   ops/s      c/B       B/s     mB/s
     1:  772091 1.012     4458  762738  4458.90    762585    0.763
    32:  772441 1.003     4416  769993   138.03  24635124   24.635
    64:  591560 1.012     5815  584744    90.86  37423287   37.423
  1024:  101443 0.988    33103  102718    32.33 105181084  105.181
  8192:   14327 0.987   234304   14512    28.60 118884426  118.884
 16384:    7230 0.992   466453    7289    28.47 119433767  119.434
Hash_DRBG SHA512
    Op      ops  secs     c/op   ops/s      c/B       B/s     mB/s
     1:  768426 1.004     4443  765313  4443.60    765210    0.765
    32:  768774 1.005     4446  764797   138.96  24469520   24.470
    64:  768774 1.003     4435  766694    69.30  49066880   49.067
  1024:  136893 1.005    24970  136174    24.39 139438829  139.439
  8192:   19064 0.995   177396   19167    21.65 157022299  157.022
 16384:    9565 0.988   351355    9677    21.45 158558525  158.559
Hash_DRBG SHA512_224
    Op      ops  secs     c/op   ops/s      c/B       B/s     mB/s
     1: 1134943 1.007     3017 1127043  3017.13   1126994    1.127
    32:  727490 0.930     4348  782035   135.88  25025114   25.025
    64:  598853 1.005     5704  596123    89.14  38146531   38.147
  1024:   66022 1.002    51589   65911    50.38  67491819   67.492
  8192:    8496 0.991   396660    8572    48.42  70224220   70.224
 16384:    4255 0.993   793304    4286    48.42  70225635   70.226
Hash_DRBG SHA512_256
    Op      ops  secs     c/op   ops/s      c/B       B/s     mB/s
     1: 1132674 1.004     3013 1128539  3013.87   1128215    1.128
    32: 1136840 1.004     3001 1133052    93.81  36246342   36.246
    64:  781137 1.000     4354  780957    68.04  49972627   49.973
  1024:   75706 1.002    44988   75582    43.93  77394784   77.395
  8192:    9657 0.990   348505    9756    42.54  79927458   79.927
 16384:    4830 0.986   694387    4896    42.38  80229476   80.229
```

