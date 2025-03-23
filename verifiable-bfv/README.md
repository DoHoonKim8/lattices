This work contains Proof-Of-Concept implementation of verifiable FHE operations for BFV scheme using Plonky2 proof system.

## Parameters

Currently, bfv ciphertext space is in `\mathbb{Z}_Q[X]/(X^N+1)` for which `N` is power-of-two and `Q` is a prime such that `\mathbb{Z}_Q` has `2N`-th primitive roots of unity such that (X^N+1) is full-splitting polynomial in `\mathbb{Z}_Q`. Later, `Q = q_1 q_2 ... q_n` for which `q_i`'s are NTT-friendly primes will be supported.

If you want to generate NTT parameters, specify `Q` and `N` in `src/ntt_params/gen_param_file.sage` and run it.

## Reference

- Most of bfv implementation is brought from https://github.com/cathieyun/bfv12
