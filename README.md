# hpke-simdium

SIMD C implementation of the Hybrid Public-Key Encryption (HPKE) algorithm RFC-9180.

Uses AVX-2 and AVX-512 for speeding up KEM operations.
Supported suites:
- KEM X25519 (0x20)

## Compilation

Must enable AVX512 support to compile this library:
```bash
    $ cd hpke-simdium
    $ mkdir build; cd build
    $ cmake .. -DENABLE_AVX512=ON
    $ make all
```

## License

Licensed under the [Mozilla Public License, v. 2.0.](https://www.mozilla.org/en-US/MPL/2.0/)
