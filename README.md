# hpke-simdium

SIMD C implementation of the Hybrid Public-Key Encryption (HPKE) algorithm RFC-9180.

Uses AVX-2 and AVX-512 for speeding up KEM operations.
Supported suites:
- KEM X25519 (0x20)

## Building

To compile this library, run:

```bash
cd hpke-simdium
mkdir build; cd build
cmake ..
make all
```

## Building Third Party Libraries

### GoogleTest
To compile GoogleTest, run:

```bash
cd hpke-simdium
mkdir build_third_party; cd build_third_party
cmake ../third_party
make googletest
```

This will populate the `hpke-simdium/third_party/googletest` folder with the GoogleTest library and headers.

### OpenSSL
To compile OpenSSL, run:

```bash
cd hpke-simdium
mkdir build_third_party; cd build_third_party
cmake ../third_party
make openssl
```

This will populate the `hpke-simdium/third_party/ossl` folder with the OpenSSL library and headers.

### BoringSSL
To compile BoringSSL, run:

```bash
cd hpke-simdium
mkdir build_third_party; cd build_third_party
cmake ../third_party
make boringssl
```

This will populate the `hpke-simdium/third_party/bssl` folder with the BoringSSL library and headers.

### AWS-LC
To compile AWS-LC, run:

```bash
cd hpke-simdium
mkdir build_third_party; cd build_third_party
cmake ../third_party
make awslc
```

This will populate the `hpke-simdium/third_party/awslc` folder with the aws-lc library and headers.

## License

Licensed under the [Mozilla Public License, v. 2.0.](https://www.mozilla.org/en-US/MPL/2.0/)
