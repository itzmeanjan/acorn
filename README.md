# acorn
Accelerating Acorn: A Lightweight Authenticated Cipher

## Overview

After implementing `ascon` --- a fast, lightweight cryptographic suite, implementing authenticated encryption ( read AEAD ) & cryptographically secure hashing, I decided to take up another finalist ( in lightweight application category ) of CAESER AEAD competition --- `acorn` : a lightweight authenticated cipher suite.

> Read more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> Read more about CAESER competition [here](https://competitions.cr.yp.to/caesar-submissions.html)

> Read Acorn128 v3 specification [here](https://competitions.cr.yp.to/round3/acornv3.pdf), that's what is implemented here ⭐

> If interested in Ascon, see my work [here](https://github.com/itzmeanjan/ascon)

Acorn128 is a lightweight authenticated cipher which implements following two functions

- Authenticated encryption
- Verified decryption

Simply speaking, given a plain text byte array, which is of importance ( imagine it carries some data which is not supposed to be read by everyone ) & some associated data bytes ( which can be public, doesn't carry something to be kept secret, _think of data packet header_ ), authenticated encryption procedure generates equal number of encrypted bytes ( i.e. `len(enc) == len(text)` ) and 128 -bit authenticated tag ( think of it as MAC, see [here](https://en.wikipedia.org/wiki/Message_authentication_code) ). This procedure requires two more inputs

- 128 -bit secret key
- 128 -bit public message nonce **( don't use same nonce twice with same secret key )**

After that encrypted text can be decrypted by another party who has access to following pieces of information

- 128 -bit secret key
- 128 -bit public message nonce
- 128 -bit authentication tag ( computed 👆 )
- Encrypted bytes
- Associated data bytes

Verified decryption procedure should generate two pieces of outputs

- Decrypted data bytes ( `len(dec) == len(enc)` )
- Boolean flag denoting successful verification

After that boolean flag should be tested for truthfulness, if it doesn't pass that test, decrypted data bytes should not be consumed !

If any of authentication tag/ encrypted bytes/ associated data bytes are mutated ( even a single bit flipped ), verified decryption process should fail.

Here I keep a C++ header-only library ( with C++20 features ), implementing **Acorn128 v3**, which can be compiled down to CPU/ GPGPU ( using SYCL kernels ) executable code.

- How to test/ benchmark/ use `acorn` ?
  - Can be found below.

## Prerequisites

- Make sure you've installed `g++`/ `clang++`/ `dpcpp`; I prefer `dpcpp`, find more [here](https://www.intel.com/content/www/us/en/developer/tools/oneapi/dpc-compiler.html)

> If you happen to be using something other than `dpcpp`, consider updating Makefile.

```bash
$ dpcpp --version

Intel(R) oneAPI DPC++/C++ Compiler 2022.0.0 (2022.0.0.20211123)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /opt/intel/oneapi/compiler/2022.0.2/linux/bin-llvm
```

or

```bash
$ g++ --version

g++ (Ubuntu 10.3.0-1ubuntu1~20.04) 10.3.0
```

- You'll need system development utilities like `make`, `cmake`

```bash
$ make --version

GNU Make 4.2.1
```

```bash
$ cmake --version

cmake version 3.16.3
```

- For benchmarking Acorn128 implementation, you must have `google-benchmark` globally installed; see [here](https://github.com/google/benchmark/tree/60b16f1#installation)

- Make sure you've C++ standard library, implementing `C++20` specification, installed ( as this library uses C++20 features )

## Testing

For testing functional correctness of Acorn128 cipher suite, run

```bash
make
```

This will run two kinds of tests

- Test that everything works as expected in ideal scenario
- Test that if any of followings are mutated ( even a single bit flipped ), verified decryption certainly fails
  - Associated data bytes
  - Encrypted data bytes
  - 128 -bit authentication tag

## Benchmarking

For benchmarking authenticated encryption & verified decryption using Acorn128 cipher suite, run

> `google-benchmark` header files, source files & library must be globally installed !

```bash
make benchmark
```

```bash
2022-04-05T05:46:33+00:00
Running ./bench/a.out
Run on (4 X 2300.14 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.00, 0.00, 0.00
------------------------------------------------------------------------
Benchmark              Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------
acorn_encrypt     692409 ns       692392 ns         1009 bytes_per_second=5.72982M/s items_per_second=1.44427k/s
acorn_decrypt     697829 ns       697830 ns         1004 bytes_per_second=5.68518M/s items_per_second=1.43301k/s
```

## Usage

`acorn` is a header-only C++ library ( using C++20 features ), using it is as easy as including header file `include/acorn.hpp` in your program & adding `./include` directory to your `INCLUDE_PATH` during compilation. 

- **A**uthenticated **E**ncryption with **A**ssociated **D**ata related routines that you'll be generally interested in, are kept in `acorn::` namespace.

- Also see `include/utils.hpp`, if that helps you in anyways.

```cpp
// see https://github.com/itzmeanjan/acorn/blob/10f524a/example/acorn128.cpp

#include "acorn.hpp"
#include "utils.hpp"
#include <cassert>
#include <iostream>
#include <string.h>

// Compile it with `dpcpp -std=c++20 -O3 -I ./include example/acorn128.cpp`
int
main()
{
  // plain text/ encrypted bytes length
  constexpr size_t ct_len = 32ul;
  // associated data length
  constexpr size_t d_len = 16ul;
  // secret key/ nonce/ authentication tag length
  constexpr size_t knt_len = 16ul;

  assert(knt_len == 16ul); // don't change it; must be 128 -bit

  // plain text
  uint8_t* txt = static_cast<uint8_t*>(malloc(ct_len));
  // encrypted text
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  // decrypted text
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));
  // associated data
  uint8_t* data = static_cast<uint8_t*>(malloc(d_len));
  // 128 -bit secret key
  uint8_t* key = static_cast<uint8_t*>(malloc(knt_len));
  // 128 -bit public message nonce
  uint8_t* nonce = static_cast<uint8_t*>(malloc(knt_len));
  // 128 -bit authentication tag
  uint8_t* tag = static_cast<uint8_t*>(malloc(knt_len));

  // prepare plain text ( deterministic )
  for (size_t i = 0; i < ct_len; i++) {
    txt[i] = static_cast<uint8_t>(i);
  }

  // prepare associated data ( deterministic )
  for (size_t i = 0; i < d_len; i++) {
    data[i] = static_cast<uint8_t>(i);
  }

  // prepare secret key & nonce ( deterministic )
  for (size_t i = 0; i < knt_len; i++) {
    key[i] = static_cast<uint8_t>(i);
    nonce[i] = static_cast<uint8_t>((~i));
  }

  // clear memory for encrypted text
  memset(enc, 0, ct_len);
  // clear memory for decrypted text
  memset(dec, 0, ct_len);
  // clear memory for authentication tag
  memset(tag, 0, knt_len);

  // encrypt plain text using Acorn-128
  acorn::encrypt(key, nonce, txt, ct_len, data, d_len, enc, tag);
  // decrypt to plain text using Acorn-128
  const bool f = acorn::decrypt(key, nonce, tag, enc, ct_len, data, d_len, dec);

  // to be 100% sure that verified decryption worked as expected !
  assert(f);

  // byte-by-byte match that original plain text & decrypted text are same !
  for (size_t i = 0; i < ct_len; i++) {
    assert(txt[i] == dec[i]);
  }

  std::cout << "plain text         : " << to_hex(txt, ct_len) << std::endl;
  std::cout << "associated data    : " << to_hex(data, d_len) << std::endl;
  std::cout << "secret key         : " << to_hex(key, knt_len) << std::endl;
  std::cout << "message nonce      : " << to_hex(nonce, knt_len) << std::endl;
  std::cout << "encrypted          : " << to_hex(enc, ct_len) << std::endl;
  std::cout << "authentication tag : " << to_hex(tag, knt_len) << std::endl;
  std::cout << "decrypted text     : " << to_hex(dec, ct_len) << std::endl;

  // deallocate all memory resources
  free(txt);
  free(enc);
  free(dec);
  free(data);
  free(key);
  free(nonce);
  free(tag);

  return EXIT_SUCCESS;
}
```

Now compile & execute it with

```bash
$ g++ -std=c++20 -O3 -I ./include example/acorn128.cpp && ./a.out

plain text         : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
associated data    : 000102030405060708090a0b0c0d0e0f
secret key         : 000102030405060708090a0b0c0d0e0f
message nonce      : fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0
encrypted          : b42e4dca2acefdec58da849a2decace7952706881fef46b8abd39d3ac02a9f41
authentication tag : 06288070f2f06b8f31eaa90341f080a5
decrypted text     : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

See full example of using Acorn128 API [here](https://github.com/itzmeanjan/acorn/blob/10f524a/example/acorn128.cpp)
