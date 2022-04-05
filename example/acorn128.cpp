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
