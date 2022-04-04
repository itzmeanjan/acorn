#include "acorn.hpp"
#include "utils.hpp"
#include <cassert>
#include <string.h>

namespace test_acorn {

static inline void
encrypt_decrypt(const size_t d_len, // associated data byte-length
                const size_t ct_len // plain/ cipher text byte-length
)
{
  // how much to allocate ?
  const size_t d_size = d_len * sizeof(uint8_t);
  const size_t ct_size = ct_len * sizeof(uint8_t);
  const size_t knt_size = 16 * sizeof(uint8_t); // 128 -bit

  // acquire memory resources
  uint8_t* data = static_cast<uint8_t*>(malloc(d_size));
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_size));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_size));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_size));
  uint8_t* key = static_cast<uint8_t*>(malloc(knt_size));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(knt_size));
  uint8_t* tag = static_cast<uint8_t*>(malloc(knt_size));

  // random associated data bytes
  random_data(data, d_len);
  // random plain text bytes
  random_data(text, ct_len);
  // random secret key ( 128 -bit )
  random_data(key, 16);
  // random public message nonce ( 128 -bit )
  random_data(nonce, 16);

  // zero out to be filled up memory locations
  memset(enc, 0, ct_size);
  memset(tag, 0, knt_size);
  memset(dec, 0, ct_size);

  // Acorn-128 authenticated encryption
  acorn::encrypt(key, nonce, text, ct_len, data, d_len, enc, tag);
  // Acorn-128 verified decryption
  const bool b = acorn::decrypt(key, nonce, tag, enc, ct_len, data, d_len, dec);

  // must be `true`, check to be 100% sure !
  assert(b);

  // byte-by-byte compare to ensure that original plain text byte & decrypted
  // bytes match !
  for (size_t i = 0; i < ct_len; i++) {
    assert(text[i] == dec[i]);
  }

  // deallocate memory resources
  free(data);
  free(text);
  free(enc);
  free(dec);
  free(key);
  free(nonce);
  free(tag);
}

}
