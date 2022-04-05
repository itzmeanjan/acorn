#include "acorn.hpp"
#include "utils.hpp"
#include <cassert>
#include <string.h>

// Tests Acorn-128 AEAD implementation; read more about AEAD
// https://en.wikipedia.org/wiki/Authenticated_encryption
namespace test_acorn {

// To simulate that verified decryption fails when either of associated data/
// encrypted text bytes/ authentication tag ( 128 -bit ) is changed ( mutated ),
// I've written one test case ( see `encrypt_decrypt_failure` ), where this enum
// type can be passed as choice
enum mutate_t
{
  associated_data,
  encrypted_data,
  authentication_tag
};

// Test (authenticated) encrypt -> (verified) decrypt flow for given byte length
// of associated data & plain text
static inline void
encrypt_decrypt_success(const size_t d_len, // associated data byte-length
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

// This test attempts to simulate that if any of associated data bytes/
// encrypted data bytes/ authentication tag ( 128 -bit ) is changed ( say by
// flipping a single bit ), verified decryption process must fail !
static inline void
encrypt_decrypt_failure(
  const size_t d_len,   // associated data byte-length
  const size_t ct_len,  // plain/ cipher text byte-length
  const mutate_t choice // which one to mutate to simulate failure ?
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

  // only LSB set, all other 7 bits are reset !
  constexpr uint8_t one = static_cast<uint8_t>(0b1);

  // based on request, flip a single bit ( LSB ), when possible ( applicable for
  // associated data & encrypted data, because length can be zero for them )
  switch (choice) {
    case mutate_t::associated_data:
      // because d_len can be `>= 0`
      if (d_len > 0) {
        data[0] = static_cast<uint8_t>((data[0] >> 1) << 1) |
                  static_cast<uint8_t>(~(data[0] & one) & one);
      }
      break;
    case mutate_t::encrypted_data:
      // because ct_len can be `>= 0`
      if (ct_len > 0) {
        enc[0] = static_cast<uint8_t>((enc[0] >> 1) << 1) |
                 static_cast<uint8_t>(~(enc[0] & one) & one);
      }
      break;
    case mutate_t::authentication_tag:
      // tag will always be 16 -bytes wide
      tag[0] = static_cast<uint8_t>((tag[0] >> 1) << 1) |
               static_cast<uint8_t>(~(tag[0] & one) & one);
      break;
  }

  // Acorn-128 verified decryption; may fail, given that a single bit is flipped
  const bool b = acorn::decrypt(key, nonce, tag, enc, ct_len, data, d_len, dec);

  // if a single bit was flipped, verified decryption procedure must fail,
  // otherwise it should behave as expected !
  switch (choice) {
    case mutate_t::associated_data:
      if (d_len > 0) {
        assert(!b);
      } else {
        assert(b);
      }
      break;
    case mutate_t::encrypted_data:
      if (ct_len > 0) {
        assert(!b);
      } else {
        assert(b);
      }
      break;
    case mutate_t::authentication_tag:
      assert(!b);
      break;
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
