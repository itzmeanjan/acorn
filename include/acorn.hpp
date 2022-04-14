#pragma once
#include "acorn_utils.hpp"

// Acorn-128: A lightweight authenticated cipher ( read Authenticated Encryption
// with Associated Data )
namespace acorn {

// Acorn-128 authenticated encryption, given `t_len` -bytes plain text, `d_len`
// -bytes associated data, 128 -bit secret key & 128 -bit public message nonce,
// this routine computes `c_len` -bytes encrypted text along with 128 -bit
// authentication tag
//
// Note, assert t_len == c_len
//
// See algorithms defined in section 1.3.{3,4,5,6} of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline void
encrypt(const uint8_t* const __restrict key,   // 128 -bit secret key
        const uint8_t* const __restrict nonce, // 128 -bit message nonce
        const uint8_t* const __restrict text,  // plain text
        const size_t ct_len,                   // len(text), len(cipher)
        const uint8_t* const __restrict data,  // associated data bytes
        const size_t d_len,                    // len(data)
        uint8_t* const __restrict cipher,      // encrypted bytes
        uint8_t* const __restrict tag          // 128 -bit authentication tag
)
{
  // 293 -bit Acorn-128 state, zero initialize
  uint64_t state[acorn_utils::LFSR_CNT] = { 0ul };

  // see section 1.3.3
  acorn_utils::initialize(state, key, nonce);
  // see section 1.3.4
  acorn_utils::process_associated_data(state, data, d_len);
  // see section 1.3.5
  acorn_utils::process_plain_text(state, text, cipher, ct_len);
  // see section 1.3.6
  acorn_utils::finalize(state, tag);
}

// Acorn-128 verified decryption, given `c_len` -bytes encrypted text, `d_len`
// -bytes associated data, 128 -bit secret key, 128 -bit public message nonce &
// 128 -bit authentication tag, this routine computes `t_len` -bytes decrypted
// text along with boolean verification flag `f`, denoting success of
// verification process
//
// Always ensure `assert f`, otherwise something is off !
//
// Note, assert c_len == t_len
//
// See algorithms defined in section 1.3.{3,4,5,6} of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline bool
decrypt(const uint8_t* const __restrict key,    // 128 -bit secret key
        const uint8_t* const __restrict nonce,  // 128 -bit message nonce
        const uint8_t* const __restrict tag,    // 128 -bit authentication tag
        const uint8_t* const __restrict cipher, // encrypted bytes
        const size_t ct_len,                    // len(cipher), len(text)
        const uint8_t* const __restrict data,   // associated data bytes
        const size_t d_len,                     // len(data)
        uint8_t* const __restrict text          // decrypted bytes
)
{
  // 293 -bit Acorn-128 state, zero initialize
  uint64_t state[acorn_utils::LFSR_CNT] = { 0ul };
  // 128 -bit authentication tag
  uint8_t tag_[16];

  // see section 1.3.3
  acorn_utils::initialize(state, key, nonce);
  // see section 1.3.4
  acorn_utils::process_associated_data(state, data, d_len);
  // see section 1.3.5
  acorn_utils::process_cipher_text(state, cipher, text, ct_len);
  // see section 1.3.6
  acorn_utils::finalize(state, tag_);

  // verification flag
  bool fail = false;
  // compare authentication tag byte-by-byte
  for (size_t i = 0; i < 16; i++) {
    fail |= (tag[i] ^ tag_[i]);
  }
  return !fail;
}

}
