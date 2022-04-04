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
  // 293 -bit Acorn-128 state
  bool state[acorn_utils::STATE_BIT_LEN];

  // 128 -bit secret key as bit sequence
  bool key_[128];
#pragma unroll 16
  for (size_t i = 0; i < 16; i++) {
    const size_t off = i << 3;

    key_[off + 0] = acorn_utils::bit_at<0>(key[i]);
    key_[off + 1] = acorn_utils::bit_at<1>(key[i]);
    key_[off + 2] = acorn_utils::bit_at<2>(key[i]);
    key_[off + 3] = acorn_utils::bit_at<3>(key[i]);
    key_[off + 4] = acorn_utils::bit_at<4>(key[i]);
    key_[off + 5] = acorn_utils::bit_at<5>(key[i]);
    key_[off + 6] = acorn_utils::bit_at<6>(key[i]);
    key_[off + 7] = acorn_utils::bit_at<7>(key[i]);
  }

  // 128 -bit public message nonce as bit sequence
  bool nonce_[128];
#pragma unroll 16
  for (size_t i = 0; i < 16; i++) {
    const size_t off = i << 3;

    nonce_[off + 0] = acorn_utils::bit_at<0>(nonce[i]);
    nonce_[off + 1] = acorn_utils::bit_at<1>(nonce[i]);
    nonce_[off + 2] = acorn_utils::bit_at<2>(nonce[i]);
    nonce_[off + 3] = acorn_utils::bit_at<3>(nonce[i]);
    nonce_[off + 4] = acorn_utils::bit_at<4>(nonce[i]);
    nonce_[off + 5] = acorn_utils::bit_at<5>(nonce[i]);
    nonce_[off + 6] = acorn_utils::bit_at<6>(nonce[i]);
    nonce_[off + 7] = acorn_utils::bit_at<7>(nonce[i]);
  }

  // see section 1.3.3
  acorn_utils::initialize(state, key_, nonce_);
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
  // 293 -bit Acorn-128 state
  bool state[acorn_utils::STATE_BIT_LEN];
  // 128 -bit authentication tag
  uint8_t tag_[16];

  // 128 -bit secret key as bit sequence
  bool key_[128];
#pragma unroll 16
  for (size_t i = 0; i < 16; i++) {
    const size_t off = i << 3;

    key_[off + 0] = acorn_utils::bit_at<0>(key[i]);
    key_[off + 1] = acorn_utils::bit_at<1>(key[i]);
    key_[off + 2] = acorn_utils::bit_at<2>(key[i]);
    key_[off + 3] = acorn_utils::bit_at<3>(key[i]);
    key_[off + 4] = acorn_utils::bit_at<4>(key[i]);
    key_[off + 5] = acorn_utils::bit_at<5>(key[i]);
    key_[off + 6] = acorn_utils::bit_at<6>(key[i]);
    key_[off + 7] = acorn_utils::bit_at<7>(key[i]);
  }

  // 128 -bit public message nonce as bit sequence
  bool nonce_[128];
#pragma unroll 16
  for (size_t i = 0; i < 16; i++) {
    const size_t off = i << 3;

    nonce_[off + 0] = acorn_utils::bit_at<0>(nonce[i]);
    nonce_[off + 1] = acorn_utils::bit_at<1>(nonce[i]);
    nonce_[off + 2] = acorn_utils::bit_at<2>(nonce[i]);
    nonce_[off + 3] = acorn_utils::bit_at<3>(nonce[i]);
    nonce_[off + 4] = acorn_utils::bit_at<4>(nonce[i]);
    nonce_[off + 5] = acorn_utils::bit_at<5>(nonce[i]);
    nonce_[off + 6] = acorn_utils::bit_at<6>(nonce[i]);
    nonce_[off + 7] = acorn_utils::bit_at<7>(nonce[i]);
  }

  // see section 1.3.3
  acorn_utils::initialize(state, key_, nonce_);
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
