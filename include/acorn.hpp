#pragma once
#include <cstdint>

using size_t = std::size_t;

namespace acorn {

// Acorn state bit length, see section 1.3.1 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
constexpr size_t STATE_BIT_LEN = 293ul;

// Acorn boolean function `maj`, taken from section 1.2.3 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline bool
maj(const bool x, const bool y, const bool z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

// Acorn boolean function `ch`, taken from section 1.2.3 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline bool
ch(const bool x, const bool y, const bool z)
{
  return (x & y) ^ (!x & z);
}

// Generate keystream bit, taken from section 1.3.2 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline bool
ksg128(const bool* const state // 293 -bit state
)
{
  const bool b0 = maj(state[235], state[61], state[193]);
  const bool b1 = ch(state[230], state[111], state[66]);

  return state[12] ^ state[154] ^ b0 ^ b1;
}

// Compute feedback bit, using algorithm written in section 1.3.2 of Acorn
// specification https://competitions.cr.yp.to/round3/acornv3.pdf
static inline bool
fbk128(const bool* const state, // 293 -bit state
       const bool ca,           // control bit `a`
       const bool cb,           // control bit `b`
       const bool ks            // key stream bit generated using `ksg128`
)
{
  const bool b0 = maj(state[244], state[23], state[160]);

  return state[0] ^ !state[107] ^ b0 ^ (ca & state[196]) ^ (cb & ks);
}

// Update state function, using algorithm written in section 1.3.2 of Acorn
// specification https://competitions.cr.yp.to/round3/acornv3.pdf
static inline bool
state_update_128(bool* const state, // 293 -bit state
                 const bool m,      // message bit
                 const bool ca,     // control bit `a`
                 const bool cb      // control bit `b`
)
{
  // step 1
  state[289] = state[289] ^ state[235] ^ state[230];
  state[230] = state[230] ^ state[196] ^ state[193];
  state[193] = state[193] ^ state[160] ^ state[154];
  state[154] = state[154] ^ state[111] ^ state[107];
  state[107] = state[107] ^ state[66] ^ state[61];
  state[61] = state[61] ^ state[23] ^ state[0];
  // step 2
  const bool ks = ksg128(state); // key stream bit
  // step 3
  const bool fb = fbk128(state, ca, cb, ks); // feedback bit
  // step 4
  for (size_t j = 0; j < STATE_BIT_LEN - 1ul; j++) {
    state[j] = state[j + 1];
  }
  state[292] = fb ^ m;

  return ks;
}

// Initialize Acorn128 state, following algorithm specified in section 1.3.3 of
// Acorn specification https://competitions.cr.yp.to/round3/acornv3.pdf
static inline void
initialize(bool* const __restrict state,     // 293 -bit state
           const bool* const __restrict key, // 128 -bit secret key
           const bool* const __restrict iv   // 128 -bit initialization vector
)
{
  // step 1
  for (size_t i = 0; i < STATE_BIT_LEN; i++) {
    state[i] = false;
  }

  // --- step 2, 3, 4 ---
  for (size_t i = 0; i < 128; i++) {
    state_update_128(state, key[i], true, true);
  }

  for (size_t i = 0; i < 128; i++) {
    state_update_128(state, iv[i], true, true);
  }

  state_update_128(state, key[0] ^ true, true, true);

  for (size_t i = 1; i < 1536; i++) {
    state_update_128(state, key[i % 128], true, true);
  }
  // --- step 2, 3, 4 ---
}

// Compile time evaluation of template argument for `bit_at` routine; ensuring
// requested bit position stays inside [0, 8)
constexpr bool
check_pos(const size_t pos)
{
  return pos < 8;
}

// Given 8 -bit unsigned integer, it selects requested bit value
// for `pos` | 0 <= pos <= 7
template<const size_t pos>
static inline bool
bit_at(const uint8_t byte) requires(check_pos(pos))
{
  return static_cast<bool>((byte >> pos) & static_cast<uint8_t>(0b1u));
}

// Processing the associated data bytes, following algorithm described in
// section 1.3.4 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline void
process_associated_data(
  bool* const __restrict state,         // 293 -bit state
  const uint8_t* const __restrict data, // associated data bytes
  const size_t data_len                 // len(data), can be >= 0
)
{
  // line 1 of step 1; consume all associated data bits
  for (size_t i = 0; i < data_len; i++) {
    const uint8_t byte = data[i];

    // sequentially consume 8 -bits per byte
    state_update_128(state, bit_at<7>(byte), true, true);
    state_update_128(state, bit_at<6>(byte), true, true);
    state_update_128(state, bit_at<5>(byte), true, true);
    state_update_128(state, bit_at<4>(byte), true, true);
    state_update_128(state, bit_at<3>(byte), true, true);
    state_update_128(state, bit_at<2>(byte), true, true);
    state_update_128(state, bit_at<1>(byte), true, true);
    state_update_128(state, bit_at<0>(byte), true, true);
  }

  // line 2 of step 1; append single `1` -bit
  state_update_128(state, true, true, true);

  // line 3 of step 1; append 255 `0` -bits
  for (size_t i = 1; i < 128; i++) {
    state_update_128(state, false, true, true);
  }

  for (size_t i = 128; i < 256; i++) {
    state_update_128(state, false, false, true);
  }
}

// Encrypt plain text bytes and write ciphered bytes to allocated memory
// location, following algorithm defined in section 1.3.5 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline void
process_plain_text(bool* const __restrict state,         // 293 -bit state
                   const uint8_t* const __restrict text, // plain text bytes
                   uint8_t* const __restrict cipher,     // ciphered data bytes
                   const size_t ct_len                   // can be >= 0
)
{
  // line 1 of step 1; compute encrypted bits
  //
  // also see step 3 of algorithm defined in section 1.3.5
  for (size_t i = 0; i < ct_len; i++) {
    const uint8_t byte = text[i];

    const bool p7 = bit_at<7>(byte);
    const bool ks7 = state_update_128(state, p7, true, false);
    const bool c7 = ks7 ^ p7; // encrypted bit

    const bool p6 = bit_at<6>(byte);
    const bool ks6 = state_update_128(state, p6, true, false);
    const bool c6 = ks6 ^ p6; // encrypted bit

    const bool p5 = bit_at<5>(byte);
    const bool ks5 = state_update_128(state, p5, true, false);
    const bool c5 = ks5 ^ p5; // encrypted bit

    const bool p4 = bit_at<4>(byte);
    const bool ks4 = state_update_128(state, p4, true, false);
    const bool c4 = ks4 ^ p4; // encrypted bit

    const bool p3 = bit_at<3>(byte);
    const bool ks3 = state_update_128(state, p3, true, false);
    const bool c3 = ks3 ^ p3; // encrypted bit

    const bool p2 = bit_at<2>(byte);
    const bool ks2 = state_update_128(state, p2, true, false);
    const bool c2 = ks2 ^ p2; // encrypted bit

    const bool p1 = bit_at<1>(byte);
    const bool ks1 = state_update_128(state, p1, true, false);
    const bool c1 = ks1 ^ p1; // encrypted bit

    const bool p0 = bit_at<0>(byte);
    const bool ks0 = state_update_128(state, p0, true, false);
    const bool c0 = ks0 ^ p0; // encrypted bit

    // from 8 encrypted bits prepare single ciphered byte
    const uint8_t enc = static_cast<uint8_t>(static_cast<uint8_t>(c7) << 7) |
                        static_cast<uint8_t>(static_cast<uint8_t>(c6) << 6) |
                        static_cast<uint8_t>(static_cast<uint8_t>(c5) << 5) |
                        static_cast<uint8_t>(static_cast<uint8_t>(c4) << 4) |
                        static_cast<uint8_t>(static_cast<uint8_t>(c3) << 3) |
                        static_cast<uint8_t>(static_cast<uint8_t>(c2) << 2) |
                        static_cast<uint8_t>(static_cast<uint8_t>(c1) << 1) |
                        static_cast<uint8_t>(static_cast<uint8_t>(c0));

    // write 8 encrypted bits to allocated memory
    cipher[i] = enc;
  }

  // line 2 of step 1; append single `1` -bit
  state_update_128(state, true, true, false);

  // line 3 of step 1; append 255 `0` -bits
  for (size_t i = 1; i < 128; i++) {
    state_update_128(state, false, true, false);
  }

  for (size_t i = 128; i < 256; i++) {
    state_update_128(state, false, false, false);
  }
}

// Decrypts ciphered bytes and writes them to allocated memory, following
// algorithm defined in section 1.3.5 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline void
process_cipher_text(
  bool* const __restrict state,           // 293 -bit state
  const uint8_t* const __restrict cipher, // ciphered data bytes
  uint8_t* const __restrict text,         // plain text bytes
  const size_t ct_len                     // can be >= 0
)
{
  process_plain_text(state, cipher, text, ct_len);
}

// Finalize Acorn-128, which generates authentication tag; this is result of
// authenticated encryption process & it also helps in conducting verified
// decryption
//
// See algorithm defined in section 1.3.6 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline void
finalize(bool* const __restrict state, uint8_t* const __restrict tag)
{
  for (size_t i = 0; i < 640; i++) {
    state_update_128(state, false, true, true);
  }

  // take last 128 keystream bits & interpret it as authentication tag
  for (size_t i = 0; i < 16; i++) {
    // compute 8 authentication tag bits; do it 16 times;
    // making 128 -bit authentication tag
    const bool b7 = state_update_128(state, false, true, true);
    const bool b6 = state_update_128(state, false, true, true);
    const bool b5 = state_update_128(state, false, true, true);
    const bool b4 = state_update_128(state, false, true, true);
    const bool b3 = state_update_128(state, false, true, true);
    const bool b2 = state_update_128(state, false, true, true);
    const bool b1 = state_update_128(state, false, true, true);
    const bool b0 = state_update_128(state, false, true, true);

    // authentication tag byte
    const uint8_t t_byte = static_cast<uint8_t>(static_cast<uint8_t>(b7) << 7) |
                           static_cast<uint8_t>(static_cast<uint8_t>(b6) << 6) |
                           static_cast<uint8_t>(static_cast<uint8_t>(b5) << 5) |
                           static_cast<uint8_t>(static_cast<uint8_t>(b4) << 4) |
                           static_cast<uint8_t>(static_cast<uint8_t>(b3) << 3) |
                           static_cast<uint8_t>(static_cast<uint8_t>(b2) << 2) |
                           static_cast<uint8_t>(static_cast<uint8_t>(b1) << 1) |
                           static_cast<uint8_t>(static_cast<uint8_t>(b0));

    tag[i] = t_byte;
  }
}

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
        const size_t t_len,                    // len(text)
        const uint8_t* const __restrict data,  // associated data bytes
        const size_t d_len,                    // len(data)
        uint8_t* const __restrict cipher,      // encrypted bytes
        const size_t c_len,                    // len(cipher); c_len == t_len
        uint8_t* const __restrict tag          // 128 -bit authentication tag
)
{
  // 293 -bit Acorn-128 state
  bool state[STATE_BIT_LEN];

  // 128 -bit secret key as bit sequence
  bool key_[128];
#pragma unroll 16
  for (size_t i = 0; i < 16; i++) {
    const size_t off = i << 3;

    key_[off + 0] = bit_at<7>(key[i]);
    key_[off + 1] = bit_at<6>(key[i]);
    key_[off + 2] = bit_at<5>(key[i]);
    key_[off + 3] = bit_at<4>(key[i]);
    key_[off + 4] = bit_at<3>(key[i]);
    key_[off + 5] = bit_at<2>(key[i]);
    key_[off + 6] = bit_at<1>(key[i]);
    key_[off + 7] = bit_at<0>(key[i]);
  }

  // 128 -bit public message nonce as bit sequence
  bool nonce_[128];
#pragma unroll 16
  for (size_t i = 0; i < 16; i++) {
    const size_t off = i << 3;

    nonce_[off + 0] = bit_at<7>(nonce[i]);
    nonce_[off + 1] = bit_at<6>(nonce[i]);
    nonce_[off + 2] = bit_at<5>(nonce[i]);
    nonce_[off + 3] = bit_at<4>(nonce[i]);
    nonce_[off + 4] = bit_at<3>(nonce[i]);
    nonce_[off + 5] = bit_at<2>(nonce[i]);
    nonce_[off + 6] = bit_at<1>(nonce[i]);
    nonce_[off + 7] = bit_at<0>(nonce[i]);
  }

  // see section 1.3.3
  initialize(state, key_, nonce_);
  // see section 1.3.4
  process_associated_data(state, data, d_len);
  // see section 1.3.5
  process_plain_text(state, text, cipher, t_len);
  // see section 1.3.6
  finalize(state, tag);
}

// Acorn-128 verified decryption, given `c_len` -bytes encrypted text, `d_len`
// -bytes associated data, 128 -bit secret key, 128 -bit public message nonce &
// 128 -bit authentication tag, this routine computes `t_len` -bytes decrypted
// text along with boolean verification flag `f`;
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
        const size_t c_len,                     // len(cipher)
        const uint8_t* const __restrict data,   // associated data bytes
        const size_t d_len,                     // len(data)
        uint8_t* const __restrict text,         // decrypted bytes
        const size_t t_len                      // len(text); t_len == c_len
)
{
  // 293 -bit Acorn-128 state
  bool state[STATE_BIT_LEN];
  // 128 -bit authentication tag
  uint8_t tag_[16];

  // 128 -bit secret key as bit sequence
  bool key_[128];
#pragma unroll 16
  for (size_t i = 0; i < 16; i++) {
    const size_t off = i << 3;

    key_[off + 0] = bit_at<7>(key[i]);
    key_[off + 1] = bit_at<6>(key[i]);
    key_[off + 2] = bit_at<5>(key[i]);
    key_[off + 3] = bit_at<4>(key[i]);
    key_[off + 4] = bit_at<3>(key[i]);
    key_[off + 5] = bit_at<2>(key[i]);
    key_[off + 6] = bit_at<1>(key[i]);
    key_[off + 7] = bit_at<0>(key[i]);
  }

  // 128 -bit public message nonce as bit sequence
  bool nonce_[128];
#pragma unroll 16
  for (size_t i = 0; i < 16; i++) {
    const size_t off = i << 3;

    nonce_[off + 0] = bit_at<7>(nonce[i]);
    nonce_[off + 1] = bit_at<6>(nonce[i]);
    nonce_[off + 2] = bit_at<5>(nonce[i]);
    nonce_[off + 3] = bit_at<4>(nonce[i]);
    nonce_[off + 4] = bit_at<3>(nonce[i]);
    nonce_[off + 5] = bit_at<2>(nonce[i]);
    nonce_[off + 6] = bit_at<1>(nonce[i]);
    nonce_[off + 7] = bit_at<0>(nonce[i]);
  }

  // see section 1.3.3
  initialize(state, key_, nonce_);
  // see section 1.3.4
  process_associated_data(state, data, d_len);
  // see section 1.3.5
  process_cipher_text(state, cipher, text, c_len);
  // see section 1.3.6
  finalize(state, tag_);

  // verification flag
  bool flag = true;
  // compare authentication tag byte-by-byte
  for (size_t i = 0; i < 16; i++) {
    flag &= (tag[i] == tag_[i]);
  }
  return flag;
}

}
