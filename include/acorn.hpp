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
  return (x & y) ^ (~x & z);
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

  return state[0] ^ ~state[107] ^ b0 ^ (ca & state[196]) ^ (cb & ks);
}

// Update state function, using algorithm written in section 1.3.2 of Acorn
// specification https://competitions.cr.yp.to/round3/acornv3.pdf
static inline void
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
  return (byte >> pos) & static_cast<uint8_t>(0b1u);
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

}
