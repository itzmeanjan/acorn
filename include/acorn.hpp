#pragma once
#include <cstdint>

using size_t = std::size_t;

namespace acorn {

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
  for (size_t j = 0; j < 292; j++) {
    state[j] = state[j + 1];
  }
  state[292] = fb ^ m;
}

}
