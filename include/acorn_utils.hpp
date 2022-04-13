#pragma once
#include <cstdint>

using size_t = std::size_t;

// Acorn-128: A lightweight authenticated cipher ( read Authenticated Encryption
// with Associated Data )
//
// Underlying basic functions such as updating Linear Feedback Shift
// Registers, initializing state register, processing associated data &
// processing plain/ ciphered text is implemented under this namespace
namespace acorn_utils {

// Acorn state can be represented using 7 linear feedback shift registers,
// making total of 293 -bits
//
// Due to unequal bit length of 7 LFSRs it takes seven 64 -bit unsigned integers
// to represent whole 293 -bit state register
//
// See figure 1.1 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
constexpr size_t LFSR_CNT = 7ul;

// Maximum number which can be represented using 8 -bit unsigned interger
constexpr uint8_t MAX_U8 = 0xffu;
// Minimum number which can be represented using 8 -bit unsigned interger
constexpr uint8_t MIN_U8 = 0u;

// Maximum number which can be represented using 32 -bit unsigned interger
constexpr uint32_t MAX_U32 = 0xffffffffu;
// Minimum number which can be represented using 32 -bit unsigned interger
constexpr uint32_t MIN_U32 = 0u;

// Given an array of four big endian bytes this function interprets them as a
// 32 -bit unsigned integer
static inline uint32_t
from_be_bytes(const uint8_t* const __restrict bytes)
{
  return (static_cast<uint32_t>(bytes[0]) << 24) |
         (static_cast<uint32_t>(bytes[1]) << 16) |
         (static_cast<uint32_t>(bytes[2]) << 8) |
         (static_cast<uint32_t>(bytes[3]) << 0);
}

// Given a 32 -bit unsigned integer, this function interprets it as four big
// endian bytes
static inline void
to_be_bytes(const uint32_t word, uint8_t* const __restrict bytes)
{
#if defined(__clang__)
#pragma unroll 4
#endif
  for (size_t i = 0; i < 4; i++) {
    bytes[i] = static_cast<uint8_t>(word >> ((3u - i) << 3));
  }
}

// Acorn function `maj`, taken from section 1.2.3 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline uint64_t
maj(const uint64_t x, const uint64_t y, const uint64_t z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

// Acorn function `ch`, taken from section 1.2.3 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline uint64_t
ch(const uint64_t x, const uint64_t y, const uint64_t z)
{
  return (x & y) ^ (~x & z);
}

// Generate 32 keystream bits, taken from section 1.3.2 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline uint32_t
ksg128(
  const uint64_t* const state // 293 -bit state represented as seven u64 words
)
{
  const uint64_t w235 = state[5] >> 5;
  const uint64_t w111 = state[2] >> 4;
  const uint64_t w66 = state[1] >> 5;
  const uint64_t w12 = state[0] >> 12;

  const uint64_t w0 = maj(w235, state[1], state[4]);
  const uint64_t w1 = ch(state[5], w111, w66);
  return static_cast<uint32_t>(w12 ^ state[3] ^ w0 ^ w1);
}

// Compute 32 feedback bits, using algorithm written in section 1.3.2 of Acorn
// specification https://competitions.cr.yp.to/round3/acornv3.pdf
static inline uint32_t
fbk128(const uint64_t* const state, // 293 -bit state register
       const uint32_t ca,           // 32 control bits `a`
       const uint32_t cb,           // 32 control bits `b`
       const uint32_t ks // 32 key stream bits generated using `ksg128`
)
{
  const uint64_t w244 = state[5] >> 14;
  const uint64_t w23 = state[0] >> 23;
  const uint64_t w160 = state[3] >> 6;
  const uint64_t w196 = state[4] >> 3;

  const uint64_t w0 = maj(w244, w23, w160);
  const uint64_t w1 = static_cast<uint64_t>(cb & ks);
  const uint64_t w2 = w196 & static_cast<uint64_t>(ca);

  const uint64_t w3 = w0 ^ w1 ^ w2;
  return static_cast<uint32_t>(state[0] ^ ~state[2] ^ w3);
}

// Compute 8 feedback bits, using algorithm written in section 1.3.2 of Acorn
// specification https://competitions.cr.yp.to/round3/acornv3.pdf
static inline uint8_t
fbk128(const uint64_t* const state, // 293 -bit state register
       const uint8_t ca,            // 8 control bits `a`
       const uint8_t cb,            // 8 control bits `b`
       const uint8_t ks // 8 key stream bits generated using `ksg128`
)
{
  const uint64_t w244 = state[5] >> 14;
  const uint64_t w23 = state[0] >> 23;
  const uint64_t w160 = state[3] >> 6;
  const uint64_t w196 = state[4] >> 3;

  const uint64_t w0 = maj(w244, w23, w160);
  const uint64_t w1 = static_cast<uint64_t>(cb & ks);
  const uint64_t w2 = w196 & static_cast<uint64_t>(ca);

  const uint64_t w3 = w0 ^ w1 ^ w2;
  return static_cast<uint8_t>(state[0] ^ ~state[2] ^ w3);
}

// Update state function operating on 32 -bits at a time, using algorithm
// written in section 1.3.2 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
//
// Note, if you're attempting to decrypt text back, don't use this function for
// state updation, see below.
static inline uint32_t
state_update_128(uint64_t* const state, // 293 -bit state
                 const uint32_t m,      // 32 message bits
                 const uint32_t ca,     // 32 control bits `a`
                 const uint32_t cb      // 32 control bits `b`
)
{
  const uint64_t w235 = state[5] >> 5;
  const uint64_t w196 = state[4] >> 3;
  const uint64_t w160 = state[3] >> 6;
  const uint64_t w111 = state[2] >> 4;
  const uint64_t w66 = state[1] >> 5;
  const uint64_t w23 = state[0] >> 23;

  // step 1
  state[6] ^= (state[5] ^ w235) & MAX_U32;
  state[5] ^= (state[4] ^ w196) & MAX_U32;
  state[4] ^= (state[3] ^ w160) & MAX_U32;
  state[3] ^= (state[2] ^ w111) & MAX_U32;
  state[2] ^= (state[1] ^ w66) & MAX_U32;
  state[1] ^= (state[0] ^ w23) & MAX_U32;
  // step 2
  const uint32_t ks = ksg128(state); // 32 key stream bits
  // step 3
  const uint32_t fb = fbk128(state, ca, cb, ks); // 32 feedback bits
  // step 4
  state[6] ^= (static_cast<uint64_t>(fb ^ m) << 4);
  state[0] = (state[0] >> 32) | ((state[1] & MAX_U32) << 29); // 61 - 32
  state[1] = (state[1] >> 32) | ((state[2] & MAX_U32) << 14); // 46 - 32
  state[2] = (state[2] >> 32) | ((state[3] & MAX_U32) << 15); // 47 - 32
  state[3] = (state[3] >> 32) | ((state[4] & MAX_U32) << 7);  // 39 - 32
  state[4] = (state[4] >> 32) | ((state[5] & MAX_U32) << 5);  // 37 - 32
  state[5] = (state[5] >> 32) | ((state[6] & MAX_U32) << 27); // 59 - 32
  state[6] = state[6] >> 32;

  return ks;
}

// Update state function operating on 32 -bits at a time, using algorithm
// written in section 1.3.2 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
//
// Note, only use this function when `m_in` holds 32 encrypted bits & you want
// to decrypt them back & keep in `m_out`
//
// Also note, this function doesn't return 32 key stream bits ( notice above
// overloaded variant does ) because when decrypting bits ( that's when this
// function is supposed to be invoked ) key stream bits won't be required
// anymore as we've already recovered plain text inside this function
static inline void
state_update_128(
  uint64_t* const __restrict state, // 293 -bit state
  const uint32_t m_in,              // 32 encrypted message bits
  uint32_t* const __restrict m_out, // 32 decrypted message bits ( result ! )
  const uint32_t ca,                // 32 control bits `a`
  const uint32_t cb                 // 32 control bits `b`
)
{
  const uint64_t w235 = state[5] >> 5;
  const uint64_t w196 = state[4] >> 3;
  const uint64_t w160 = state[3] >> 6;
  const uint64_t w111 = state[2] >> 4;
  const uint64_t w66 = state[1] >> 5;
  const uint64_t w23 = state[0] >> 23;

  // step 1
  state[6] ^= (state[5] ^ w235) & MAX_U32;
  state[5] ^= (state[4] ^ w196) & MAX_U32;
  state[4] ^= (state[3] ^ w160) & MAX_U32;
  state[3] ^= (state[2] ^ w111) & MAX_U32;
  state[2] ^= (state[1] ^ w66) & MAX_U32;
  state[1] ^= (state[0] ^ w23) & MAX_U32;
  // step 2
  const uint32_t ks = ksg128(state); // 32 key stream bits
  *m_out = m_in ^ ks;                // 32 decrypted bits
  // step 3
  const uint32_t fb = fbk128(state, ca, cb, ks); // 32 feedback bits
  // step 4
  state[6] ^= (static_cast<uint64_t>(fb ^ *m_out) << 4);
  state[0] = (state[0] >> 32) | ((state[1] & MAX_U32) << 29); // 61 - 32
  state[1] = (state[1] >> 32) | ((state[2] & MAX_U32) << 14); // 46 - 32
  state[2] = (state[2] >> 32) | ((state[3] & MAX_U32) << 15); // 47 - 32
  state[3] = (state[3] >> 32) | ((state[4] & MAX_U32) << 7);  // 39 - 32
  state[4] = (state[4] >> 32) | ((state[5] & MAX_U32) << 5);  // 37 - 32
  state[5] = (state[5] >> 32) | ((state[6] & MAX_U32) << 27); // 59 - 32
  state[6] = state[6] >> 32;
}

// Update state function operating on 8 -bits at a time, using algorithm written
// in section 1.3.2 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
//
// Note, if you're attempting to decrypt text back, don't use this function for
// state updation, see below.
static inline uint8_t
state_update_128(uint64_t* const state, // 293 -bit state
                 const uint8_t m,       // 8 message bits
                 const uint8_t ca,      // 8 control bits `a`
                 const uint8_t cb       // 8 control bits `b`
)
{
  const uint64_t w235 = state[5] >> 5;
  const uint64_t w196 = state[4] >> 3;
  const uint64_t w160 = state[3] >> 6;
  const uint64_t w111 = state[2] >> 4;
  const uint64_t w66 = state[1] >> 5;
  const uint64_t w23 = state[0] >> 23;

  // step 1
  state[6] ^= (state[5] ^ w235) & MAX_U8;
  state[5] ^= (state[4] ^ w196) & MAX_U8;
  state[4] ^= (state[3] ^ w160) & MAX_U8;
  state[3] ^= (state[2] ^ w111) & MAX_U8;
  state[2] ^= (state[1] ^ w66) & MAX_U8;
  state[1] ^= (state[0] ^ w23) & MAX_U8;
  // step 2
  const uint8_t ks = static_cast<uint8_t>(ksg128(state)); // 8 key stream bits
  // step 3
  const uint8_t fb = fbk128(state, ca, cb, ks); // 8 feedback bits
  // step 4
  state[6] ^= (static_cast<uint64_t>(fb ^ m) << 4);
  state[0] = (state[0] >> 8) | ((state[1] & MAX_U8) << 53); // 61 - 8
  state[1] = (state[1] >> 8) | ((state[2] & MAX_U8) << 38); // 46 - 8
  state[2] = (state[2] >> 8) | ((state[3] & MAX_U8) << 39); // 47 - 8
  state[3] = (state[3] >> 8) | ((state[4] & MAX_U8) << 31); // 39 - 8
  state[4] = (state[4] >> 8) | ((state[5] & MAX_U8) << 29); // 37 - 8
  state[5] = (state[5] >> 8) | ((state[6] & MAX_U8) << 51); // 59 - 8
  state[6] = state[6] >> 8;

  return ks;
}

// Update state function operating on 8 -bits at a time, using algorithm written
// in section 1.3.2 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
//
// Note, use this function for Acorn-128 state updation only when you're
// attempting to decrypt 8 -bits. Encrypted input 8 -bits need to be present in
// `m_in`, while decrypted output 8 -bits to live in `m_out`.
//
// Also note, this function doesn't need to return 8 key stream bits because
// decrypted bits are recovered back from encrypted bits inside this function
// body, so key steram bits are quite useless to function caller
static inline void
state_update_128(uint64_t* const __restrict state, // 293 -bit state
                 const uint8_t m_in,               // 8 encrypted message bits
                 uint8_t* const __restrict m_out,  // 8 decrypted message bits
                 const uint8_t ca,                 // 8 control bits `a`
                 const uint8_t cb                  // 8 control bits `b`
)
{
  const uint64_t w235 = state[5] >> 5;
  const uint64_t w196 = state[4] >> 3;
  const uint64_t w160 = state[3] >> 6;
  const uint64_t w111 = state[2] >> 4;
  const uint64_t w66 = state[1] >> 5;
  const uint64_t w23 = state[0] >> 23;

  // step 1
  state[6] ^= (state[5] ^ w235) & MAX_U8;
  state[5] ^= (state[4] ^ w196) & MAX_U8;
  state[4] ^= (state[3] ^ w160) & MAX_U8;
  state[3] ^= (state[2] ^ w111) & MAX_U8;
  state[2] ^= (state[1] ^ w66) & MAX_U8;
  state[1] ^= (state[0] ^ w23) & MAX_U8;
  // step 2
  const uint8_t ks = static_cast<uint8_t>(ksg128(state)); // 8 key stream bits
  *m_out = m_in ^ ks;                                     // 8 decrypted bits
  // step 3
  const uint8_t fb = fbk128(state, ca, cb, ks) ^ *m_out; // 8 feedback bits
  // step 4
  state[6] ^= (static_cast<uint64_t>(fb) << 4);
  state[0] = (state[0] >> 8) | ((state[1] & MAX_U8) << 53); // 61 - 8
  state[1] = (state[1] >> 8) | ((state[2] & MAX_U8) << 38); // 46 - 8
  state[2] = (state[2] >> 8) | ((state[3] & MAX_U8) << 39); // 47 - 8
  state[3] = (state[3] >> 8) | ((state[4] & MAX_U8) << 31); // 39 - 8
  state[4] = (state[4] >> 8) | ((state[5] & MAX_U8) << 29); // 37 - 8
  state[5] = (state[5] >> 8) | ((state[6] & MAX_U8) << 51); // 59 - 8
  state[6] = state[6] >> 8;
}

// Initialize Acorn128 state, following algorithm specified in section 1.3.3 of
// Acorn specification https://competitions.cr.yp.to/round3/acornv3.pdf
static inline void
initialize(
  uint64_t* const __restrict state,    // 293 -bit state ( ensure zeroed ! )
  const uint8_t* const __restrict key, // 128 -bit secret key
  const uint8_t* const __restrict iv   // 128 -bit initialization vector
)
{
  // --- step 2, 3, 4 ---
  for (size_t i = 0; i < 4; i++) {
    const uint32_t word = from_be_bytes(key + (i << 2));
    state_update_128(state, word, MAX_U32, MAX_U32);
  }

  for (size_t i = 0; i < 4; i++) {
    const uint32_t word = from_be_bytes(iv + (i << 2));
    state_update_128(state, word, MAX_U32, MAX_U32);
  }

  state_update_128(state, from_be_bytes(key) ^ 0b1u, MAX_U32, MAX_U32);

  for (size_t i = 1; i < 48; i++) {
    const uint32_t word = from_be_bytes(key + ((i & 3) << 2));
    state_update_128(state, word, MAX_U32, MAX_U32);
  }
  // --- step 2, 3, 4 ---
}

// Processing the associated data bytes, following algorithm described in
// section 1.3.4 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline void
process_associated_data(
  uint64_t* const __restrict state,     // 293 -bit state
  const uint8_t* const __restrict data, // associated data bytes
  const size_t data_len                 // len(data), can be >= 0
)
{
  const size_t u32_cnt = data_len >> 2; // 32 -bit chunk count
  const size_t u08_cnt = data_len % 4;  // remaining 8 -bit chunk count

  // line 1 of step 1; consume all associated data bits
  for (size_t i = 0; i < u32_cnt; i++) {
    const uint32_t word = from_be_bytes(data + (i << 2));
    state_update_128(state, word, MAX_U32, MAX_U32);
  }

  for (size_t i = 0; i < u08_cnt; i++) {
    state_update_128(state, data[(u32_cnt << 2) + i], MAX_U8, MAX_U8);
  }

  // line 2 of step 1; append single `1` -bit
  state_update_128(state, 1u, MAX_U32, MAX_U32);

  // line 3 of step 1; append 255 `0` -bits
  for (size_t i = 0; i < 4; i++) {
    state_update_128(state, 0u, MAX_U32, MAX_U32);
  }

  for (size_t i = 4; i < 8; i++) {
    state_update_128(state, 0u, MIN_U32, MAX_U32);
  }
}

// Encrypt plain text bytes and write ciphered bytes to allocated memory
// location, following algorithm defined in section 1.3.5 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline void
process_plain_text(uint64_t* const __restrict state,     // 293 -bit state
                   const uint8_t* const __restrict text, // plain text bytes
                   uint8_t* const __restrict cipher,     // ciphered data bytes
                   const size_t ct_len                   // can be >= 0
)
{
  const size_t u32_cnt = ct_len >> 2; // 32 -bit chunk count
  const size_t u08_cnt = ct_len % 4;  // remaining 8 -bit chunk count

  // line 1 of step 1; compute encrypted bits
  //
  // also see step 3 of algorithm defined in section 1.3.5
  for (size_t i = 0; i < u32_cnt; i++) {
    const uint32_t dec = from_be_bytes(text + (i << 2));
    const uint32_t ks = state_update_128(state, dec, MAX_U32, MIN_U32);

    const uint32_t enc = dec ^ ks;
    to_be_bytes(enc, cipher + (i << 2));
  }

  for (size_t i = 0; i < u08_cnt; i++) {
    const uint8_t dec = text[(u32_cnt << 2) + i];
    const uint8_t ks = state_update_128(state, dec, MAX_U8, MIN_U8);

    const uint8_t enc = dec ^ ks;
    cipher[(u32_cnt << 2) + i] = enc;
  }

  // line 2 of step 1; append single `1` -bit
  state_update_128(state, 1u, MAX_U32, MIN_U32);

  // line 3 of step 1; append 255 `0` -bits
  for (size_t i = 0; i < 4; i++) {
    state_update_128(state, 0u, MAX_U32, MIN_U32);
  }

  for (size_t i = 4; i < 8; i++) {
    state_update_128(state, 0u, MIN_U32, MIN_U32);
  }
}

// Decrypts ciphered bytes and writes them to allocated memory, following
// algorithm defined in section 1.3.5 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline void
process_cipher_text(
  uint64_t* const __restrict state,       // 293 -bit state
  const uint8_t* const __restrict cipher, // ciphered data bytes
  uint8_t* const __restrict text,         // plain text bytes
  const size_t ct_len                     // can be >= 0
)
{
  const size_t u32_cnt = ct_len >> 2; // 32 -bit chunk count
  const size_t u08_cnt = ct_len % 4;  // remaining 8 -bit chunk count

  // line 1 of step 1; compute decrypted bits
  //
  // also see step 3 of algorithm defined in section 1.3.5
  for (size_t i = 0; i < u32_cnt; i++) {
    const uint32_t enc = from_be_bytes(cipher + (i << 2));
    uint32_t dec = 0; // recover 32 plain text bits

    state_update_128(state, enc, &dec, MAX_U32, MIN_U32);
    to_be_bytes(dec, text + (i << 2));
  }

  for (size_t i = 0; i < u08_cnt; i++) {
    state_update_128(state,
                     cipher[(u32_cnt << 2) + i],
                     text + (u32_cnt << 2) + i,
                     MAX_U8,
                     MIN_U8);
  }

  // line 2 of step 1; append single `1` -bit
  state_update_128(state, 1u, MAX_U32, MIN_U32);

  // line 3 of step 1; append 255 `0` -bits
  for (size_t i = 0; i < 4; i++) {
    state_update_128(state, 0u, MAX_U32, MIN_U32);
  }

  for (size_t i = 4; i < 8; i++) {
    state_update_128(state, 0u, MIN_U32, MIN_U32);
  }
}

// Finalize Acorn-128, which generates 128 -bit authentication tag; this is
// result of authenticated encryption process & it also helps in conducting
// verified decryption
//
// See algorithm defined in section 1.3.6 of Acorn specification
// https://competitions.cr.yp.to/round3/acornv3.pdf
static inline void
finalize(uint64_t* const __restrict state, uint8_t* const __restrict tag)
{
  for (size_t i = 0; i < 20; i++) {
    state_update_128(state, 0u, MAX_U32, MAX_U32);
  }

  // take last 128 keystream bits & interpret it as authentication tag
  for (size_t i = 0; i < 4; i++) {
    const uint32_t ks = state_update_128(state, 0u, MAX_U32, MAX_U32);
    to_be_bytes(ks, tag + (i << 2));
  }
}

}
