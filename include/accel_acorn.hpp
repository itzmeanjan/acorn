#pragma once
#include "acorn.hpp"
#include <CL/sycl.hpp>

// Accelerated Acorn-128: A lightweight AEAD ( authenticated encryption with
// associated data ) scheme, targeting accelerators ( i.e. multi-core CPUs,
// GPGPUs ) using SYCL
namespace accel_acorn {

class kernelAcorn128Encrypt;
class kernelAcorn128Decrypt;

// Encrypt N -many independent, non-overlapping, equal-length plain text
// byteslices along with N -many independent, non-overlapping, equal-length
// associated data byteslices on multi-core CPU/ GPGPU, using Acorn-128 AEAD
//
// Input:
//
// - N -many secret keys, each of 128 -bit
// - N -many public message nonces, each of 128 -bit
// - N -many plain text byteslices, each of same length
// - N -many associated data byteslices, each of same length
//
// Note, avoid nonce reuse i.e. under same secret key don't use same nonce twice
//
// Note, associated data bytes are never encrypted
//
// Output:
//
// - N -many encrypted text byteslices, each of same length
//
// assert enc_len == text_len
//
// - N -many authentication tags, each of 128 -bit
// - SYCL event, resulting from submission of compute job to SYCL queue
static inline sycl::event
encrypt(
  sycl::queue& q,                        // SYCL job submission queue
  const uint8_t* const __restrict key,   // secret keys
  const size_t key_len,                  // = wi_cnt * 16
  const uint8_t* const __restrict nonce, // public message nonces
  const size_t nonce_len,                // = wi_cnt * 16
  const uint8_t* const __restrict text,  // plain text
  const size_t text_len,                 // text_len % wi_cnt == 0
  const uint8_t* const __restrict data,  // associated data
  const size_t data_len,                 // data_len % wi_cnt == 0
  uint8_t* const __restrict enc,         // encrypted data bytes
  const size_t enc_len,                  // = text_len
  uint8_t* const __restrict tag,         // authentication tags
  const size_t tag_len,                  // = wi_cnt * 16
  const size_t wi_cnt,                   // # -of work items to be dispatched
  const size_t wg_size,                  // # -of work items to be grouped
  const std::vector<sycl::event> evts    // forms SYCL runtime dependency graph
)
{
  // all work groups to have same number of effective work-items
  assert(wi_cnt % wg_size == 0);
  // each secret key of 128 -bit
  assert(wi_cnt << 4 == key_len);
  // each public message nonce of 128 -bit
  assert(wi_cnt << 4 == nonce_len);
  // each authentication tag of 128 -bit
  assert(wi_cnt << 4 == tag_len);
  // independent, non-overlapping plain text byteslices
  assert(text_len % wi_cnt == 0);
  // independent, non-overlapping associated data byteslices
  assert(data_len % wi_cnt == 0);
  // encrypted bytes length must be same as plain text length
  assert(text_len == enc_len);

  // each work item to consume these many plain text bytes during encryption
  const size_t per_wi_ct_len = text_len / wi_cnt;
  // each work item to consume these many associated data bytes during
  // encryption, though note that associated data bytes are never encrypted !
  const size_t per_wi_ad_len = data_len / wi_cnt;

  sycl::event evt = q.submit([&](sycl::handler& h) {
    // SYCL dependency graph
    h.depends_on(evts);
    h.parallel_for<kernelAcorn128Encrypt>(
      sycl::nd_range<1>{ wi_cnt, wg_size }, [=](sycl::nd_item<1> it) {
        const size_t idx = it.get_global_linear_id();

        const size_t knt_off = idx << 4;
        const size_t ct_off = idx * per_wi_ct_len;
        const size_t ad_off = idx * per_wi_ad_len;

        acorn::encrypt(key + knt_off,
                       nonce + knt_off,
                       text + ct_off,
                       per_wi_ct_len,
                       data + ad_off,
                       per_wi_ad_len,
                       enc + ct_off,
                       tag + knt_off);
      });
  });
  return evt;
}

// Decrypt N -many independent, non-overlapping, equal-length cipher text
// byteslices along with N -many independent, non-overlapping, equal-length
// associated data byteslices on multi-core CPU/ GPGPU, using Acorn-128 AEAD
//
// Input:
//
// - N -many secret keys, each of 128 -bit
// - N -many public message nonces, each of 128 -bit
// - N -many authentication tags, each of 128 -bit
// - N -many cipher text byteslices, each of same length
// - N -many associated data byteslices, each of same length
//
// Note, associated data bytes are never encrypted
//
// Output:
//
// - N -many decrypted text byteslices, each of same length
//
// assert text_len == enc_len
//
// - N -many verification flags, each a boolean value
// - SYCL event, resulting from submission of compute job to SYCL queue
static inline sycl::event
decrypt(
  sycl::queue& q,                        // SYCL job submission queue
  const uint8_t* const __restrict key,   // secret keys
  const size_t key_len,                  // = wi_cnt * 16
  const uint8_t* const __restrict nonce, // public message nonces
  const size_t nonce_len,                // = wi_cnt * 16
  const uint8_t* const __restrict tag,   // authentication tags
  const size_t tag_len,                  // = wi_cnt * 16
  const uint8_t* const __restrict enc,   // encrypted data bytes
  const size_t enc_len,                  // enc_len % wi_cnt == 0
  const uint8_t* const __restrict data,  // associated data
  const size_t data_len,                 // data_len % wi_cnt == 0
  uint8_t* const __restrict text,        // plain text bytes
  const size_t text_len,                 // = enc_len
  bool* const __restrict flag,           // verification flags
  const size_t flag_len,                 // wi_cnt * sizeof(bool)
  const size_t wi_cnt,                   // # -of work items to be dispatched
  const size_t wg_size,                  // # -of work items to be grouped
  const std::vector<sycl::event> evts    // forms SYCL runtime dependency graph
)
{
  // all work groups to have same number of effective work-items
  assert(wi_cnt % wg_size == 0);
  // each secret key of 128 -bit
  assert(wi_cnt << 4 == key_len);
  // each public message nonce of 128 -bit
  assert(wi_cnt << 4 == nonce_len);
  // each authentication tag of 128 -bit
  assert(wi_cnt << 4 == tag_len);
  // independent, non-overlapping cipher text byteslices
  assert(enc_len % wi_cnt == 0);
  // independent, non-overlapping associated data byteslices
  assert(data_len % wi_cnt == 0);
  // decrypted bytes length must be same as cipher text length
  assert(enc_len == text_len);
  // each verification flag is of boolean type
  assert(wi_cnt * sizeof(bool) == flag_len);

  // each work item to consume these many cipher text bytes during decryption
  const size_t per_wi_ct_len = enc_len / wi_cnt;
  // each work item to consume these many associated data bytes during
  // decryption, though note that associated data bytes are never encrypted in
  // first place !
  const size_t per_wi_ad_len = data_len / wi_cnt;

  sycl::event evt = q.submit([&](sycl::handler& h) {
    // SYCL dependency graph
    h.depends_on(evts);
    h.parallel_for<kernelAcorn128Decrypt>(
      sycl::nd_range<1>{ wi_cnt, wg_size }, [=](sycl::nd_item<1> it) {
        const size_t idx = it.get_global_linear_id();

        const size_t knt_off = idx << 4;
        const size_t ct_off = idx * per_wi_ct_len;
        const size_t ad_off = idx * per_wi_ad_len;

        const bool flg = acorn::decrypt(key + knt_off,
                                        nonce + knt_off,
                                        tag + knt_off,
                                        enc + ct_off,
                                        per_wi_ct_len,
                                        data + ad_off,
                                        per_wi_ad_len,
                                        text + ct_off);

        flag[idx] = flg;
      });
  });
  return evt;
}

}
