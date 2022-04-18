#pragma once
#include "acorn.hpp"
#include <CL/sycl.hpp>
#include <sycl/ext/intel/fpga_extensions.hpp>

// Acorn-128: A lightweight authenticated cipher ( read Authenticated Encryption
// with Associated Data ) targeting FPGA using SYCL/ DPC++
namespace acorn_fpga {

// To avoid kernel name mangling in FPGA optimization report
class kernelAcorn128Encrypt;
class kernelAcorn128Decrypt;

// Acorn-128 authenticated encryption on FPGA
//
// When N -many equal length plain text byte slices along with N -many equal
// length associated data byte slices need to be encrypted using Acorn-128, this
// routine can be used for offloading computation to FPGA. This routine invokes
// `acorn::encrypt` N -many times in a deeply pipelined loop ( iterative
// fashion, because computation is offloaded as SYCL single_task ) & stores
// computed encrypted byte slices & authentication tags ( each 128 -bit ) in
// respective memory offsets.
//
// Input:
//
// - N -many secret key ( same/ different ), each 128 -bit
// - N -many public message nonce ( same/ different ), each 128 -bit
// - N -many plain text byte slices, each of length T -bytes
// - N -many associated data byte slices, each of length D -bytes
//
// Note, avoid nonce reuse i.e. don't use same nonce twice with same secret key
//
// Output:
//
// - N -many encrypted text byte slices, each of length T -bytes
// - N -many authentication tags, each 128 -bit
// - SYCL event as result of job submission, can be used for constructing SYCL
// dependency graph
//
// Note, in function signature all data lengths are in terms of `bytes` !
static inline sycl::event
encrypt(
  sycl::queue& q,                        // SYCL job submission queue
  const uint8_t* const __restrict key,   // secret keys
  const size_t key_len,                  // = invk_cnt * 16
  const uint8_t* const __restrict nonce, // public nonces
  const size_t nonce_len,                // = invk_cnt * 16
  const uint8_t* const __restrict text,  // plain text
  const size_t text_len,                 // text_len % invk_cnt == 0
  const uint8_t* const __restrict data,  // associated data
  const size_t data_len,                 // data_len % invk_cnt == 0
  uint8_t* const __restrict enc,         // encrypted data bytes
  const size_t enc_len,                  // = text_len
  uint8_t* const __restrict tag,         // authentication tags
  const size_t tag_len,                  // = invk_cnt * 16
  const size_t invk_cnt,                 // to be invoked these many times
  const std::vector<sycl::event> evts    // forms SYCL runtime dependency graph
)
{
  assert(invk_cnt << 4 == key_len);
  assert(invk_cnt << 4 == nonce_len);
  assert(invk_cnt << 4 == tag_len);
  assert(text_len % invk_cnt == 0);
  assert(data_len % invk_cnt == 0);
  assert(text_len == enc_len);

  const size_t per_invk_ct_len = text_len / invk_cnt;
  const size_t per_invk_dt_len = data_len / invk_cnt;

  sycl::event evt = q.submit([&](sycl::handler& h) {
    h.depends_on(evts);
    h.single_task<kernelAcorn128Encrypt>([=]() [[intel::kernel_args_restrict]] {
      [[intel::ivdep]] for (size_t i = 0; i < invk_cnt; i++)
      {
        const size_t knt_off = i << 4;
        const size_t ct_off = i * per_invk_ct_len;
        const size_t add_off = i * per_invk_dt_len;

        acorn::encrypt(key + knt_off,
                       nonce + knt_off,
                       text + ct_off,
                       per_invk_ct_len,
                       data + add_off,
                       per_invk_dt_len,
                       enc + ct_off,
                       tag + knt_off);
      }
    });
  });
  return evt;
}

// Acorn-128 verified decryption on FPGA
//
// When N -many equal length encrypted text byte slices along with N -many equal
// length associated data byte slices ( associated data bytes aren't encrypted
// in first place, but even a single bit flip must result in authentication
// failure ) need to be decrypted using Acorn-128, this routine can be used for
// offloading computation to FPGA. This routine invokes `acorn::decrypt` N -many
// times in a deeply pipelined loop ( iterative fashion, as computation is
// offloaded as SYCL single_task ) & stores computed decrypted byte slices &
// verification flags ( each boolean value ) in respective memory offsets.
//
// Input:
//
// - N -many secret key ( same/ different ), each 128 -bit
// - N -many public message nonce ( same/ different ), each 128 -bit
// - N -many authentication tag ( same/ different ), each 128 -bit
// - N -many encrypted byte slices, each of length T -bytes
// - N -many associated data byte slices, each of length D -bytes
//
// Output:
//
// - N -many decrypted text byte slices, each of length T -bytes
// - N -many verification flags, each boolean value
// - SYCL event as result of job submission, can be used for constructing
// dependency graph
//
// After transferring output data back to host, first verification flags need to
// be tested for truth value, if it doesn't pass, something is off, as message
// authenticity can't be ensured !
//
// Note, in function signature all data lengths are in terms of `bytes` !
static inline sycl::event
decrypt(
  sycl::queue& q,                        // SYCL job submission queue
  const uint8_t* const __restrict key,   // secret keys
  const size_t key_len,                  // = invk_cnt * 16
  const uint8_t* const __restrict nonce, // public nonces
  const size_t nonce_len,                // = invk_cnt * 16
  const uint8_t* const __restrict tag,   // authentication tags
  const size_t tag_len,                  // = invk_cnt * 16
  const uint8_t* const __restrict enc,   // encrypted data bytes
  const size_t enc_len,                  // enc_en % invk_cnt == 0
  const uint8_t* const __restrict data,  // associated data
  const size_t data_len,                 // data_len % invk_cnt == 0
  uint8_t* const __restrict text,        // plain text bytes
  const size_t text_len,                 // = enc_len
  bool* const __restrict flag,           // verification flags
  const size_t flag_len,                 // invk_cnt * sizeof(bool)
  const size_t invk_cnt,                 // to be invoked these many times
  const std::vector<sycl::event> evts    // forms SYCL runtime dependency graph
)
{
  assert(invk_cnt << 4 == key_len);
  assert(invk_cnt << 4 == nonce_len);
  assert(invk_cnt << 4 == tag_len);
  assert(enc_len % invk_cnt == 0);
  assert(data_len % invk_cnt == 0);
  assert(enc_len == text_len);
  assert(invk_cnt * sizeof(bool) == flag_len);

  const size_t per_invk_ct_len = enc_len / invk_cnt;
  const size_t per_invk_dt_len = data_len / invk_cnt;
  const size_t per_invk_flg_len = sizeof(bool);

  sycl::event evt = q.submit([&](sycl::handler& h) {
    h.depends_on(evts);
    h.single_task<kernelAcorn128Decrypt>([=]() [[intel::kernel_args_restrict]] {
      [[intel::ivdep]] for (size_t i = 0; i < invk_cnt; i++)
      {
        const size_t knt_off = i << 4;
        const size_t ct_off = i * per_invk_ct_len;
        const size_t add_off = i * per_invk_dt_len;
        const size_t flg_off = i * per_invk_flg_len;

        const bool flg = acorn::decrypt(key + knt_off,
                                        nonce + knt_off,
                                        tag + knt_off,
                                        enc + ct_off,
                                        per_invk_ct_len,
                                        data + add_off,
                                        per_invk_dt_len,
                                        text + ct_off);

        flag[flg_off] = flg;
      }
    });
  });
  return evt;
}

}
