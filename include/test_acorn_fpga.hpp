#pragma once
#include "acorn_fpga.hpp"
#include "utils.hpp"

// Tests Acorn-128 AEAD implementation, targeting FPGA using SYCL/ DPC++
namespace test_acorn_fpga {

// Test (authenticated) encrypt -> (verified) decrypt flow while offloading
// computation to ( emulated or h/w ) FPGA using SYCL/ DPC++
static inline void
encrypt_decrypt(sycl::queue& q,               // SYCL job submission queue
                const size_t per_invk_ct_len, // bytes
                const size_t per_invk_dt_len, // bytes
                const size_t invk_cnt         // to be invoked these many times
)
{
  const size_t ct_len = invk_cnt * per_invk_ct_len; // alloc memory of bytes
  const size_t dt_len = invk_cnt * per_invk_dt_len; // alloc memory of bytes
  const size_t knt_len = invk_cnt << 4;             // alloc memory of bytes
  const size_t flg_len = invk_cnt * sizeof(bool);   // alloc memory of bytes

  // plain text on host
  uint8_t* txt_h = static_cast<uint8_t*>(std::malloc(ct_len));
  // encrypted text on host
  uint8_t* enc_h = static_cast<uint8_t*>(std::malloc(ct_len));
  // decrypted text on host
  uint8_t* dec_h = static_cast<uint8_t*>(std::malloc(ct_len));
  // associated data on host
  uint8_t* data_h = static_cast<uint8_t*>(std::malloc(dt_len));
  // secret keys on host
  uint8_t* keys_h = static_cast<uint8_t*>(std::malloc(knt_len));
  // public message nonces on host
  uint8_t* nonces_h = static_cast<uint8_t*>(std::malloc(knt_len));
  // authentication tags on host
  uint8_t* tags_h = static_cast<uint8_t*>(std::malloc(knt_len));
  // boolean verification flags on host
  bool* flags_h = static_cast<bool*>(std::malloc(flg_len));

  // plain text on accelerator
  uint8_t* txt_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
  // encrypted text on accelerator
  uint8_t* enc_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
  // decrypted text on accelerator
  uint8_t* dec_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
  // associated data on accelerator
  uint8_t* data_d = static_cast<uint8_t*>(sycl::malloc_device(dt_len, q));
  // secret keys on accelerator
  uint8_t* keys_d = static_cast<uint8_t*>(sycl::malloc_device(knt_len, q));
  // public message nonces on accelerator
  uint8_t* nonces_d = static_cast<uint8_t*>(sycl::malloc_device(knt_len, q));
  // authentication tags on accelerator
  uint8_t* tags_d = static_cast<uint8_t*>(sycl::malloc_device(knt_len, q));
  // boolean verification flags on accelerator
  bool* flags_d = static_cast<bool*>(sycl::malloc_device(flg_len, q));

  // prepare random plain text on host
  random_data(txt_h, ct_len);
  // prepare random associated data on host
  random_data(data_h, dt_len);
  // prepare random secret keys on host
  random_data(keys_h, knt_len);
  // prepare random public message nonces on host
  random_data(nonces_h, knt_len);

  // zero out to-be-transferred host memory allocations
  memset(enc_h, 0, ct_len);
  memset(dec_h, 0, ct_len);
  memset(tags_h, 0, knt_len);
  memset(flags_h, 0, flg_len);

  // transfer prepared ( on host ) random input bytes to accelerator
  sycl::event evt0 = q.memcpy(txt_d, txt_h, ct_len);
  sycl::event evt1 = q.memcpy(data_d, data_h, dt_len);
  sycl::event evt2 = q.memcpy(keys_d, keys_h, knt_len);
  sycl::event evt3 = q.memcpy(nonces_d, nonces_h, knt_len);

  // zero out to-be-computed accelerator memory allocations
  sycl::event evt4 = q.memset(enc_d, 0, ct_len);
  sycl::event evt5 = q.memset(dec_d, 0, ct_len);
  sycl::event evt6 = q.memset(tags_d, 0, knt_len);
  sycl::event evt7 = q.memset(flags_d, 0, flg_len);

  std::vector<sycl::event> evts0{ evt0, evt1, evt2, evt3, evt4, evt6 };

  // Acorn-128 authenticated encryption on accelerator
  sycl::event evt8 = acorn_fpga::encrypt(q,
                                         keys_d,
                                         knt_len,
                                         nonces_d,
                                         knt_len,
                                         txt_d,
                                         ct_len,
                                         data_d,
                                         dt_len,
                                         enc_d,
                                         ct_len,
                                         tags_d,
                                         knt_len,
                                         invk_cnt,
                                         evts0);

  // Acorn-128 verified decryption on accelerator
  sycl::event evt9 = acorn_fpga::decrypt(q,
                                         keys_d,
                                         knt_len,
                                         nonces_d,
                                         knt_len,
                                         tags_d,
                                         knt_len,
                                         enc_d,
                                         ct_len,
                                         data_d,
                                         dt_len,
                                         dec_d,
                                         ct_len,
                                         flags_d,
                                         flg_len,
                                         invk_cnt,
                                         { evt5, evt7, evt8 });

  // transfer deciphered text back to host
  sycl::event evt10 = q.submit([&](sycl::handler& h) {
    h.depends_on(evt9);
    h.memcpy(dec_h, dec_d, ct_len);
  });

  // transfer verification flags back to host
  sycl::event evt11 = q.submit([&](sycl::handler& h) {
    h.depends_on(evt10);
    h.memcpy(flags_h, flags_d, flg_len);
  });

  // transfer encrypted data bytes back to host
  sycl::event evt12 = q.submit([&](sycl::handler& h) {
    h.depends_on(evt8);
    h.memcpy(enc_h, enc_d, ct_len);
  });

  // transfer authentication tags back to host
  sycl::event evt13 = q.submit([&](sycl::handler& h) {
    h.depends_on(evt8);
    h.memcpy(tags_h, tags_d, knt_len);
  });

  std::vector<sycl::event> evts1{ evt10, evt11, evt12, evt13 };
  sycl::event evt14 = q.ext_oneapi_submit_barrier(evts1);

  // host synchronization i.e. blocking call !
  evt14.wait();

  // test on host that everything worked as expected !
  for (size_t i = 0; i < invk_cnt; i++) {
    assert(flags_h[i]);

    const size_t ct_off = i * per_invk_ct_len;
    for (size_t j = 0; j < per_invk_ct_len; j++) {
      assert(txt_h[ct_off + j] == dec_h[ct_off + j]);
    }
  }

  // deallocate host memory resources
  std::free(txt_h);
  std::free(enc_h);
  std::free(dec_h);
  std::free(data_h);
  std::free(keys_h);
  std::free(nonces_h);
  std::free(tags_h);
  std::free(flags_h);

  // deallocate SYCL runtime managed accelerator memory resources
  sycl::free(txt_d, q);
  sycl::free(enc_d, q);
  sycl::free(dec_d, q);
  sycl::free(data_d, q);
  sycl::free(keys_d, q);
  sycl::free(nonces_d, q);
  sycl::free(tags_d, q);
  sycl::free(flags_d, q);
}

}
