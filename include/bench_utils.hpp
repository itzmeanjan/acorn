#pragma once
#include "acorn_fpga.hpp"
#include "utils.hpp"

#define GB 1073741824. // 1 << 30 bytes
#define MB 1048576.    // 1 << 20 bytes
#define KB 1024.       // 1 << 10 bytes

// Benchmark Acorn-128 AEAD implementation, targeting FPGA using SYCL/ DPC++
namespace bench_acorn_fpga {

// Which one to benchmark
//
// 0) Acorn-128 single work-item encrypt routine on FPGA
// 1) Acorn-128 single work-item decrypt routine on FPGA
enum acorn_type
{
  acorn_encrypt,
  acorn_decrypt,
};

// Time execution of SYCL command, whose submission resulted into given SYCL
// event, in nanosecond level granularity
//
// Ensure SYCL queue, onto which command was submitted, has profiling enabled !
static inline uint64_t
time_event(sycl::event& evt)
{
  // type aliasing because I wanted to keep them all single line
  using u64 = sycl::cl_ulong;
  using prof_t = sycl::info::event_profiling;

  const prof_t BEG = prof_t::command_start;
  const prof_t END = prof_t::command_end;

  const u64 beg = evt.get_profiling_info<BEG>();
  const u64 end = evt.get_profiling_info<END>();

  return static_cast<uint64_t>(end - beg);
}

// Convert how many bytes processed in how long timespan ( given in nanosecond
// level granularity ) to more human digestable
// format ( i.e. GB/ s or MB/ s or KB/ s or B/ s )
static inline const std::string
to_readable_bandwidth(const size_t bytes, // bytes
                      const uint64_t ts   // nanoseconds
)
{
  const double bytes_ = static_cast<double>(bytes);
  const double ts_ = static_cast<double>(ts) * 1e-9; // seconds
  const double bps = bytes_ / ts_;                   // bytes/ sec

  return bps >= GB
           ? (std::to_string(bps / GB) + " GB/ s")
           : bps >= MB ? (std::to_string(bps / MB) + " MB/ s")
                       : bps >= KB ? (std::to_string(bps / KB) + " KB/ s")
                                   : (std::to_string(bps) + " B/ s");
}

// Executes accelerated Acorn-128 encrypt/ decrypt kernels ( chosen using
// `type` parameter ) on FPGA, on `invk_cnt` -many ( read single work-item SYCL
// FPGA kernel is iterated those many times ) independent input byte slices (
// plain text/ cipher text/ associated data ), while returning how much time
// spent on following
//
// - host -> device input tx time ( total )
// - kernel execution time
// - device -> host input tx time ( total )
//
// along with how many bytes of data were processed during aforementioned
// activities
//
// - bytes of data transferred from host -> device
// - bytes of data consumed during encryption/ decryption
// - bytes of data transferred from device -> host
static inline void
exec_kernel(sycl::queue& q,                // SYCL job submission queue
            const size_t per_invk_ct_len,  // bytes
            const size_t per_invk_dt_len,  // bytes
            const size_t invk_cnt,         // to be invoked these many times
            acorn_type type,               // which Acorn routine to benchmark
            uint64_t* const __restrict ts, // time spent on activities
            size_t* const __restrict io    // processed bytes during activities
)
{
  // SYCL queue must have profiling enabled !
  assert(q.has_property<sycl::property::queue::enable_profiling>());

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
    h.depends_on(evt9);
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

  if (type == acorn_encrypt) {
    const uint64_t t0 = time_event(evt0) + time_event(evt1);
    const uint64_t t1 = time_event(evt2) + time_event(evt3);

    ts[0] = t0 + t1;
    ts[1] = time_event(evt8);
    ts[2] = time_event(evt12) + time_event(evt13);

    io[0] = ct_len + dt_len + 2 * knt_len;
    io[1] = ct_len + dt_len;
    io[2] = ct_len + knt_len;
  } else if (type == acorn_decrypt) {
    const uint64_t t0 = time_event(evt0) + time_event(evt1);
    const uint64_t t1 = time_event(evt2) + time_event(evt3) * 2;

    ts[0] = t0 + t1;
    ts[1] = time_event(evt9);
    ts[2] = time_event(evt10) + time_event(evt11);

    io[0] = ct_len + dt_len + 3 * knt_len;
    io[1] = ct_len + dt_len;
    io[2] = ct_len + flg_len;
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
