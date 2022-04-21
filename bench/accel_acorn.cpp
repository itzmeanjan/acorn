#include "bench_utils.hpp"
#include "table.hpp"
#include <iostream>

int
main()
{
  // associated data byte length, same for all cases
  constexpr size_t dt_len = 32ul;
  // min # -of work-items to be dispatched
  constexpr size_t min_wi_cnt = 1ul << 16;
  // max # -of work-items to be dispatched
  constexpr size_t max_wi_cnt = 1ul << 18;
  // # -of work-items to be grouped during execution
  //
  // @note, consider taking better decision about appropriate work-group size
  // for certain kernel at runtime based on SYCL runtime heuristics
  constexpr size_t wg_size = 32ul;
  constexpr size_t min_ct_len = 64ul;   // bytes
  constexpr size_t max_ct_len = 4096ul; // bytes

#if defined SYCL_TARGET_CPU
  sycl::cpu_selector s{};
#pragma message("Selecting default CPU accelerator !")
#elif defined SYCL_TARGET_GPU
  sycl::gpu_selector s{};
#pragma message("Selecting default GPU accelerator !")
#else
  sycl::default_selector s{};
#pragma message("Selecting default SYCL accelerator !")
#endif

  sycl::device d{ s };
  sycl::context c{ d };
  sycl::queue q{ c, d, sycl::property::queue::enable_profiling{} };

  std::cout << "running on " << d.get_info<sycl::info::device::name>()
            << std::endl
            << std::endl;

  uint64_t* ts = static_cast<uint64_t*>(std::malloc(sizeof(uint64_t) * 3));
  size_t* io = static_cast<size_t*>(std::malloc(sizeof(size_t) * 3));

  std::cout << "Benchmarking Acorn-128 encrypt" << std::endl << std::endl;

  TextTable t0('-', '|', '+');

  t0.add("invocation count");
  t0.add("plain text len ( bytes )");
  t0.add("associated data len ( bytes )");
  t0.add("host-to-device b/w");
  t0.add("kernel b/w");
  t0.add("device-to-host b/w");
  t0.endOfRow();

  for (size_t invk = min_wi_cnt; invk <= max_wi_cnt; invk <<= 1) {
    for (size_t ct_len = min_ct_len; ct_len <= max_ct_len; ct_len <<= 1) {
      bench_acorn::exec_kernel(q,
                               ct_len,
                               dt_len,
                               invk,
                               wg_size,
                               bench_acorn::acorn_type::accel_acorn_encrypt,
                               ts,
                               io);

      t0.add(std::to_string(invk));
      t0.add(std::to_string(ct_len));
      t0.add(std::to_string(dt_len));
      t0.add(bench_acorn::to_readable_bandwidth(io[0], ts[0]));
      t0.add(bench_acorn::to_readable_bandwidth(io[1], ts[1]));
      t0.add(bench_acorn::to_readable_bandwidth(io[2], ts[2]));
      t0.endOfRow();
    }
  }

  t0.setAlignment(1, TextTable::Alignment::RIGHT);
  t0.setAlignment(2, TextTable::Alignment::RIGHT);
  t0.setAlignment(3, TextTable::Alignment::RIGHT);
  t0.setAlignment(4, TextTable::Alignment::RIGHT);
  t0.setAlignment(5, TextTable::Alignment::RIGHT);
  std::cout << t0;

  std::cout << std::endl
            << "Benchmarking Acorn-128 decrypt" << std::endl
            << std::endl;

  TextTable t1('-', '|', '+');

  t1.add("invocation count");
  t1.add("cipher text len ( bytes )");
  t1.add("associated data len ( bytes )");
  t1.add("host-to-device b/w");
  t1.add("kernel b/w");
  t1.add("device-to-host b/w");
  t1.endOfRow();

  for (size_t invk = min_wi_cnt; invk <= max_wi_cnt; invk <<= 1) {
    for (size_t ct_len = min_ct_len; ct_len <= max_ct_len; ct_len <<= 1) {
      bench_acorn::exec_kernel(q,
                               ct_len,
                               dt_len,
                               invk,
                               wg_size,
                               bench_acorn::acorn_type::accel_acorn_decrypt,
                               ts,
                               io);

      t1.add(std::to_string(invk));
      t1.add(std::to_string(ct_len));
      t1.add(std::to_string(dt_len));
      t1.add(bench_acorn::to_readable_bandwidth(io[0], ts[0]));
      t1.add(bench_acorn::to_readable_bandwidth(io[1], ts[1]));
      t1.add(bench_acorn::to_readable_bandwidth(io[2], ts[2]));
      t1.endOfRow();
    }
  }

  t1.setAlignment(1, TextTable::Alignment::RIGHT);
  t1.setAlignment(2, TextTable::Alignment::RIGHT);
  t1.setAlignment(3, TextTable::Alignment::RIGHT);
  t1.setAlignment(4, TextTable::Alignment::RIGHT);
  t1.setAlignment(5, TextTable::Alignment::RIGHT);
  std::cout << t1;

  std::free(ts);
  std::free(io);

  return EXIT_SUCCESS;
}
