#include "bench_utils.hpp"
#include "table.hpp"
#include <iostream>

#if !(defined FPGA_EMU || defined FPGA_HW)
#define FPGA_EMU
#endif

int
main()
{
  constexpr size_t dt_len = 64ul; // associated data byte length
  constexpr size_t ct_len = 64ul; // plain text byte length
  constexpr size_t min_invk_cnt = 1ul << 16;
  constexpr size_t max_invk_cnt = 1ul << 20;

#if defined FPGA_EMU
  sycl::ext::intel::fpga_emulator_selector s{};
#elif defined FPGA_HW
  sycl::ext::intel::fpga_selector s{};
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
  t0.add("host-to-device b/w");
  t0.add("kernel b/w");
  t0.add("device-to-host b/w");
  t0.endOfRow();

  for (size_t invk = min_invk_cnt; invk <= max_invk_cnt; invk <<= 1) {
    bench_acorn_fpga::exec_kernel(q,
                                  ct_len,
                                  dt_len,
                                  invk,
                                  bench_acorn_fpga::acorn_type::acorn_encrypt,
                                  ts,
                                  io);

    t0.add(std::to_string(invk));
    t0.add(bench_acorn_fpga::to_readable_bandwidth(io[0], ts[0]));
    t0.add(bench_acorn_fpga::to_readable_bandwidth(io[1], ts[1]));
    t0.add(bench_acorn_fpga::to_readable_bandwidth(io[2], ts[2]));
    t0.endOfRow();
  }

  t0.setAlignment(1, TextTable::Alignment::RIGHT);
  t0.setAlignment(2, TextTable::Alignment::RIGHT);
  t0.setAlignment(3, TextTable::Alignment::RIGHT);
  std::cout << t0;

  std::cout << std::endl
            << "Benchmarking Acorn-128 decrypt" << std::endl
            << std::endl;

  TextTable t1('-', '|', '+');

  t1.add("invocation count");
  t1.add("host-to-device b/w");
  t1.add("kernel b/w");
  t1.add("device-to-host b/w");
  t1.endOfRow();

  for (size_t invk = min_invk_cnt; invk <= max_invk_cnt; invk <<= 1) {
    bench_acorn_fpga::exec_kernel(q,
                                  ct_len,
                                  dt_len,
                                  invk,
                                  bench_acorn_fpga::acorn_type::acorn_decrypt,
                                  ts,
                                  io);

    t1.add(std::to_string(invk));
    t1.add(bench_acorn_fpga::to_readable_bandwidth(io[0], ts[0]));
    t1.add(bench_acorn_fpga::to_readable_bandwidth(io[1], ts[1]));
    t1.add(bench_acorn_fpga::to_readable_bandwidth(io[2], ts[2]));
    t1.endOfRow();
  }

  t1.setAlignment(1, TextTable::Alignment::RIGHT);
  t1.setAlignment(2, TextTable::Alignment::RIGHT);
  t1.setAlignment(3, TextTable::Alignment::RIGHT);
  std::cout << t1;

  std::free(ts);
  std::free(io);

  return EXIT_SUCCESS;
}
