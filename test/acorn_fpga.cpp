#include "test_acorn_fpga.hpp"
#include <iostream>

#if !(defined FPGA_EMU || defined FPGA_HW)
#define FPGA_EMU
#endif

int
main()
{
  // these many independent, non-overlapping input byte sequences to be
  // encrypted/ decrypted
  constexpr size_t invk_cnt = 1ul << 10;
  constexpr size_t dt_len = 64ul; // associated data byte length
  constexpr size_t ct_len = 64ul; // plain text byte length

#if defined FPGA_EMU
  sycl::ext::intel::fpga_emulator_selector s{};
#elif defined FPGA_HW
  sycl::ext::intel::fpga_selector s{};
#endif

  sycl::device d{ s };
  sycl::context c{ d };
  sycl::queue q{ c, d };

  std::cout << "running on " << d.get_info<sycl::info::device::name>()
            << std::endl
            << std::endl;

  test_acorn_fpga::encrypt_decrypt(q, ct_len, dt_len, invk_cnt);

#if defined FPGA_EMU
  std::cout << "[test] passed Acorn-128 encrypt/ decrypt on emulated FPGA !"
            << std::endl;
#elif defined FPGA_HW
  std::cout << "[test] passed Acorn-128 encrypt/ decrypt on FPGA !"
            << std::endl;
#endif

  return EXIT_SUCCESS;
}
