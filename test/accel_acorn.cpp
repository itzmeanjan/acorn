#include "test_accel_acorn.hpp"
#include <iostream>

int
main()
{
  // total work items to be dispatched during each testing round
  constexpr size_t wi_cnt = 1ul << 10;
  // # -of work-items to be grouped together
  constexpr size_t wg_size = 32ul;
  // associated data byte length for each work-item
  constexpr size_t dt_len = 32ul;
  // plain text byte length for each work-item
  constexpr size_t ct_len = 32ul;

  sycl::default_selector s{};
  sycl::device d{ s };
  sycl::context c{ d };
  sycl::queue q{ c, d };

  std::cout << "running on " << d.get_info<sycl::info::device::name>()
            << std::endl
            << std::endl;

  for (size_t i = 0; i < ct_len; i++) {
    for (size_t j = 0; j < dt_len; j++) {
      test_accel_acorn::encrypt_decrypt(q, i, j, wi_cnt, wg_size);
    }
  }

  std::cout << "[test] passed accelerated Acorn-128 encrypt/ decrypt !"
            << std::endl;

  return EXIT_SUCCESS;
}
