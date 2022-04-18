#include "acorn_fpga.hpp"
#include <cassert>
#include <iostream>

#if !(defined FPGA_EMU || defined FPGA_HW)
#define FPGA_EMU
#endif

// When targeting FPGA emulator, compile it with
//
// dpcpp -std=c++20 -fintelfpga -DFPGA_EMU -I ./include
// example/acorn128_fpga.cpp -o acorn128_fpga_emu.out
//
// Before targeting FPGA h/w synthesis, read
// https://github.com/itzmeanjan/acorn/blob/2c19769/Makefile
// for instructions
int
main()
{
#if defined FPGA_EMU
  sycl::ext::intel::fpga_emulator_selector s{};
#elif defined FPGA_HW
  sycl::ext::intel::fpga_selector s{};
#endif

  sycl::device d{ s };
  sycl::context c{ d };
  sycl::queue q{ c, d };

  // how many independent instances of Acorn-128 encrypt/ decrypt to be executed
  // on device kernel, in iterative fashion
  constexpr size_t invk_cnt = 1024ul;
  // each plain text/ encrypted byteslice is 32 -bytes
  constexpr size_t ct_len = invk_cnt << 5;
  // each associated data byteslice is 16 -bytes
  constexpr size_t d_len = invk_cnt << 4;
  // each secret key/ nonce/ authentication tag is 128 -bit
  constexpr size_t knt_len = invk_cnt << 4;
  // each verification status is boolean
  constexpr size_t f_len = invk_cnt * sizeof(bool);

  // allocate SYCL runtime managed USM, which can easily transfer data bytes
  // back and forth between host & accelerator
  uint8_t* txt = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  uint8_t* enc = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  uint8_t* dec = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  uint8_t* data = static_cast<uint8_t*>(sycl::malloc_shared(d_len, q));
  uint8_t* key = static_cast<uint8_t*>(sycl::malloc_shared(knt_len, q));
  uint8_t* nonce = static_cast<uint8_t*>(sycl::malloc_shared(knt_len, q));
  uint8_t* tag = static_cast<uint8_t*>(sycl::malloc_shared(knt_len, q));
  bool* flag = static_cast<bool*>(sycl::malloc_shared(f_len, q));

  // prepare plain text ( deterministic )
  for (size_t i = 0; i < ct_len; i++) {
    txt[i] = static_cast<uint8_t>(i);
  }

  // prepare associated data ( deterministic )
  for (size_t i = 0; i < d_len; i++) {
    data[i] = static_cast<uint8_t>(i);
  }

  // prepare secret key & nonce ( deterministic )
  for (size_t i = 0; i < knt_len; i++) {
    key[i] = static_cast<uint8_t>(i);
    nonce[i] = static_cast<uint8_t>((~i));
  }

  // clear memory for encrypted text
  sycl::event evt0 = q.memset(enc, 0, ct_len);
  // clear memory for decrypted text
  sycl::event evt1 = q.memset(dec, 0, ct_len);
  // clear memory for authentication tag
  sycl::event evt2 = q.memset(tag, 0, knt_len);
  // clear memory for verification flag
  sycl::event evt3 = q.memset(flag, 0, f_len);

  // encrypt N -many independent, non-overlapping plain text
  // byteslices using Acorn-128 AEAD, on FPGA emulator or h/w
  sycl::event evt4 = acorn_fpga::encrypt(q,
                                         key,
                                         knt_len,
                                         nonce,
                                         knt_len,
                                         txt,
                                         ct_len,
                                         data,
                                         d_len,
                                         enc,
                                         ct_len,
                                         tag,
                                         knt_len,
                                         invk_cnt,
                                         { evt0, evt2 });
  // decrypt N -many independent, non-overlapping encrypted
  // byteslices using Acorn-128 AEAD, on FPGA emulator or h/w
  sycl::event evt5 = acorn_fpga::decrypt(q,
                                         key,
                                         knt_len,
                                         nonce,
                                         knt_len,
                                         tag,
                                         knt_len,
                                         enc,
                                         ct_len,
                                         data,
                                         d_len,
                                         dec,
                                         ct_len,
                                         flag,
                                         f_len,
                                         invk_cnt,
                                         { evt1, evt3, evt4 });

  // host synchronization i.e. wait until offloaded computation finishes !
  evt5.wait();

  // ensure that verified decryption of all byteslices worked as expected
  for (size_t i = 0; i < invk_cnt; i++) {
    assert(flag[i]);
  }
  // do byte-by-byte comparison to be sure that plain text bytes are same as
  // decrypted bytes
  for (size_t i = 0; i < ct_len; i++) {
    assert(txt[i] == dec[i]);
  }

#if defined FPGA_EMU
  std::cout << "Acorn-128 authenticated encryption/ verified decryption, on "
               "FPGA emulator, working as expected !"
            << std::endl;
#elif defined FPGA_HW
  std::cout << "Acorn-128 authenticated encryption/ verified decryption, on "
               "FPGA h/w, working as expected !"
            << std::endl;
#endif

  // deallocate all SYCL runtime managed memory resources
  sycl::free(txt, q);
  sycl::free(enc, q);
  sycl::free(dec, q);
  sycl::free(data, q);
  sycl::free(key, q);
  sycl::free(nonce, q);
  sycl::free(tag, q);

  return EXIT_SUCCESS;
}
