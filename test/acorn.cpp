#include "test_acorn.hpp"
#include <iostream>

int
main()
{
  constexpr size_t d_len = 64ul;  // associated data byte length
  constexpr size_t ct_len = 64ul; // plain text byte length

  // test Acorn-128 cipher suite for various combinations of associated data &
  // plain text bytes !
  for (size_t i = 0; i < d_len; i++) {
    for (size_t j = 0; j < ct_len; j++) {
      test_acorn::encrypt_decrypt_success(i, j);

      // simulate failure in verified decryption by mutating associated data
      test_acorn::encrypt_decrypt_failure(i, j, test_acorn::associated_data);
      // simulate failure in verified decryption by mutating encrypted data
      test_acorn::encrypt_decrypt_failure(i, j, test_acorn::encrypted_data);
      // simulate failure in verified decryption by mutating authentication tag
      test_acorn::encrypt_decrypt_failure(i, j, test_acorn::authentication_tag);
      // simulate failure in verified decryption by mutating message nonce
      test_acorn::encrypt_decrypt_failure(i, j, test_acorn::nonce);
      // simulate failure in verified decryption by mutating secret key
      test_acorn::encrypt_decrypt_failure(i, j, test_acorn::secret_key);
    }
  }

  std::cout << "[test] passed Acorn-128 encrypt/ decrypt !" << std::endl;

  return EXIT_SUCCESS;
}
