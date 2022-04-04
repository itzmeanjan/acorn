#include <cstdint>
#include <random>

// Generate `d_len` -many random 8 -bit unsigned integers
static inline void
random_data(uint8_t* const data, const size_t d_len)
{
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint8_t> dis;

  for (size_t i = 0; i < d_len; i++) {
    data[i] = dis(gen);
  }
}
