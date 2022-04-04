#include <cstdint>
#include <iomanip>
#include <random>
#include <sstream>

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

// Converts byte array of length `len` to readable hex string; copied from
// https://github.com/itzmeanjan/ascon/blob/9cf905d/include/utils.hpp#L323-L334
static inline const std::string
to_hex(const uint8_t* const bytes, const size_t len)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < len; i++) {
    ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(bytes[i]);
  }

  return ss.str();
}
