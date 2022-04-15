#include "acorn.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>
#include <string.h>

#define KNT_LEN 16u // secret key/ nonce/ tag length in bytes

// Benchmark Acorn-128 authenticated encryption routine
static void
acorn_encrypt(benchmark::State& state,
              const size_t ct_len,
              const size_t data_len)
{
  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(data_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  random_data(text, ct_len);
  // random associated data bytes
  random_data(data, data_len);
  // random secret key ( = 128 -bit )
  random_data(key, KNT_LEN);
  // random public message nonce ( = 128 -bit )
  random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  size_t itr = 0;
  for (auto _ : state) {
    acorn::encrypt(key, nonce, text, ct_len, data, data_len, enc, tag);

    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
    benchmark::DoNotOptimize(itr++);
  }

  state.SetBytesProcessed(static_cast<int64_t>((data_len + ct_len) * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

  // deallocate all resources
  free(text);
  free(enc);
  free(data);
  free(key);
  free(nonce);
  free(tag);
}

// Benchmark Acorn-128 verified decryption routine
static void
acorn_decrypt(benchmark::State& state,
              const size_t ct_len,
              const size_t data_len)
{
  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(data_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  random_data(text, ct_len);
  // random associated data bytes
  random_data(data, data_len);
  // random secret key ( = 128 -bit )
  random_data(key, KNT_LEN);
  // random public message nonce ( = 128 -bit )
  random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(dec, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  // compute encrypted text & authentication tag
  acorn::encrypt(key, nonce, text, ct_len, data, data_len, enc, tag);

  size_t itr = 0;
  for (auto _ : state) {
    using namespace benchmark;
    using namespace acorn;

    DoNotOptimize(decrypt(key, nonce, tag, enc, ct_len, data, data_len, dec));
    DoNotOptimize(dec);
    DoNotOptimize(itr++);
  }

  state.SetBytesProcessed(static_cast<int64_t>((data_len + ct_len) * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

  // deallocate all resources
  free(text);
  free(enc);
  free(dec);
  free(data);
  free(key);
  free(nonce);
  free(tag);
}

// Benchmark Acorn-128 encrypt routine with 64 -bytes plain text & 32 -bytes
// associated data
static void
acorn_encrypt_64B_32B(benchmark::State& state)
{
  acorn_encrypt(state, 64ul, 32ul);
}

// Benchmark Acorn-128 encrypt routine with 128 -bytes plain text & 32 -bytes
// associated data
static void
acorn_encrypt_128B_32B(benchmark::State& state)
{
  acorn_encrypt(state, 128ul, 32ul);
}

// Benchmark Acorn-128 encrypt routine with 256 -bytes plain text & 32 -bytes
// associated data
static void
acorn_encrypt_256B_32B(benchmark::State& state)
{
  acorn_encrypt(state, 256ul, 32ul);
}

// Benchmark Acorn-128 encrypt routine with 512 -bytes plain text & 32 -bytes
// associated data
static void
acorn_encrypt_512B_32B(benchmark::State& state)
{
  acorn_encrypt(state, 512ul, 32ul);
}

// Benchmark Acorn-128 encrypt routine with 1024 -bytes plain text & 32 -bytes
// associated data
static void
acorn_encrypt_1024B_32B(benchmark::State& state)
{
  acorn_encrypt(state, 1024ul, 32ul);
}

// Benchmark Acorn-128 encrypt routine with 2048 -bytes plain text & 32 -bytes
// associated data
static void
acorn_encrypt_2048B_32B(benchmark::State& state)
{
  acorn_encrypt(state, 2048ul, 32ul);
}

// Benchmark Acorn-128 encrypt routine with 4096 -bytes plain text & 32 -bytes
// associated data
static void
acorn_encrypt_4096B_32B(benchmark::State& state)
{
  acorn_encrypt(state, 4096ul, 32ul);
}

// Benchmark Acorn-128 decrypt routine with 64 -bytes cipher text & 32 -bytes
// associated data
static void
acorn_decrypt_64B_32B(benchmark::State& state)
{
  acorn_decrypt(state, 64ul, 32ul);
}

// Benchmark Acorn-128 decrypt routine with 128 -bytes cipher text & 32 -bytes
// associated data
static void
acorn_decrypt_128B_32B(benchmark::State& state)
{
  acorn_decrypt(state, 128ul, 32ul);
}

// Benchmark Acorn-128 decrypt routine with 256 -bytes cipher text & 32 -bytes
// associated data
static void
acorn_decrypt_256B_32B(benchmark::State& state)
{
  acorn_decrypt(state, 256ul, 32ul);
}

// Benchmark Acorn-128 decrypt routine with 512 -bytes cipher text & 32 -bytes
// associated data
static void
acorn_decrypt_512B_32B(benchmark::State& state)
{
  acorn_decrypt(state, 512ul, 32ul);
}

// Benchmark Acorn-128 decrypt routine with 1024 -bytes cipher text & 32 -bytes
// associated data
static void
acorn_decrypt_1024B_32B(benchmark::State& state)
{
  acorn_decrypt(state, 1024ul, 32ul);
}

// Benchmark Acorn-128 decrypt routine with 2048 -bytes cipher text & 32 -bytes
// associated data
static void
acorn_decrypt_2048B_32B(benchmark::State& state)
{
  acorn_decrypt(state, 2048ul, 32ul);
}

// Benchmark Acorn-128 decrypt routine with 4096 -bytes cipher text & 32 -bytes
// associated data
static void
acorn_decrypt_4096B_32B(benchmark::State& state)
{
  acorn_decrypt(state, 4096ul, 32ul);
}

// register for benchmarking
//
// Note, associated data size is kept constant for all benchmaark cases !
BENCHMARK(acorn_encrypt_64B_32B);
BENCHMARK(acorn_encrypt_128B_32B);
BENCHMARK(acorn_encrypt_256B_32B);
BENCHMARK(acorn_encrypt_512B_32B);
BENCHMARK(acorn_encrypt_1024B_32B);
BENCHMARK(acorn_encrypt_2048B_32B);
BENCHMARK(acorn_encrypt_4096B_32B);

BENCHMARK(acorn_decrypt_64B_32B);
BENCHMARK(acorn_decrypt_128B_32B);
BENCHMARK(acorn_decrypt_256B_32B);
BENCHMARK(acorn_decrypt_512B_32B);
BENCHMARK(acorn_decrypt_1024B_32B);
BENCHMARK(acorn_decrypt_2048B_32B);
BENCHMARK(acorn_decrypt_4096B_32B);

// main function to make it executable
BENCHMARK_MAIN();
