#include "acorn.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>
#include <string.h>

#define CT_LEN 4096ul // bytes; >= 0
#define DATA_LEN 64ul // bytes; >= 0
#define KNT_LEN 16ul  // bytes; secret key/ nonce/ auth tag

// Benchmark Acorn-128 authenticated encryption routine
static void
acorn_encrypt(benchmark::State& state)
{
  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(CT_LEN));
  uint8_t* enc = static_cast<uint8_t*>(malloc(CT_LEN));
  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  random_data(text, CT_LEN);
  // random associated data bytes
  random_data(data, DATA_LEN);
  // random secret key ( = 128 -bit )
  random_data(key, KNT_LEN);
  // random public message nonce ( = 128 -bit )
  random_data(nonce, KNT_LEN);

  memset(enc, 0, CT_LEN);
  memset(tag, 0, KNT_LEN);

  size_t itr = 0;
  for (auto _ : state) {
    acorn::encrypt(key, nonce, text, CT_LEN, data, DATA_LEN, enc, tag);

    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
    benchmark::DoNotOptimize(itr++);
  }

  state.SetBytesProcessed(static_cast<int64_t>((DATA_LEN + CT_LEN) * itr));
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
acorn_decrypt(benchmark::State& state)
{
  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(CT_LEN));
  uint8_t* enc = static_cast<uint8_t*>(malloc(CT_LEN));
  uint8_t* dec = static_cast<uint8_t*>(malloc(CT_LEN));
  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  random_data(text, CT_LEN);
  // random associated data bytes
  random_data(data, DATA_LEN);
  // random secret key ( = 128 -bit )
  random_data(key, KNT_LEN);
  // random public message nonce ( = 128 -bit )
  random_data(nonce, KNT_LEN);

  memset(enc, 0, CT_LEN);
  memset(dec, 0, CT_LEN);
  memset(tag, 0, KNT_LEN);

  // compute encrypted text & authentication tag
  acorn::encrypt(key, nonce, text, CT_LEN, data, DATA_LEN, enc, tag);

  size_t itr = 0;
  for (auto _ : state) {
    using namespace benchmark;
    using namespace acorn;

    DoNotOptimize(decrypt(key, nonce, tag, enc, CT_LEN, data, DATA_LEN, dec));
    DoNotOptimize(dec);
    DoNotOptimize(itr++);
  }

  state.SetBytesProcessed(static_cast<int64_t>((DATA_LEN + CT_LEN) * itr));
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

// register for benchmarking
BENCHMARK(acorn_encrypt);
BENCHMARK(acorn_decrypt);

// main function to make it executable
BENCHMARK_MAIN();
