#include <random>
#include <cstdint>

namespace beldexss::util {

/// Returns a reference to a randomly seeded, thread-local RNG.
std::mt19937_64& rng();

/// Returns a random number from [0, n); (copied from beldexd)
uint64_t uniform_distribution_portable(std::mt19937_64& mersenne_twister, uint64_t n);

}  // namespace beldexss::util
