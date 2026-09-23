#include "secp256k1/benchmark_harness.hpp"
#include "secp256k1/ct/point.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace {

using secp256k1::fast::FieldElement;
using secp256k1::fast::Point;
using secp256k1::fast::Scalar;

std::uint64_t next_random(std::uint64_t& state) noexcept {
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * 0x2545f4914f6cdd1dULL;
}

Scalar random_canonical_scalar(std::uint64_t& state) {
    for (;;) {
        std::array<std::uint8_t, 32> bytes{};
        for (std::size_t i = 0; i < 4; ++i) {
            const auto word = next_random(state);
            for (std::size_t j = 0; j < 8; ++j)
                bytes[i * 8 + j] = static_cast<std::uint8_t>(word >> (56 - 8 * j));
        }
        Scalar scalar;
        if (Scalar::parse_bytes_strict_nonzero(bytes, scalar)) return scalar;
    }
}

} // namespace

int main() {
    constexpr std::size_t pool_size = 32;
    constexpr std::size_t warmup = 256;
    constexpr std::size_t iterations = 4096;
    std::array<FieldElement, pool_size> peers{};
    std::array<Scalar, pool_size> scalars{};
    std::uint64_t state = 0x39d7f082b41e6a5cULL;
    const auto generator = Point::generator();
    for (std::size_t i = 0; i < pool_size; ++i) {
        peers[i] = generator.scalar_mul(Scalar::from_uint64(i + 1)).x();
        scalars[i] = random_canonical_scalar(state);
    }

    for (std::size_t i = 0; i < warmup; ++i) {
        const auto output = secp256k1::ct::ecmult_const_xonly(
            peers[i % pool_size], FieldElement::one(), scalars[i % pool_size]);
        bench::DoNotOptimize(output);
    }

    std::uint64_t checksum = 0xcbf29ce484222325ULL;
    const auto started = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < iterations; ++i) {
        const auto output = secp256k1::ct::ecmult_const_xonly(
            peers[i % pool_size], FieldElement::one(), scalars[i % pool_size]);
        bench::DoNotOptimize(output);
        const auto bytes = output.to_bytes();
        checksum ^= static_cast<std::uint64_t>(bytes[0]) + i;
        checksum *= 0x100000001b3ULL;
    }
    const auto elapsed = std::chrono::steady_clock::now() - started;
    std::printf("Hamburg ecmult_const_xonly %.2f ns/call, checksum=%016llx, "
                "iterations=%zu, pool=%zu\n",
                std::chrono::duration<double, std::nano>(elapsed).count() / iterations,
                static_cast<unsigned long long>(checksum), iterations, pool_size);
    return 0;
}
