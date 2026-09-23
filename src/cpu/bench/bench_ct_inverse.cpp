#include "secp256k1/benchmark_harness.hpp"
#include "secp256k1/ct/field.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>

namespace {

using secp256k1::fast::FieldElement;

std::uint64_t next_random(std::uint64_t& state) noexcept {
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * 0x2545f4914f6cdd1dULL;
}

FieldElement seeded_input(std::uint64_t& state) {
    for (;;) {
        std::array<std::uint8_t, 32> bytes{};
        for (std::size_t word = 0; word < 4; ++word) {
            const auto value = next_random(state);
            for (std::size_t byte = 0; byte < 8; ++byte)
                bytes[word * 8 + byte] = static_cast<std::uint8_t>(value >> (56 - 8 * byte));
        }
        FieldElement input;
        if (FieldElement::parse_bytes_strict(bytes, input) &&
            input != FieldElement::zero()) return input;
    }
}

} // namespace

int main() {
    constexpr std::size_t pool_size = 64;
    constexpr std::size_t warmup = 4096;
    constexpr std::size_t iterations = 32768;
    std::array<FieldElement, pool_size> inputs{};
    std::uint64_t state = 0x70f4b5c68a1932deULL;
    for (auto& input : inputs) input = seeded_input(state);

    for (std::size_t i = 0; i < warmup; ++i) {
        auto output = secp256k1::ct::field_inv(inputs[i % pool_size]);
        bench::DoNotOptimize(output);
    }

    std::uint64_t checksum = 0xcbf29ce484222325ULL;
    const auto started = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < iterations; ++i) {
        auto output = secp256k1::ct::field_inv(inputs[i % pool_size]);
        bench::DoNotOptimize(output);
        checksum ^= output.limbs()[0] + static_cast<std::uint64_t>(i);
        checksum *= 0x100000001b3ULL;
    }
    const auto elapsed = std::chrono::steady_clock::now() - started;
    std::printf("ct inverse %.2f ns/call, checksum=%016llx, iterations=%zu, pool=%zu\n",
                std::chrono::duration<double, std::nano>(elapsed).count() / iterations,
                static_cast<unsigned long long>(checksum), iterations, pool_size);
    return 0;
}
