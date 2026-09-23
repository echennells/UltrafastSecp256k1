#include "secp256k1/ct/field.hpp"
#include "secp256k1/field_52.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

using secp256k1::fast::FieldElement;
using secp256k1::fast::FieldElement52;

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

bool check(const FieldElement& input, std::size_t index,
           std::uint64_t& checksum) {
    const auto actual = secp256k1::ct::field_inv(input);
    // Public-data oracle has a separate FE52 representation and variable-time
    // SafeGCD path. This test never passes a secret to that reference.
    const auto expected = FieldElement52::from_fe(input).inverse_safegcd().to_fe();
    const auto actual_bytes = actual.to_bytes();
    const auto expected_bytes = expected.to_bytes();
    if (actual_bytes != expected_bytes ||
        std::memcmp(actual.limbs().data(), expected.limbs().data(), 32) != 0) {
        std::printf("FAIL: inverse byte/limb mismatch at input %zu\n", index);
        return false;
    }
    const auto product = secp256k1::ct::field_mul(input, actual);
    const auto wanted = input == FieldElement::zero()
                            ? FieldElement::zero() : FieldElement::one();
    if (product.to_bytes() != wanted.to_bytes()) {
        std::printf("FAIL: inverse product at input %zu\n", index);
        return false;
    }
    for (const auto byte : actual_bytes) {
        checksum ^= byte;
        checksum *= 0x100000001b3ULL;
    }
    return true;
}

} // namespace

int main() {
    constexpr std::uint64_t max = ~std::uint64_t{0};
    constexpr std::array<FieldElement::limbs_type, 13> edges{{
        {0, 0, 0, 0},
        {1, 0, 0, 0},
        {2, 0, 0, 0},
        {0xFFFFFFFEFFFFFC2EULL, max, max, max}, // p - 1
        {0xFFFFFFFEFFFFFC2DULL, max, max, max}, // p - 2
        {max, 0, 0, 0},
        {0, 1, 0, 0},
        {1, 1, 0, 0},
        {max, max, 0, 0},
        {0, 0, 1, 0},
        {0, 0, 0, 1},
        {0, 0, 0, 1ULL << 63},
        {0xFFFFFFFEFFFFFC2CULL, max, max, max}, // p - 3
    }};
    std::uint64_t checksum = 0xcbf29ce484222325ULL;
    std::size_t index = 0;
    for (const auto& limbs : edges) {
        if (!check(FieldElement::from_limbs(limbs), index++, checksum)) return 1;
    }
    std::uint64_t state = 0x70f4b5c68a1932deULL;
    for (std::size_t i = 0; i < 1024; ++i) {
        if (!check(seeded_input(state), index++, checksum)) return 1;
    }
    std::printf("PASS: ct inverse exact bytes, limbs and products; samples=%zu checksum=%016llx\n",
                index, static_cast<unsigned long long>(checksum));
    return 0;
}
