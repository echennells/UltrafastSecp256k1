#include "secp256k1/ct/point.hpp"

#include <array>
#include <cstdint>
#include <cstdio>

namespace {

using secp256k1::fast::FieldElement;
using secp256k1::fast::Point;
using secp256k1::fast::Scalar;

void print_hex(const std::array<std::uint8_t, 32>& bytes) {
    for (const auto byte : bytes) std::printf("%02x", static_cast<unsigned>(byte));
}

bool expect_x(const FieldElement& xn, const FieldElement& xd, const Scalar& q,
              const std::array<std::uint8_t, 32>& expected, const char* name) {
    const auto actual = secp256k1::ct::ecmult_const_xonly(xn, xd, q).to_bytes();
    if (actual == expected) {
        std::printf("PASS: %s\n", name);
        return true;
    }
    std::printf("FAIL: %s\n  got=", name);
    print_hex(actual);
    std::printf("\n  want=");
    print_hex(expected);
    std::printf("\n");
    return false;
}

} // namespace

int main() {
    const auto generator = Point::generator();
    const auto one = FieldElement::one();
    const auto zero = FieldElement::zero();
    const auto seven = Scalar::from_uint64(7);
    const std::array<std::uint8_t, 32> zero_bytes{};

    // 7*G.x is pinned independently of the x-only implementation.
    constexpr std::array<std::uint8_t, 32> seven_g_x{
        0x5c, 0xbd, 0xf0, 0x64, 0x6e, 0x5d, 0xb4, 0xea,
        0xa3, 0x98, 0xf3, 0x65, 0xf2, 0xea, 0x7a, 0x0e,
        0x3d, 0x41, 0x9b, 0x7e, 0x03, 0x30, 0xe3, 0x9c,
        0xe9, 0x2b, 0xdd, 0xed, 0xca, 0xc4, 0xf9, 0xbc,
    };
    if (generator.scalar_mul(seven).x().to_bytes() != seven_g_x) {
        std::puts("FAIL: independent 7*G reference differs from pinned bytes");
        return 1;
    }

    bool ok = true;
    ok = expect_x(generator.x(), one, seven, seven_g_x,
                  "valid direct generator fraction") && ok;
    const auto three = FieldElement::from_uint64(3);
    ok = expect_x(generator.x() * three, three, seven, seven_g_x,
                  "valid scaled generator fraction") && ok;
    ok = expect_x(generator.x(), one, Scalar::zero(), zero_bytes,
                  "zero scalar") && ok;

    // Preserve the independently pinned Hamburg exceptional-set witness.
    constexpr std::array<std::uint8_t, 32> witness_q{
        0x68, 0xf9, 0x71, 0xcf, 0x6c, 0x8d, 0xb0, 0x9d,
        0x29, 0xf6, 0x17, 0x77, 0x4c, 0x1e, 0xd4, 0xe9,
        0x4a, 0x90, 0x2a, 0xd5, 0x77, 0xcf, 0xa6, 0xb4,
        0x72, 0x3e, 0xe7, 0xb8, 0xea, 0x46, 0xa0, 0x6b,
    };
    constexpr std::array<std::uint8_t, 32> witness_x{
        0x5e, 0x09, 0x3b, 0xab, 0x94, 0x09, 0x2a, 0x15,
        0x02, 0x25, 0xa3, 0x7a, 0x6c, 0x50, 0x75, 0xca,
        0x78, 0x30, 0xea, 0x5c, 0xd9, 0x69, 0x60, 0xcb,
        0x10, 0x65, 0x69, 0xd8, 0x3e, 0x7a, 0xde, 0xa4,
    };
    Scalar witness_scalar;
    if (!Scalar::parse_bytes_strict_nonzero(witness_q, witness_scalar) ||
        generator.scalar_mul(witness_scalar).x().to_bytes() != witness_x) {
        std::puts("FAIL: independent Hamburg reference differs from pinned bytes");
        return 1;
    }
    ok = expect_x(generator.x(), one, witness_scalar, witness_x,
                  "Hamburg exceptional scalar") && ok;

    // x=5 has no secp256k1 lift. A zero denominator is never a valid fraction.
    ok = expect_x(FieldElement::from_uint64(5), one, seven, zero_bytes,
                  "invalid off-curve x=5") && ok;
    ok = expect_x(generator.x(), zero, seven, zero_bytes,
                  "invalid zero denominator") && ok;
    return ok ? 0 : 1;
}
