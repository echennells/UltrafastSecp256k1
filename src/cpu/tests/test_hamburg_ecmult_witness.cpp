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

bool check_xonly(const Point& generator, const Scalar& scalar,
                 const std::array<std::uint8_t, 32>& expected,
                 const char* name) {
    const auto independent = generator.scalar_mul(scalar).x().to_bytes();
    if (independent != expected) {
        std::printf("FAIL: %s fast::Point reference differs from pinned expected\n  got=", name);
        print_hex(independent);
        std::printf("\n  want=");
        print_hex(expected);
        std::printf("\n");
        return false;
    }
    const auto actual = secp256k1::ct::ecmult_const_xonly(
        generator.x(), FieldElement::one(), scalar).to_bytes();
    if (actual != expected) {
        std::printf("FAIL: %s ct::ecmult_const_xonly\n  got=", name);
        print_hex(actual);
        std::printf("\n  want=");
        print_hex(expected);
        std::printf("\n");
        return false;
    }
    std::printf("PASS: %s\n", name);
    return true;
}

} // namespace

int main() {
    const auto generator = Point::generator();
    if (!check_xonly(generator, Scalar::one(), generator.x().to_bytes(),
                     "generator x, scalar 1 control")) return 1;

    // This scalar is strictly parsed so reduction cannot silently change the witness.
    constexpr std::array<std::uint8_t, 32> scalar_bytes{
        0x68, 0xf9, 0x71, 0xcf, 0x6c, 0x8d, 0xb0, 0x9d,
        0x29, 0xf6, 0x17, 0x77, 0x4c, 0x1e, 0xd4, 0xe9,
        0x4a, 0x90, 0x2a, 0xd5, 0x77, 0xcf, 0xa6, 0xb4,
        0x72, 0x3e, 0xe7, 0xb8, 0xea, 0x46, 0xa0, 0x6b,
    };
    constexpr std::array<std::uint8_t, 32> expected_x{
        0x5e, 0x09, 0x3b, 0xab, 0x94, 0x09, 0x2a, 0x15,
        0x02, 0x25, 0xa3, 0x7a, 0x6c, 0x50, 0x75, 0xca,
        0x78, 0x30, 0xea, 0x5c, 0xd9, 0x69, 0x60, 0xcb,
        0x10, 0x65, 0x69, 0xd8, 0x3e, 0x7a, 0xde, 0xa4,
    };
    Scalar scalar;
    if (!Scalar::parse_bytes_strict_nonzero(scalar_bytes, scalar) ||
        scalar.to_bytes() != scalar_bytes) {
        std::puts("FAIL: witness scalar must be canonical and nonzero");
        return 1;
    }
    return check_xonly(generator, scalar, expected_x,
                       "generator x, Hamburg exceptional scalar") ? 0 : 1;
}
