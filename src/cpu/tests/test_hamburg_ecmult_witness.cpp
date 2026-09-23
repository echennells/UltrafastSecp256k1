#include "secp256k1/ct/point.hpp"
#include "secp256k1/ct/ops.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

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

bool check_reference(const Point& peer, const Scalar& scalar, const char* name,
                     FieldElement denominator = FieldElement::one()) {
    // The public-data fast::Point path does not use the Hamburg CT ladder.
    const auto expected = scalar.is_zero()
        ? FieldElement::zero().to_bytes()
        : peer.scalar_mul(scalar).x().to_bytes();
    const auto actual = secp256k1::ct::ecmult_const_xonly(
        peer.x() * denominator, denominator, scalar).to_bytes();
    if (actual == expected) return true;
    std::printf("FAIL: %s ct::ecmult_const_xonly\n  got=", name);
    print_hex(actual);
    std::printf("\n  want=");
    print_hex(expected);
    std::printf("\n");
    return false;
}

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

int main(int argc, char** argv) {
    const auto generator = Point::generator();
    if (argc == 2 && std::strcmp(argv[1], "--offcurve") == 0) {
        // x=5 has no secp256k1 lift; check the public invalid-point contract
        // separately from the Hamburg exceptional-set regression.
        const auto actual = secp256k1::ct::ecmult_const_xonly(
            FieldElement::from_uint64(5), FieldElement::one(),
            Scalar::from_uint64(7)).to_bytes();
        if (actual == FieldElement::zero().to_bytes()) {
            std::puts("PASS: off-curve x=5 returns zero");
            return 0;
        }
        std::printf("FAIL: off-curve x=5 returned nonzero x=");
        print_hex(actual);
        std::printf("\n");
        return 2;
    }
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
    if (argc == 2 && std::strcmp(argv[1], "--taint") == 0) {
        SECP256K1_CLASSIFY(&scalar, sizeof(scalar));
        auto actual = secp256k1::ct::ecmult_const_xonly(
            generator.x(), FieldElement::one(), scalar);
        SECP256K1_DECLASSIFY(&actual, sizeof(actual));
        if (actual.to_bytes() != expected_x) {
            std::puts("FAIL: tainted Hamburg witness differs from independent x");
            return 1;
        }
        std::puts("PASS: tainted Hamburg witness");
        return 0;
    }
    bool ok = check_xonly(generator, scalar, expected_x,
                          "generator x, Hamburg exceptional scalar");
    // Near-order boundary vector. Its pinned x was computed by a separate
    // BigInt Jacobian double/add oracle; it is not a pre-fix RED witness.
    constexpr std::array<std::uint8_t, 32> second_scalar_bytes{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0x29, 0x1a, 0x66, 0x81, 0xb7, 0xcb, 0x5c, 0xd2,
        0x06, 0x8c, 0xab, 0xdf, 0x18, 0xa7, 0x80, 0x02,
    };
    constexpr std::array<std::uint8_t, 32> second_expected_x{
        0xb6, 0x97, 0xe5, 0xfb, 0x10, 0x22, 0xc6, 0xdf,
        0x52, 0x29, 0x58, 0x80, 0x7b, 0x0c, 0x8a, 0x3d,
        0x30, 0x49, 0x1f, 0x63, 0x62, 0x3f, 0xb8, 0xa9,
        0x5e, 0x22, 0x08, 0x9e, 0xb3, 0x30, 0x00, 0x2f,
    };
    Scalar second_scalar;
    if (!Scalar::parse_bytes_strict_nonzero(second_scalar_bytes, second_scalar) ||
        second_scalar.to_bytes() != second_scalar_bytes) {
        std::puts("FAIL: second witness scalar must be canonical and nonzero");
        return 1;
    }
    ok = check_xonly(generator, second_scalar, second_expected_x,
                     "generator x, independent near-order scalar") && ok;
    ok = check_reference(generator, scalar, "Hamburg witness as x/7 fraction",
                         FieldElement::from_uint64(7)) && ok;
    ok = check_reference(generator, Scalar::zero(), "generator x, scalar 0") && ok;
    ok = check_reference(generator, Scalar::zero() - Scalar::one(),
                         "generator x, scalar n-1") && ok;

    std::uint64_t state = 0x73e6d9b14c25f08aULL;
    for (std::size_t i = 0; i < 256; ++i) {
        const auto peer_scalar = Scalar::from_uint64(next_random(state) | 1ULL);
        const auto test_scalar = random_canonical_scalar(state);
        const auto denominator = FieldElement::from_uint64(next_random(state) | 1ULL);
        const auto peer = generator.scalar_mul(peer_scalar);
        char name[64];
        std::snprintf(name, sizeof(name), "deterministic peer/scalar %zu", i);
        ok = check_reference(peer, test_scalar, name) && ok;
        std::snprintf(name, sizeof(name), "fractional peer/scalar %zu", i);
        ok = check_reference(peer, test_scalar, name, denominator) && ok;
    }
    if (ok) std::puts("PASS: Hamburg x-only differential cases");
    return ok ? 0 : 1;
}
