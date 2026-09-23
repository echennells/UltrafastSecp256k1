#include "secp256k1/ct/point.hpp"
#include "secp256k1/detail/ct_point_internal.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <utility>

namespace {

using secp256k1::fast::FieldElement;
using secp256k1::fast::Point;
using secp256k1::fast::Scalar;

bool check_raw_result(const Point& peer, const Scalar& scalar, const char* name) {
    const auto raw = secp256k1::ct::detail::scalar_mul_jacobian(peer, scalar);
    const auto actual = raw.to_point().to_compressed();
    const auto public_result = secp256k1::ct::scalar_mul(peer, scalar).to_compressed();
    const auto reference = peer.scalar_mul(scalar).to_compressed();
    if (actual == public_result && actual == reference) return true;
    std::printf("FAIL: %s\n", name);
    return false;
}

std::uint64_t next_random(std::uint64_t& state) {
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * 0x2545f4914f6cdd1dULL;
}

} // namespace

int main() {
    const auto generator = Point::generator();
    const auto doubled = generator.dbl();
    if (doubled.is_infinity() || doubled.z() == FieldElement::one()) {
        std::puts("FAIL: doubled peer must be non-affine");
        return 1;
    }

    const auto order_minus_one = Scalar::from_hex(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
    const std::array<std::pair<Scalar, const char*>, 3> named{{
        {Scalar::one(), "scalar 1"},
        {Scalar::from_uint64(2), "scalar 2"},
        {order_minus_one, "scalar n-1"},
    }};
    for (const auto& [scalar, name] : named) {
        if (!check_raw_result(generator, scalar, name)) return 1;
        if (!check_raw_result(doubled, scalar, name)) return 1;
    }

    std::uint64_t state = 0x9e3779b97f4a7c15ULL;
    for (int i = 0; i < 8; ++i) {
        std::array<std::uint8_t, 32> bytes{};
        for (std::size_t j = 0; j < bytes.size(); j += 8) {
            const auto word = next_random(state);
            for (unsigned b = 0; b < 8; ++b)
                bytes[j + b] = static_cast<std::uint8_t>(word >> (8 * b));
        }
        Scalar scalar;
        if (!Scalar::parse_bytes_strict_nonzero(bytes, scalar)) {
            --i;
            continue;
        }
        if (!check_raw_result(generator, scalar, "deterministic random scalar")) return 1;
        if (!check_raw_result(doubled, scalar, "deterministic random scalar/non-affine peer")) return 1;
    }

    std::puts("PASS: raw Jacobian scalar multiplication matches public and fast references");
    return 0;
}
