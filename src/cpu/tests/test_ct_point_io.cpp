#include "secp256k1/ct/point.hpp"
#include "secp256k1/detail/ct_point_internal.hpp"
#include "secp256k1/detail/ct_point_io.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

bool check_serializers(const secp256k1::ct::CTJacobianPoint& raw,
                       const Point& reference, const char* name) {
    const auto compressed = reference.to_compressed();
    const auto uncompressed = reference.to_uncompressed();
    constexpr auto valid = ~std::uint64_t{0};
    std::array<std::uint8_t, 32> x{};
    std::array<std::uint8_t, 33> c{};
    std::array<std::uint8_t, 64> xy{};
    const auto xm = secp256k1::ct::detail::point_to_x32(raw, x);
    const auto cm = secp256k1::ct::detail::point_to_compressed33(raw, c);
    const auto xym = secp256k1::ct::detail::point_to_xy64(raw, xy);
    if (xm == valid && cm == valid && xym == valid &&
        std::equal(x.begin(), x.end(), uncompressed.begin() + 1) &&
        c == compressed &&
        std::equal(xy.begin(), xy.end(), uncompressed.begin() + 1)) return true;
    std::printf("FAIL: %s serialization\n", name);
    return false;
}

bool check_invalid_serializers(const secp256k1::ct::CTJacobianPoint& raw,
                               const char* name) {
    std::array<std::uint8_t, 32> x;
    std::array<std::uint8_t, 33> c;
    std::array<std::uint8_t, 64> xy;
    x.fill(0xa5);
    c.fill(0xa5);
    xy.fill(0xa5);
    const auto xm = secp256k1::ct::detail::point_to_x32(raw, x);
    const auto cm = secp256k1::ct::detail::point_to_compressed33(raw, c);
    const auto xym = secp256k1::ct::detail::point_to_xy64(raw, xy);
    const auto all_zero = [](std::uint8_t b) { return b == 0; };
    if (xm == 0 && cm == 0 && xym == 0 &&
        std::all_of(x.begin(), x.end(), all_zero) &&
        std::all_of(c.begin(), c.end(), all_zero) &&
        std::all_of(xy.begin(), xy.end(), all_zero)) return true;
    std::printf("FAIL: %s invalid serialization\n", name);
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
    if (std::getenv("SECP256K1_CT_OLD_CONVERSION_PROBE") != nullptr) {
        auto raw = secp256k1::ct::detail::scalar_mul_jacobian(
            doubled, Scalar::from_uint64(17));
        SECP256K1_CLASSIFY(&raw, sizeof(raw));
        auto bytes = raw.to_point().to_compressed();
        SECP256K1_DECLASSIFY(bytes.data(), bytes.size());
        std::printf("old conversion probe: %02x\n", bytes[0]);
        return 0;
    }
    if (std::getenv("SECP256K1_CT_SERIALIZER_PROBE") != nullptr) {
        auto raw = secp256k1::ct::detail::scalar_mul_jacobian(
            doubled, Scalar::from_uint64(17));
        SECP256K1_CLASSIFY(&raw, sizeof(raw));
        std::array<std::uint8_t, 32> x{};
        std::array<std::uint8_t, 33> compressed{};
        std::array<std::uint8_t, 64> xy{};
        auto xm = secp256k1::ct::detail::point_to_x32(raw, x);
        auto cm = secp256k1::ct::detail::point_to_compressed33(raw, compressed);
        auto xym = secp256k1::ct::detail::point_to_xy64(raw, xy);
        SECP256K1_DECLASSIFY(&xm, sizeof(xm));
        SECP256K1_DECLASSIFY(&cm, sizeof(cm));
        SECP256K1_DECLASSIFY(&xym, sizeof(xym));
        SECP256K1_DECLASSIFY(x.data(), x.size());
        SECP256K1_DECLASSIFY(compressed.data(), compressed.size());
        SECP256K1_DECLASSIFY(xy.data(), xy.size());
        if (xm != ~std::uint64_t{0} || cm != xm || xym != xm ||
            !std::equal(x.begin(), x.end(), xy.begin()) ||
            !std::equal(x.begin(), x.end(), compressed.begin() + 1)) return 1;
        std::puts("PASS: raw Jacobian serializers under taint");
        return 0;
    }
    if (doubled.is_infinity() || doubled.z() == FieldElement::one()) {
        std::puts("FAIL: doubled peer must be non-affine");
        return 1;
    }
    if (!check_serializers(secp256k1::ct::CTJacobianPoint::from_point(generator),
                           generator, "generator")) return 1;
    if (!check_serializers(secp256k1::ct::CTJacobianPoint::from_point(doubled),
                           doubled, "doubled projective")) return 1;
    if (!check_serializers(secp256k1::ct::detail::scalar_mul_jacobian(
                               doubled, Scalar::from_uint64(17)),
                           doubled.scalar_mul(Scalar::from_uint64(17)),
                           "raw non-affine multiple")) return 1;
    const auto infinity = secp256k1::ct::CTJacobianPoint::make_infinity();
    if (!check_invalid_serializers(infinity, "infinity")) return 1;
    auto flag_only = secp256k1::ct::CTJacobianPoint::from_point(generator);
    flag_only.infinity = ~std::uint64_t{0};
    if (!check_invalid_serializers(flag_only, "infinity flag with nonzero Z")) return 1;
    auto zero_z = secp256k1::ct::CTJacobianPoint::from_point(generator);
    zero_z.z = secp256k1::ct::FE52::zero();
    if (!check_invalid_serializers(zero_z, "zero Z without infinity flag")) return 1;

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
