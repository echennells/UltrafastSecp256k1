#ifndef SECP256K1_DETAIL_CT_POINT_IO_HPP
#define SECP256K1_DETAIL_CT_POINT_IO_HPP

#include "secp256k1/ct/point.hpp"
#include "secp256k1/detail/secure_erase.hpp"

#include <array>
#include <cstdint>

namespace secp256k1::ct::detail {

// The only runtime validity decisions are represented by a mask. The profile
// using the 4x64 portable field fallback needs separate field-kernel evidence
// before this complete path can be described as constant-time there.
template <std::size_t N>
inline std::uint64_t serialize_jacobian(const CTJacobianPoint& point,
                                        std::array<std::uint8_t, N>& out) noexcept {
    static_assert(N == 32 || N == 33 || N == 64);
#if defined(SECP256K1_FAST_52BIT)
    FieldElement x = point.x.to_fe();
    FieldElement z = point.z.to_fe();
#else
    FieldElement x = point.x;
    FieldElement z = point.z;
#endif
    FieldElement zi = field_inv(z);
    FieldElement zi2 = field_sqr(zi);
    FieldElement ax = field_mul(x, zi2);
    std::array<std::uint8_t, 32> xb{};
    ax.to_bytes_into(xb.data());
    const std::uint64_t valid = is_zero_mask(point.infinity) & ~field_is_zero(z);
    const auto keep = static_cast<std::uint8_t>(valid);

    if constexpr (N == 32) {
        for (std::size_t i = 0; i < 32; ++i) out[i] = xb[i] & keep;
    } else {
#if defined(SECP256K1_FAST_52BIT)
        FieldElement y = point.y.to_fe();
#else
        FieldElement y = point.y;
#endif
        FieldElement zi3 = field_mul(zi2, zi);
        FieldElement ay = field_mul(y, zi3);
        std::array<std::uint8_t, 32> yb{};
        ay.to_bytes_into(yb.data());
        if constexpr (N == 33) {
            out[0] = static_cast<std::uint8_t>(2 | (yb[31] & 1)) & keep;
            for (std::size_t i = 0; i < 32; ++i) out[i + 1] = xb[i] & keep;
        } else {
            for (std::size_t i = 0; i < 32; ++i) {
                out[i] = xb[i] & keep;
                out[i + 32] = yb[i] & keep;
            }
        }
        secp256k1::detail::secure_erase(yb.data(), yb.size());
        secp256k1::detail::secure_erase(&ay, sizeof(ay));
        secp256k1::detail::secure_erase(&zi3, sizeof(zi3));
        secp256k1::detail::secure_erase(&y, sizeof(y));
    }
    secp256k1::detail::secure_erase(xb.data(), xb.size());
    secp256k1::detail::secure_erase(&ax, sizeof(ax));
    secp256k1::detail::secure_erase(&zi2, sizeof(zi2));
    secp256k1::detail::secure_erase(&zi, sizeof(zi));
    secp256k1::detail::secure_erase(&z, sizeof(z));
    secp256k1::detail::secure_erase(&x, sizeof(x));
    return valid;
}

inline std::uint64_t point_to_x32(const CTJacobianPoint& point,
                                  std::array<std::uint8_t, 32>& out) noexcept {
    return serialize_jacobian(point, out);
}

inline std::uint64_t point_to_compressed33(const CTJacobianPoint& point,
                                           std::array<std::uint8_t, 33>& out) noexcept {
    return serialize_jacobian(point, out);
}

inline std::uint64_t point_to_xy64(const CTJacobianPoint& point,
                                   std::array<std::uint8_t, 64>& out) noexcept {
    return serialize_jacobian(point, out);
}

} // namespace secp256k1::ct::detail

#endif // SECP256K1_DETAIL_CT_POINT_IO_HPP
