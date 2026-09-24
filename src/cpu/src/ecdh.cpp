#include "secp256k1/ecdh.hpp"
#include "secp256k1/sha256.hpp"
#include "secp256k1/ct/point.hpp"
#include "secp256k1/detail/ct_point_internal.hpp"
#include "secp256k1/detail/ct_point_io.hpp"
#include "secp256k1/detail/secure_erase.hpp"
#include <cstring>
#if defined(SECP256K1_CT_ECDH_TAINT_PROBE)
#include <cstdlib>
#endif

namespace secp256k1 {

using fast::Scalar;
using fast::Point;
using fast::FieldElement;

namespace {
struct EraseOnExit {
    void* ptr;
    std::size_t size;
    ~EraseOnExit() { secp256k1::detail::secure_erase(ptr, size); }
};

// The peer is public. Check its Jacobian coordinates directly so validation
// does not spend an inversion converting a non-affine peer to affine form.
bool valid_peer(const Point& peer) {
    if (peer.is_infinity()) return false;
    if (peer.is_normalized()) {
        const auto x = peer.x_raw();
        const auto y = peer.y_raw();
        return y.square() == x.square() * x + FieldElement::from_uint64(7);
    }
    const auto x = peer.X();
    const auto y = peer.Y();
    const auto z = peer.z();
    if (z == FieldElement::zero()) return false;
    const auto z2 = z.square();
    const auto z6 = z2.square() * z2;
    return y.square() == x.square() * x + FieldElement::from_uint64(7) * z6;
}
} // namespace

// -- ECDH: SHA-256(compressed point) ------------------------------------------

std::array<std::uint8_t, 32> ecdh_compute(
    const Scalar& private_key,
    const Point& public_key) {

    if (private_key.is_zero_ct()) return {};

    // SEC-005: reject off-curve pubkeys (invalid-curve attack defense).
    if (!valid_peer(public_key)) return {};

    auto shared = ct::detail::scalar_mul_jacobian(public_key, private_key);
    EraseOnExit erase_shared{&shared, sizeof(shared)};
#if defined(SECP256K1_CT_ECDH_TAINT_PROBE)
    if (std::getenv("SECP256K1_ECDH_NEW_PATH_PROBE"))
        SECP256K1_CLASSIFY(&shared, sizeof(shared));
#endif
    std::array<std::uint8_t, 33> compressed{};
    EraseOnExit erase_compressed{compressed.data(), compressed.size()};
    auto valid = ct::detail::point_to_compressed33(shared, compressed);
    SECP256K1_DECLASSIFY(&valid, sizeof(valid));
    if (valid == 0) return {};

    // Hash with SHA-256
    auto result = SHA256::hash(compressed.data(), compressed.size());
    return result;
}

// -- ECDH: SHA-256(x-coordinate) ----------------------------------------------

std::array<std::uint8_t, 32> ecdh_compute_xonly(
    const Scalar& private_key,
    const Point& public_key) {

    if (private_key.is_zero_ct()) return {};

    // SEC-005: reject off-curve pubkeys (invalid-curve attack defense).
    if (!valid_peer(public_key)) return {};

    auto shared = ct::detail::scalar_mul_jacobian(public_key, private_key);
    EraseOnExit erase_shared{&shared, sizeof(shared)};
#if defined(SECP256K1_CT_ECDH_TAINT_PROBE)
    if (std::getenv("SECP256K1_ECDH_NEW_PATH_PROBE"))
        SECP256K1_CLASSIFY(&shared, sizeof(shared));
#endif
    std::array<std::uint8_t, 32> x_bytes{};
    EraseOnExit erase_x{ x_bytes.data(), x_bytes.size() };
    auto valid = ct::detail::point_to_x32(shared, x_bytes);
    SECP256K1_DECLASSIFY(&valid, sizeof(valid));
    if (valid == 0) return {};

    auto result = SHA256::hash(x_bytes.data(), x_bytes.size());
    return result;
}

// -- ECDH: Raw x-coordinate --------------------------------------------------

std::array<std::uint8_t, 32> ecdh_compute_raw(
    const Scalar& private_key,
    const Point& public_key) {

    if (private_key.is_zero_ct()) return {};

    // SEC-005: reject off-curve pubkeys (invalid-curve attack defense).
    if (!valid_peer(public_key)) return {};

    auto shared = ct::detail::scalar_mul_jacobian(public_key, private_key);
    EraseOnExit erase_shared{&shared, sizeof(shared)};
#if defined(SECP256K1_CT_ECDH_TAINT_PROBE)
    if (std::getenv("SECP256K1_ECDH_NEW_PATH_PROBE"))
        SECP256K1_CLASSIFY(&shared, sizeof(shared));
#endif
    std::array<std::uint8_t, 32> result{};
    auto valid = ct::detail::point_to_x32(shared, result);
    SECP256K1_DECLASSIFY(&valid, sizeof(valid));
    if (valid == 0) return {};
    return result;
}

} // namespace secp256k1
