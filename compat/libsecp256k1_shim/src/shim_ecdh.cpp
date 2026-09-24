// ============================================================================
// shim_ecdh.cpp -- ECDH key exchange (secp256k1_ecdh)
// ============================================================================
// Implements the libsecp256k1 ECDH module API using the CT engine.
// ECDH is secret-bearing: the private key scalar multiplication must use
// the raw Jacobian multiplication and fixed-size serializer.
// ============================================================================

#include "secp256k1_ecdh.h"
#include "secp256k1.h"
#include "shim_internal.hpp"

#include <cstring>
#include <array>
#if defined(SECP256K1_CT_ECDH_TAINT_PROBE)
#include <cstdlib>
#endif

#include "secp256k1/detail/secure_erase.hpp"

#include "secp256k1/ecdh.hpp"
#include "secp256k1/field.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/sha256.hpp"
#include "secp256k1/ct/point.hpp"
#include "secp256k1/detail/ct_point_internal.hpp"
#include "secp256k1/detail/ct_point_io.hpp"

using namespace secp256k1::fast;

namespace {
struct ScopeSecureErase {
    void* ptr;
    std::size_t size;
    ~ScopeSecureErase() { secp256k1::detail::secure_erase(ptr, size); }
};
} // namespace

// -- Default hash: SHA-256(compressed_point) -----------------------------------
// Matches libsecp256k1's secp256k1_ecdh_hashfp_sha256 behaviour exactly.

static int default_hashfp(unsigned char* output,
    const unsigned char* x32, const unsigned char* y32, void* /*data*/)
{
    // prefix: 02 for even y, 03 for odd y
    uint8_t prefix = static_cast<uint8_t>(0x02 | (y32[31] & 1));
    uint8_t compressed[33];
    ScopeSecureErase erase_compressed{compressed, sizeof(compressed)};
    compressed[0] = prefix;
    std::memcpy(compressed + 1, x32, 32);
    auto h = secp256k1::SHA256::hash(compressed, 33);
    ScopeSecureErase erase_hash{h.data(), h.size()};
    std::memcpy(output, h.data(), 32);
    return 1;
}

extern "C" {

const secp256k1_ecdh_hashfp secp256k1_ecdh_hashfp_sha256 = default_hashfp;

int secp256k1_ecdh(
    const secp256k1_context* ctx,
    unsigned char* output,
    const secp256k1_pubkey* pubkey,
    const unsigned char* seckey,
    secp256k1_ecdh_hashfp hashfp,
    void* data)
{
    SHIM_REQUIRE_CTX(ctx);
    if (!output) { secp256k1_shim_call_illegal_cb(ctx, "secp256k1_ecdh: NULL output"); return 0; }
    if (!pubkey) { secp256k1_shim_call_illegal_cb(ctx, "secp256k1_ecdh: NULL pubkey"); return 0; }
    if (!seckey) { secp256k1_shim_call_illegal_cb(ctx, "secp256k1_ecdh: NULL seckey"); return 0; }

    if (!hashfp) hashfp = default_hashfp;

    // P1-SEC-NEW-001 (Rule 11): private key MUST use strict parsing — values >= n
    // must be rejected, not silently reduced. libsecp256k1 reduces silently; this shim
    // is stricter. Divergence documented in docs/SHIM_KNOWN_DIVERGENCES.md.
    std::array<uint8_t, 32> kb{};
    ScopeSecureErase erase_kb{kb.data(), kb.size()};
    std::memcpy(kb.data(), seckey, 32);
    Scalar sk;
    ScopeSecureErase erase_sk{&sk, sizeof(sk)};
    if (!Scalar::parse_bytes_strict_nonzero(kb.data(), sk)) return 0;

    // Deserialize public key (shim layout: X || Y, 64 bytes)
    std::array<uint8_t, 32> xb{}, yb{};
    std::memcpy(xb.data(), pubkey->data,      32);
    std::memcpy(yb.data(), pubkey->data + 32, 32);
    auto x = FieldElement::from_bytes(xb);
    auto y = FieldElement::from_bytes(yb);
    // P2-SEC-NEW-002: curve membership check prevents invalid-curve (small-order subgroup)
    // attack. A hostile caller who bypasses ec_pubkey_parse could supply an off-curve point;
    // ECDH on a small-order point leaks private key bits modulo the subgroup order.
    {
        auto lhs = y.square();
        auto rhs = x.square() * x + FieldElement::from_uint64(7);
        if (!(lhs == rhs)) return 0;
    }
    auto pk = Point::from_affine(x, y);
    if (pk.is_infinity()) return 0;

    // ECDH: result = sk * PK  (constant-time — secret key must not leak via timing)
    auto result = secp256k1::ct::detail::scalar_mul_jacobian(pk, sk);
    ScopeSecureErase erase_result{&result, sizeof(result)};
#if defined(SECP256K1_CT_ECDH_TAINT_PROBE)
    if (std::getenv("SECP256K1_ECDH_NEW_PATH_PROBE"))
        SECP256K1_CLASSIFY(&result, sizeof(result));
#endif
    std::array<uint8_t, 64> xy64{};
    ScopeSecureErase erase_xy{xy64.data(), xy64.size()};
    auto valid = secp256k1::ct::detail::point_to_xy64(result, xy64);
    SECP256K1_DECLASSIFY(&valid, sizeof(valid));
    if (valid == 0) return 0;

    // Custom callbacks consume secret bytes and remain outside our CT claim.
    return hashfp(output, xy64.data(), xy64.data() + 32, data);
}

} // extern "C"
