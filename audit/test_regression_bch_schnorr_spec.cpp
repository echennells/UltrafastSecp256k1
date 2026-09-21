// ============================================================================
// test_regression_bch_schnorr_spec.cpp
// ============================================================================
// Bitcoin Cash 2019 Schnorr (OP_CHECKDATASIG / secp256k1_schnorr_*) conformance.
//
// This is NOT BIP-340. The authoritative construction is the 2019-05-15 BCH
// upgrade specification. Two of its requirements were absent from
// compat/libsecp256k1_bchn_shim/src/shim_schnorr_bch.cpp until 2026-09-14, and
// nothing in the tree ran that file: the BCH shim is built only under
// SECP256K1_BCHN_SHIM_BUILD_TESTS, which defaults OFF and which no CI workflow
// and no ci/ script ever turned on. It was neither compiled nor tested.
//
//   (1) JACOBI(R.y) == 1.  The signer must negate its nonce when R.y is not a
//       quadratic residue; the verifier must fail when Jacobi(R'.y) != 1
//       (spec verification step 10). Neither existed. Measured over 16 fixed
//       (key, message) pairs, the pre-fix signer produced a residue R.y in only
//       6 -- so 10 of 16 signatures would have been REJECTED by BCHN and by
//       Libauth -- while its own verifier accepted all 16, because the same
//       omission on both sides hid the other.
//
//   (2) RFC 6979 algo16 = "Schnorr+SHA256  " (two trailing 0x20).  The signer
//       used the plain ECDSA nonce path, so its nonces -- and therefore its
//       signature bytes -- matched neither BCHN nor Libauth for the same key
//       and message. 0 of 16 were byte-identical before; 16 of 16 are now.
//
//       The tag is a SECURITY control, not a formatting detail. The function it
//       called, rfc6979_nonce(d, msg), is the one ct::ecdsa_sign calls, with the
//       same arguments -- so signing one message under both schemes with one key
//       reused a single nonce across two equations, s1 = k^-1(z + r*d) and
//       s2 = k + e*d, from which d = (s1*s2 - z)/(r + s1*e). Both signatures are
//       public. Measured against the pre-fix shim: the Schnorr r equalled the
//       ECDSA r in every case, and 16 of 16 private keys were recovered from
//       their own signature pairs. Section (4) is the regression probe.
//
// The vectors below come from an INDEPENDENT pure-Python implementation written
// from the specification text, RFC 6979 and libsecp256k1's nonce keydata layout
// -- not from this engine. Its RFC 6979 was itself cross-checked against
// rfc6979_nonce_libsecp_compat with the "ECDSA\0..." tag, a path this repository
// already asserts is byte-identical to upstream, so the BCH-tagged output it
// produces is trustworthy as a known-answer source.
//
// Spec: https://upgradespecs.bitcoincashnode.org/2019-05-15-schnorr/
// ============================================================================

#include "secp256k1.h"
#include "secp256k1_schnorr.h"

#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/field.hpp"
#include "secp256k1/sha256.hpp"
#include "secp256k1/ct/point.hpp"
#include "secp256k1/ct/sign.hpp"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <array>

using secp256k1::fast::FieldElement;
using secp256k1::fast::Point;
using secp256k1::fast::Scalar;

static int g_pass = 0, g_fail = 0;
static void check(bool cond, const char* msg) {
    if (cond) { ++g_pass; }
    else      { ++g_fail; std::printf("  [FAIL] %s\n", msg); }
}

// The BCH shim only null-checks its context argument; every test here exercises
// the signing/verification math, not context lifetime, which
// test_bchn_schnorr_fail_clear already covers.
static const char kCtxStorage = 0;
static const secp256k1_context* bch_ctx() {
    return reinterpret_cast<const secp256k1_context*>(&kCtxStorage);
}

static bool from_hex(const char* hex, std::uint8_t* out, std::size_t n) {
    if (std::strlen(hex) != n * 2) return false;
    for (std::size_t i = 0; i < n; ++i) {
        unsigned v = 0;
        if (std::sscanf(hex + 2 * i, "%2x", &v) != 1) return false;
        out[i] = static_cast<std::uint8_t>(v);
    }
    return true;
}

struct BchVector {
    const char* seckey;   // 32 bytes
    const char* msg;      // 32 bytes
    const char* pub_x;    // 32 bytes
    const char* pub_y;    // 32 bytes
    const char* sig;      // 64 bytes: r || s
};

static const BchVector kVectors[] = {
    { // SHA256("key1") / SHA256("msg1")
      "8174099687a26621f4e2cdd7cc03b3dacedb3fb962255b1aafd033cabe831530",
      "289e5175e02c788c2d442cfe81d6be0533d8c13e253ef763fda45d37accfe4d4",
      "f771877964fa2ce401d87bc2558a0df1e6921acef99389f059712b32cfda35fd",
      "90294bf51aedc048671c77d21792f2c7320e02234afb8ee77e1fce48a9390947",
      "7e32606ecf3439a34cf2b2b0b264c8bfbe78854b8c5a5a8f75669b091712cfe5d26de69291c11509e006a60d05e033d427636bd0adfde51b36eaa0fa69e06840" },
    { // SHA256("key2") / SHA256("msg2")
      "b10253764c8b233fb37542e23401c7b450e5a6f9751f3b5a014f6f67e8bc999d",
      "a78521e49048b6e0d368d3fba417fc20c7546272dafa78a8a173fcca6c81233b",
      "f039fdcdb728efbbddf4ee452419a988497debb7bd1b42644c5fa66e9af8c8b6",
      "08f516435d1217f63e786a5a66c2122c343d07c583239329cc7c2256d71d1d27",
      "2e38ea24145c2e139c84a3dd7cbe1d02c7a4a6573262317bc585c397ed4844abe57420edac4e1b2230087ebd2b50f1e38a7bcc235331349bf57f2c22186d080d" },
    { // SHA256("key3") / SHA256("msg3")
      "f576104eebeab09651d83acffc77c8b8c6eaa4b767aeab24d7da80f83f51d865",
      "89da2bd31a5d008c84323c9693f12f09e62a75a688a55f2a6fd24660afba5660",
      "6da0e4d65a933e828c9de388005281dfa7e4948895d10c7c3ef617b5e40d97fd",
      "f424db33400fd7fab1d6e84f4551babd04662a8b1699fbcbf96aba3a3eaedd86",
      "8d66933e3593f104f72e27815bfcaae2c702b7f9ca6ebb3ba99a8d38b6aec1df5e3cbfcf4178b4fe144ebc541623b5cf293cd8a5cf56d09e883ef0c7b2eda6b7" },
    { // SHA256("key4") / SHA256("msg4")
      "a4b3504c2769fce9547f6dda310dd8b094d630a044d65f5324d4b37310aab714",
      "51b5df22eaeaf7a6101b57cfb45084cb98864b1502c6ed1a692da604366a13a4",
      "b15867cb022210f38bf0ae40f4deadc680779338d2bf2569bb99507f95280a2e",
      "68af1237eb189b5f5e0d948135a1fc274cace4171fe65b0d5220a09528717f91",
      "67451e09febdd0a1ece301dd22f0b071e298c1815a3588308b184c330201e820024cb8a6f717ac7d40223740e9160963ce82f954959c3be78979bbaf3468d4ac" },
    { // SHA256("key5") / SHA256("msg5")
      "07e7394e0702340d9fd1d777fbbad2804a5188d1dd07ff580f473bd7645ff205",
      "92253243f3471651d425293dfe382cb9017fe15fc46b1deb79e561f5a38f7242",
      "70e3043d088ec7ebe970529cd9ae6f90c9e04ce4c71f883b1f73b3e6cb2202b3",
      "4c7c4f90f6afef5fedce6ee64bc99e11485d49548fcf0b5fbb37b4d0611522f9",
      "51734be9d97e86521cb3f9d9d57edc01aa06c28e6359b6f917e40776445979e736e1efe840b5dbc3deed3afdd93cfd43b3debdfe3c0efc256dc3a22154bd032d" },
    { // SHA256("key6") / SHA256("msg6")
      "8dfad052fee5c62957d3ebe1752219a02f45634b2c32a6ac408b26ffcedfb7da",
      "cd682266d91f196c09590f35c003fa8aaf01321dcb8cb675c6bc1d70c5b6822b",
      "4141a1ef664b76572adc99eb6a57c927aef4b84e37441338b0eb0f698aa74242",
      "f3a0b00ca1df74816c6252d6b54cbf4524d9063268431881e10e80d06026e423",
      "0c1b442a8bca3ce72affffea110e62bafdf2aabacdb1bf36a106de5a175b4c563d1cb666e93aa9e65ae26a760a5d3c569df8f745bd6c7f8566c25df3024a0f75" },
    { // SHA256("key7") / SHA256("msg7")
      "1e3f92d0f678eb83b0bf93855d90699d8ae5dfb4ae023bdf352bd8d93f2060b1",
      "f6bca2ea669a35112ab2a8292f5a88c675cc265e0b7af2e0ae1b9fe080be108f",
      "732beac3f258cf9d0f3a372e1dd7fe507707b137600953cfd53211b69a08f969",
      "c4da0b301d1baf48f537b75ddac333079944dbaef63fee21d4ff83154dad4efe",
      "f655371c9fb5d011fc5404a76b283415cc1938c23319f47cb90cb9b584b898cc766e2f165f327278d91bd77f9583b24e599b355617ba7600ebda14b9da28c6db" },
    { // SHA256("key8") / SHA256("msg8")
      "5bda7a9c0fb9e5102411342f9bedf63f37d8835ee6e903e95dd3050fd15af81c",
      "231cf49d59380f36c61d1a7b53e95b2cc337bb1c13a935a1e81951e22d248c43",
      "c8a20fe0d0ffa89561717ba19863df4a6cd37ab7f284fac30b4d5677becb5927",
      "e58dff892acab580bc92cda66b44345a9fc45aae370d15eb684dc0c8df6bb79d",
      "7f9e5751fece09c949462a80951a76deb181556815153c657cbccdd5af2015a23825c46eff40c838e05a63662976ce1d173714edc12d105d3d0c2685f9caf3f1" },
};
static constexpr int kNumVectors =
    static_cast<int>(sizeof(kVectors) / sizeof(kVectors[0]));

// p == 3 (mod 4), so sqrt(y)^2 == y exactly when y is a quadratic residue.
// That equivalence IS the Jacobi test the specification names.
static bool jacobi_is_one(const FieldElement& y) {
    if (y == FieldElement::zero()) return false;   // Jacobi(0) == 0, never 1
    FieldElement const root = y.sqrt();
    return root.square() == y;
}

// e = SHA256(r[32] || P_compressed[33] || msg[32]), the spec's challenge hash.
static Scalar challenge(const std::uint8_t* r32, const Point& P,
                         const std::uint8_t* msg32) {
    std::uint8_t pcomp[33];
    auto const px = P.x().to_bytes();
    pcomp[0] = (P.y().limbs()[0] & 1u) ? 0x03 : 0x02;
    std::memcpy(pcomp + 1, px.data(), 32);

    secp256k1::SHA256 h;
    h.update(r32, 32);
    h.update(pcomp, 33);
    h.update(msg32, 32);
    auto const digest = h.finalize();
    return Scalar::from_bytes(digest);
}

int test_regression_bch_schnorr_spec_run() {
    std::printf("======================================================================\n");
    std::printf("  Regression: Bitcoin Cash 2019 Schnorr specification conformance\n");
    std::printf("  (1) Jacobi(R.y) == 1   (2) RFC6979 algo16 \"Schnorr+SHA256  \"\n");
    std::printf("======================================================================\n");

    const secp256k1_context* const ctx = bch_ctx();

    // ---- (1) known-answer vectors from the independent oracle ----------
    // Byte-for-byte. Anything short of that means our nonce stream is not the
    // one BCHN and Libauth derive, which is exactly what bug (2) was.
    std::printf("\n--- (1) signatures are byte-identical to the spec oracle ---\n");
    {
        int identical = 0, verified = 0, residue = 0;
        for (int i = 0; i < kNumVectors; ++i) {
            const BchVector& v = kVectors[i];
            std::uint8_t sk[32], msg[32], want[64], got[64];
            if (!from_hex(v.seckey, sk, 32) || !from_hex(v.msg, msg, 32) ||
                !from_hex(v.sig, want, 64)) {
                check(false, "vector hex decodes");
                continue;
            }
            std::memset(got, 0, sizeof(got));
            if (secp256k1_schnorr_sign(ctx, got, msg, sk, nullptr, nullptr) != 1) {
                check(false, "secp256k1_schnorr_sign succeeds on a valid key");
                continue;
            }
            if (std::memcmp(got, want, 64) == 0) ++identical;

            // The pubkey blob layout is [x:32][y:32], big-endian, as produced by
            // secp256k1_ec_pubkey_create.
            std::uint8_t pxb[32], pyb[32];
            from_hex(v.pub_x, pxb, 32);
            from_hex(v.pub_y, pyb, 32);
            secp256k1_pubkey pk{};
            std::memcpy(pk.data, pxb, 32);
            std::memcpy(pk.data + 32, pyb, 32);
            if (secp256k1_schnorr_verify(ctx, got, msg, &pk) == 1) ++verified;

            // R.y of the signature we just produced must be a residue. Recover R
            // from the verification equation rather than trusting the signer.
            std::array<std::uint8_t, 32> xb{}, yb{};
            std::memcpy(xb.data(), pxb, 32);
            std::memcpy(yb.data(), pyb, 32);
            Point const P = Point::from_affine(FieldElement::from_bytes(xb),
                                                FieldElement::from_bytes(yb));
            Scalar s;
            if (!Scalar::parse_bytes_strict(got + 32, s)) continue;
            Scalar const e = challenge(got, P, msg);
            Point const R = Point::dual_scalar_mul_gen_point(s, e.negate(), P);
            if (!R.is_infinity() && jacobi_is_one(R.y())) ++residue;
        }
        check(identical == kNumVectors,
              "every signature is byte-identical to the independent oracle");
        check(verified == kNumVectors, "every oracle vector verifies");
        check(residue == kNumVectors, "every produced R.y is a quadratic residue");
        std::printf("  %d/%d byte-identical, %d/%d verify, %d/%d residue R.y\n",
                    identical, kNumVectors, verified, kNumVectors,
                    residue, kNumVectors);
    }

    // ---- (2) the twin signature must be REJECTED -----------------------
    // For a valid (r, s) built from nonce k, the value s' = 2*e*d - s is the
    // signature the SAME r would carry under nonce -k -- the point -R. Exactly
    // one of R and -R has a residue Y, so a spec-conformant verifier accepts
    // exactly one of (r, s) and (r, s'). A verifier missing the Jacobi check
    // accepts BOTH, which is what this engine did: it is the direct negative
    // control for bug (1), and it fails loudly if the check is ever removed.
    std::printf("\n--- (2) the -R twin of a valid signature is rejected ---\n");
    {
        int rejected = 0, accepted_original = 0;
        for (int i = 0; i < kNumVectors; ++i) {
            const BchVector& v = kVectors[i];
            std::uint8_t sk[32], msg[32], sig[64];
            from_hex(v.seckey, sk, 32);
            from_hex(v.msg, msg, 32);
            if (secp256k1_schnorr_sign(ctx, sig, msg, sk, nullptr, nullptr) != 1) continue;

            std::uint8_t pxb[32], pyb[32];
            from_hex(v.pub_x, pxb, 32);
            from_hex(v.pub_y, pyb, 32);
            secp256k1_pubkey pk{};
            std::memcpy(pk.data, pxb, 32);
            std::memcpy(pk.data + 32, pyb, 32);
            if (secp256k1_schnorr_verify(ctx, sig, msg, &pk) == 1) ++accepted_original;

            std::array<std::uint8_t, 32> xb{}, yb{};
            std::memcpy(xb.data(), pxb, 32);
            std::memcpy(yb.data(), pyb, 32);
            Point const P = Point::from_affine(FieldElement::from_bytes(xb),
                                                FieldElement::from_bytes(yb));
            Scalar d;
            if (!Scalar::parse_bytes_strict_nonzero(sk, d)) continue;
            Scalar s;
            if (!Scalar::parse_bytes_strict(sig + 32, s)) continue;

            Scalar const e  = challenge(sig, P, msg);
            Scalar const ed = e * d;
            Scalar const s_twin = (ed + ed) - s;          // 2ed - s  =  -k + ed

            std::uint8_t twin[64];
            std::memcpy(twin, sig, 32);                    // same r
            auto const tb = s_twin.to_bytes();
            std::memcpy(twin + 32, tb.data(), 32);

            if (secp256k1_schnorr_verify(ctx, twin, msg, &pk) == 0) ++rejected;
        }
        check(accepted_original == kNumVectors, "the original signature verifies");
        check(rejected == kNumVectors,
              "the -R twin (same r, s = 2ed - s) is rejected by the verifier");
        std::printf("  %d/%d twins rejected, %d/%d originals accepted\n",
                    rejected, kNumVectors, accepted_original, kNumVectors);
    }

    // ---- (3) the nonce stream is domain-separated from ECDSA -----------
    // If the algo16 tag were dropped again, the BCH nonce would collapse onto
    // the ECDSA nonce for the same (key, message) and r would change. Pinning
    // the r bytes from the oracle already catches that, but state it directly:
    // signing is deterministic and stable across calls.
    std::printf("\n--- (3) signing is deterministic across repeated calls ---\n");
    {
        int stable = 0;
        for (int i = 0; i < kNumVectors; ++i) {
            std::uint8_t sk[32], msg[32], a[64], b[64];
            from_hex(kVectors[i].seckey, sk, 32);
            from_hex(kVectors[i].msg, msg, 32);
            if (secp256k1_schnorr_sign(ctx, a, msg, sk, nullptr, nullptr) != 1) continue;
            if (secp256k1_schnorr_sign(ctx, b, msg, sk, nullptr, nullptr) != 1) continue;
            if (std::memcmp(a, b, 64) == 0) ++stable;
        }
        check(stable == kNumVectors, "same (key, message) yields the same signature");
        std::printf("  %d/%d deterministic\n", stable, kNumVectors);
    }

    // ---- (4) the BCH nonce stream must not collide with ECDSA's ---------
    // This is why the algo16 tag is a security control and not a formatting
    // detail. Before the fix the shim called rfc6979_nonce(d, msg) -- the very
    // function, with the very arguments, that ct::ecdsa_sign uses. Signing the
    // same 32-byte message with the same key under both schemes therefore used
    // ONE nonce twice, across two different equations:
    //
    //     ECDSA    s1 = k^-1 (z + r*d)
    //     Schnorr  s2 = k + e*d
    //     =>       d  = (s1*s2 - z) / (r + s1*e)   mod n
    //
    // Two unknowns, two equations, and both signatures are public: the private
    // key falls out. Measured against the pre-fix shim, 16 of 16 keys were
    // recovered from their own signature pairs.
    //
    // The cheap, total observable is r: with a shared nonce, the Schnorr r and
    // the ECDSA r are the same point's X coordinate. They must differ.
    std::printf("\n--- (4) BCH nonce is domain-separated from the ECDSA nonce ---\n");
    {
        int distinct = 0;
        for (int i = 0; i < kNumVectors; ++i) {
            std::uint8_t sk[32], msg[32], sig[64];
            from_hex(kVectors[i].seckey, sk, 32);
            from_hex(kVectors[i].msg, msg, 32);
            if (secp256k1_schnorr_sign(ctx, sig, msg, sk, nullptr, nullptr) != 1) continue;

            Scalar d;
            if (!Scalar::parse_bytes_strict_nonzero(sk, d)) continue;
            std::array<std::uint8_t, 32> m{};
            std::memcpy(m.data(), msg, 32);
            auto const es = secp256k1::ct::ecdsa_sign(m, d);
            auto const ecdsa_r = es.r.to_bytes();

            // Equal r means one nonce served both signatures.
            if (std::memcmp(sig, ecdsa_r.data(), 32) != 0) ++distinct;
        }
        check(distinct == kNumVectors,
              "BCH Schnorr r != ECDSA r for the same key and message (no shared nonce)");
        std::printf("  %d/%d distinct nonces\n", distinct, kNumVectors);
    }

    std::printf("\n[regression_bch_schnorr_spec] %d/%d checks passed\n",
                g_pass, g_pass + g_fail);
    return (g_fail > 0) ? 1 : 0;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_bch_schnorr_spec_run(); }
#endif
