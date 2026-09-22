// ============================================================================
// REGRESSION: secp256k1::release_process_resources() actually releases, and the
// library still works afterwards.
//
// GitHub issue #430 (evoskuil, libbitcoin): linking this library into an MSVC
// debug-CRT build makes the CRT leak detector report 259 blocks / ~1.32 MB live at
// process exit -- the fused dual-mul generator tables (1,310,720 bytes, built on the
// first verify that needs them) plus the batch worker pool, its thread vector and the
// workers' thread_local state. One-time and bounded, not accumulating, but
// indistinguishable from a real leak in CRT and sanitizer output, and the pool keeps OS
// threads alive to process exit.
//
// The retention itself is deliberate and stays the default: an immortal table has no
// static-destruction-order hazard, and the pool deliberately has NO automatic
// destruction because its destructor joins threads, which deadlocks if it runs while
// the Windows loader lock is held during DLL unload. What was missing was a way for the
// embedder to hand the memory back on a thread THEY choose. That is
// release_process_resources().
//
// Two ways this fix could be wrong, and the checks that catch each:
//
//   It could not release.        PRR-3 asserts process_resources_active() is false
//                                after the call. Stub release_process_resources() to a
//                                no-op and PRR-3 goes red.
//
//   It could release and leave   PRR-5 recomputes a*G + b*P through the exact code path
//   the library broken, or       that owns the freed table and requires the result to be
//   rebuild a corrupt table.     byte-identical to the pre-release answer AND equal to
//                                the same product computed through an independent path
//                                (two separate scalar_muls). A rebuild that is merely
//                                self-consistent still fails the independent leg.
//
// Checks:
//   PRR-1  release on an already-released library is a no-op; active() is false.
//          (The module releases first so it has a known starting state whether it runs
//          standalone or after other modules in unified_audit_runner.)
//   PRR-2  using the library makes active() true.
//   PRR-3  after release, active() is false.
//   PRR-4  a second release back-to-back is a no-op and does not crash.
//   PRR-5  re-running the same work after a release gives the identical answer, and
//          that answer is independently correct.
//   PRR-6  release -> use -> release -> use survives repetition, not just one cycle.
// ============================================================================

#ifndef UNIFIED_AUDIT_RUNNER
#ifndef STANDALONE_TEST
#define STANDALONE_TEST
#endif
#endif

#include "secp256k1/process_resources.hpp"
#include "secp256k1/batch_verify.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/schnorr.hpp"
#include "ufsecp.h"   // PRR-7: the C ABI wrapper embedders actually reach this through

#include <array>
#include <cstdint>
#include <cstdio>
#include <vector>

using namespace secp256k1;
using fast::Point;
using fast::Scalar;

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

namespace {

// Fixed inputs. Nothing here is random: a rebuild fault must not be able to pass by
// drawing a different sample.
constexpr std::uint64_t kScalarA = 0x0123456789abcdefULL;
constexpr std::uint64_t kScalarB = 0xfedcba9876543210ULL;
constexpr std::uint64_t kBaseKey = 0x00000000deadbeefULL;

// a*G + b*P through Point::dual_scalar_mul_gen_point -- the function that owns the
// generator tables release_process_resources() frees. This is the probe: it is the one
// call whose answer depends on the freed memory being correctly rebuilt.
std::array<std::uint8_t, 65> dual_mul_probe() {
    Scalar const a = Scalar::from_uint64(kScalarA);
    Scalar const b = Scalar::from_uint64(kScalarB);
    Point const  P = Point::generator().scalar_mul(Scalar::from_uint64(kBaseKey));
    return Point::dual_scalar_mul_gen_point(a, b, P).to_uncompressed();
}

// The same product computed WITHOUT the fused path: two independent scalar
// multiplications and one addition. This is the known answer -- if the rebuilt table
// were corrupt but internally consistent, dual_mul_probe() would keep agreeing with
// itself and only this leg would catch it.
std::array<std::uint8_t, 65> independent_probe() {
    Scalar const a = Scalar::from_uint64(kScalarA);
    Scalar const b = Scalar::from_uint64(kScalarB);
    Point const  P = Point::generator().scalar_mul(Scalar::from_uint64(kBaseKey));
    return Point::generator().scalar_mul(a).add(P.scalar_mul(b)).to_uncompressed();
}

// A Schnorr batch large enough to take the _mt path, so the worker pool is created.
std::vector<SchnorrBatchEntry> make_schnorr_batch(std::size_t n) {
    std::vector<SchnorrBatchEntry> e(n);
    for (std::size_t i = 0; i < n; ++i) {
        Scalar const sk = Scalar::from_uint64(kBaseKey + i);
        SchnorrKeypair const kp = schnorr_keypair_create(sk);
        std::array<std::uint8_t, 32> msg{};
        std::array<std::uint8_t, 32> aux{};
        for (int b = 0; b < 8; ++b) {
            msg[static_cast<std::size_t>(b)] =
                static_cast<std::uint8_t>((i >> (b * 8)) & 0xff);
        }
        e[i].pubkey_x  = kp.px;
        e[i].message   = msg;
        e[i].signature = schnorr_sign(kp, msg, aux);
    }
    return e;
}

// Touch both retained surfaces: the generator tables (via the fused dual-mul) and the
// batch worker pool (via a multi-threaded Schnorr batch verify).
bool exercise_library(std::vector<SchnorrBatchEntry>& batch) {
    (void)dual_mul_probe();
    return schnorr_batch_verify_mt(batch.data(), batch.size(), 4);
}

}  // namespace

int test_regression_process_resource_release_run() {
    g_pass = 0; g_fail = 0;
    std::printf("======================================================================\n");
    std::printf("  Regression: release_process_resources() releases, and the library\n");
    std::printf("  keeps working afterwards (GitHub issue #430)\n");
    std::printf("======================================================================\n\n");

    // Known starting state. Under unified_audit_runner an earlier module has almost
    // certainly already built the tables and started the pool, so "false before first
    // use" is not assertable here -- "false after a release" is, and it is the property
    // that matters.
    release_process_resources();

    // PRR-1 -- releasing an already-released library changes nothing and does not crash.
    CHECK(!process_resources_active(),
          "PRR-1: active() is false after a release");
    release_process_resources();
    CHECK(!process_resources_active(),
          "PRR-1: releasing an already-released library is a no-op");

    // PRR-2 -- using the library builds the retained state back up.
    std::vector<SchnorrBatchEntry> batch = make_schnorr_batch(64);
    CHECK(exercise_library(batch),
          "PRR-2: the valid Schnorr batch verifies (the work the pool exists for)");
    std::array<std::uint8_t, 65> const before = dual_mul_probe();
    CHECK(before == independent_probe(),
          "PRR-2: a*G + b*P via the fused path equals the independent two-mul answer");
    CHECK(process_resources_active(),
          "PRR-2: active() is true once the tables are built and the pool is running");

    // PRR-3 -- the assertion the whole fix exists for.
    release_process_resources();
    CHECK(!process_resources_active(),
          "PRR-3: active() is false after release -- the tables are freed and the "
          "worker threads are joined, so a CRT/sanitizer leak check sees nothing");

    // PRR-4 -- idempotent from the used state too, not just the pristine one.
    release_process_resources();
    CHECK(!process_resources_active(),
          "PRR-4: a second release back-to-back is a no-op");

    // PRR-5 -- lazy re-initialisation rebuilds correctly, not just plausibly.
    std::array<std::uint8_t, 65> const after = dual_mul_probe();
    CHECK(after == before,
          "PRR-5: the rebuilt generator tables give a byte-identical a*G + b*P");
    CHECK(after == independent_probe(),
          "PRR-5: and that answer is independently correct, so a self-consistent but "
          "corrupt rebuild cannot pass");
    CHECK(process_resources_active(),
          "PRR-5: the probe rebuilt the released state rather than running on freed "
          "memory");

    // PRR-6 -- survives repetition. A release that half-tears-down tends to work once
    // and fail on the second round, so one cycle is not enough evidence.
    for (int round = 0; round < 2; ++round) {
        release_process_resources();
        CHECK(!process_resources_active(),
              "PRR-6: release is still clean on a repeated cycle");
        CHECK(exercise_library(batch),
              "PRR-6: the Schnorr batch still verifies on a freshly rebuilt pool");
        CHECK(dual_mul_probe() == before,
              "PRR-6: and the fused dual-mul still gives the same answer");
    }

    // PRR-7 -- the C ABI wrapper reaches the same machinery. A shim or C embedder cannot
    // call the C++ entry point, so if ufsecp_release_process_resources() were wired to
    // the wrong thing (or to nothing) the fix would not reach the caller who reported it.
    CHECK(exercise_library(batch),
          "PRR-7: library in use before the C ABI release");
    CHECK(process_resources_active(),
          "PRR-7: active() is true before the C ABI release");
    ufsecp_release_process_resources();
    CHECK(!process_resources_active(),
          "PRR-7: ufsecp_release_process_resources() releases the same state as the "
          "C++ entry point");
    ufsecp_release_process_resources();
    CHECK(!process_resources_active(),
          "PRR-7: the C ABI wrapper is idempotent too");
    CHECK(dual_mul_probe() == before,
          "PRR-7: and the library still computes the same answer after it");

    // Leave the process as we found it: rebuilt, so later modules in the unified runner
    // pay no surprise cold-start and see the library in its normal warm state.
    (void)dual_mul_probe();

    std::printf("\n[regression_process_resource_release] %d/%d checks passed\n",
                g_pass, g_pass + g_fail);
    return (g_fail > 0) ? 1 : 0;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_process_resource_release_run(); }
#endif
