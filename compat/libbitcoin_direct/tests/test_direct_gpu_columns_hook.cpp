// Runtime provider/hook smoke for the libbitcoin direct GPU-accelerated column
// verify path. This test lives IN the libbitcoin direct profile itself (not the
// C ABI audit path) so the direct-GPU opt-in profile carries its own acceptance
// smoke, visible in `ctest -N` / target help as `lbtc_direct_gpu_columns_hook`.
//
// It asserts the engine's GpuColumnsVerifyHook AND its sibling
// GpuColumnsAvailableHook (caller-visible discovery, ufsecp::lbtc::gpu_available())
// are self-installed at process startup — BEFORE this test installs any double —
// by the GPU-host self-installer (EngineGpuColumnsInstaller in secp256k1_gpu_host),
// which this executable retains at link via the targeted
// `--undefined=secp256k1_gpu_columns_provider_anchor` anchor. A null hook here
// means that provider object was dropped at link and "transparent GPU column
// verify" (and the availability query) silently degraded to CPU-only — exactly
// what this smoke guards. It then runs a small valid column batch through the
// unified engine call (GPU when a device exists, transparent CPU fallback
// otherwise) and a tampered-row fail-closed check — all through the ONE
// caller-visible verify API, with no CPU/GPU split and no caller-visible GPU
// status; the availability query is a separate, narrower discovery-only check
// (see GpuColumnsAvailableHook in secp256k1/batch_verify.hpp).
//
// Build: linked only in the SECP256K1_BUILD_LIBBITCOIN_GPU profile with a GPU
// backend compiled (see compat/libbitcoin_direct/CMakeLists.txt). Returns 0 on
// success, 1 on any failure.
//
// Test-data generation uses CT-backed ufsecp::lbtc::* entrypoints so this file
// emits no deprecated non-CT signing/keypair warnings.
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "secp256k1/batch_verify.hpp"

#include "gpu_backend.hpp"
#include "ufsecp/libbitcoin.hpp"

namespace {
std::uint64_t g_xs = 0x243F6A8885A308D3ull;
std::uint8_t nb() { g_xs ^= g_xs << 13; g_xs ^= g_xs >> 7; g_xs ^= g_xs << 17; return static_cast<std::uint8_t>(g_xs); }
int fails = 0;
void check(bool cond, const char* what) { if (!cond) { std::printf("FAIL: %s\n", what); ++fails; } }

// Generate a valid random secret key (CT-backed via ufsecp::lbtc::seckey_verify).
void rand_sk(std::uint8_t sk[32]) {
    do { for (int i = 0; i < 32; ++i) sk[i] = nb(); } while (!ufsecp::lbtc::seckey_verify(sk));
}

secp256k1::gpu::DeviceInfo device(std::uint32_t compute_units, bool host_unified_memory) {
    secp256k1::gpu::DeviceInfo info{};
    info.compute_units = compute_units;
    info.host_unified_memory = host_unified_memory;
    return info;
}

// The hook initializes the preferred device, not the first enumerated one.
void check_preferred_device() {
    using secp256k1::gpu::preferred_device;
    check(preferred_device(nullptr, 0) == 0, "preferred device of none is 0");
    const secp256k1::gpu::DeviceInfo one[] = { device(8, true) };
    check(preferred_device(one, 1) == 0, "preferred device of one is 0");
    const secp256k1::gpu::DeviceInfo integrated_first[] = { device(96, true), device(28, false) };
    check(preferred_device(integrated_first, 2) == 1, "discrete preferred over integrated with more units");
    const secp256k1::gpu::DeviceInfo discrete[] = { device(28, false), device(64, false), device(40, false) };
    check(preferred_device(discrete, 3) == 1, "most compute units among discrete");
    const secp256k1::gpu::DeviceInfo tied[] = { device(64, false), device(64, false) };
    check(preferred_device(tied, 2) == 0, "tie resolves to first enumerated");
    const secp256k1::gpu::DeviceInfo integrated[] = { device(24, true), device(32, true) };
    check(preferred_device(integrated, 2) == 1, "most compute units among integrated");
}
} // namespace

int main() {
    // (1) STARTUP ASSERTION — read BEFORE any test double touches the hook.
    // Non-destructive read: swap the installed hook out to null, capturing it, then
    // restore it immediately. The GPU-host installer runs at load, before main, so a
    // non-null capture proves the provider TU is linked and self-installed.
    secp256k1::GpuColumnsVerifyHook startup_hook =
        secp256k1::install_gpu_columns_verify_hook(nullptr);
    secp256k1::install_gpu_columns_verify_hook(startup_hook);  // restore immediately
    check(startup_hook != nullptr,
          "GpuColumnsVerifyHook self-installed at startup by secp256k1_gpu_host (provider TU retained)");

    // (1b) Same startup assertion for the sibling availability-query hook: it
    // installs in the SAME constructor as the verify hook above, so a non-null
    // capture here is just as much a proof the provider TU is retained. This also
    // exercises the ufsecp::lbtc::gpu_available() call site libbitcoin-direct
    // callers are meant to use before marshalling a batch.
    secp256k1::GpuColumnsAvailableHook startup_available_hook =
        secp256k1::install_gpu_available_query_hook(nullptr);
    secp256k1::install_gpu_available_query_hook(startup_available_hook);  // restore immediately
    check(startup_available_hook != nullptr,
          "GpuColumnsAvailableHook self-installed at startup by secp256k1_gpu_host (provider TU retained)");
    check(secp256k1::gpu_columns_available() == ufsecp::lbtc::gpu_available(),
          "secp256k1::gpu_columns_available() and ufsecp::lbtc::gpu_available() agree");

    auto startup_bip352_hook = ufsecp::lbtc::gpu_hook::install_lbtc_bip352_hook(nullptr);
    ufsecp::lbtc::gpu_hook::install_lbtc_bip352_hook(startup_bip352_hook);
    check(startup_bip352_hook != nullptr, "BIP-352 hook self-installed at startup by secp256k1_gpu_host");
    auto startup_bip352_columns_hook = ufsecp::lbtc::gpu_hook::install_lbtc_bip352_columns_hook(nullptr);
    ufsecp::lbtc::gpu_hook::install_lbtc_bip352_columns_hook(startup_bip352_columns_hook);
    check(startup_bip352_columns_hook != nullptr,
          "column BIP-352 hook self-installed at startup by secp256k1_gpu_host");

    if (ufsecp::lbtc::gpu_available()) {
        const std::array<std::uint8_t, 32> scan{{0x0f, 0x69, 0x4e, 0x06, 0x80, 0x28, 0xa7, 0x17, 0xf8, 0xaf, 0x6b,
                                                 0x94, 0x11, 0xf9, 0xa1, 0x33, 0xdd, 0x35, 0x65, 0x25, 0x87, 0x14,
                                                 0xcc, 0x22, 0x65, 0x94, 0xb3, 0x4d, 0xb9, 0x0c, 0x1f, 0x2c}};
        const std::array<std::uint8_t, 33> spend{{0x02, 0x5c, 0xc9, 0x85, 0x6d, 0x6f, 0x83, 0x75, 0x35, 0x0e, 0x12,
                                                  0x39, 0x78, 0xda, 0xac, 0x20, 0x0c, 0x26, 0x0c, 0xb5, 0xb5, 0xae,
                                                  0x83, 0x10, 0x6c, 0xab, 0x90, 0x48, 0x4d, 0xcd, 0x8f, 0xcf, 0x36}};
        const std::array<std::uint8_t, 33> point{{0x02, 0x4a, 0xc2, 0x53, 0xc2, 0x16, 0x53, 0x2e, 0x96, 0x19, 0x88,
                                                  0xe2, 0xa8, 0xce, 0x26, 0x6a, 0x44, 0x7c, 0x89, 0x4c, 0x78, 0x1e,
                                                  0x52, 0xef, 0x6c, 0xee, 0x90, 0x23, 0x61, 0xdb, 0x96, 0x00, 0x04}};
        std::uint64_t prefix{};
        check(ufsecp::lbtc::bip352_scan_prefixes(scan.data(), spend.data(), 1, point.data(), 1, &prefix),
              "BIP-352 reference prefix");

        // The common scan above may use OpenCL or Metal; CUDA timings only
        // apply when a CUDA device is present as well.
        if (secp256k1::gpu::is_available(1)) {
            auto backend = secp256k1::gpu::create_backend(1);
            check(backend != nullptr, "CUDA backend creation");
            if (backend) {
                check(backend->init(0) == secp256k1::gpu::GpuError::Ok, "CUDA backend initialization");
                secp256k1::gpu::GpuBackend::TimingBreakdownMs timing{};
                std::uint64_t timed_prefix{};
                check(backend->bip352_scan_batch_multispend_timed(scan.data(), spend.data(), 1, point.data(), 1,
                                                                  &timed_prefix, &timing) == secp256k1::gpu::GpuError::Ok,
                      "BIP-352 timed scan");
                check(timed_prefix == prefix, "BIP-352 timed scan result");
                check(timing.setup_ms > 0.0 && timing.h2d_ms > 0.0 && timing.kernel_ms > 0.0 && timing.d2h_ms > 0.0,
                      "BIP-352 CUDA event timings");
            }
        }

        const std::array<std::uint32_t, 3> correlates{{7, 7, 8}};
        std::array<std::uint8_t, 24> prefixes{};
        for (int byte = 0; byte < 8; ++byte)
            prefixes[8 + byte] = static_cast<std::uint8_t>(prefix >> (56 - byte * 8));
        std::array<std::uint8_t, 99> points{};
        std::memcpy(points.data(), point.data(), point.size());
        std::memcpy(points.data() + 33, point.data(), point.size());
        std::memcpy(points.data() + 66, point.data(), point.size());
        std::array<std::uint8_t, 3> matches{};
        check(ufsecp::lbtc::bip352_scan_columns(scan.data(), spend.data(), 1,
                                                reinterpret_cast<const std::uint8_t*>(correlates.data()),
                                                prefixes.data(), points.data(), 3, matches.data()),
              "BIP-352 column scan");
        check(matches[0] == 1 && matches[1] == 0 && matches[2] == 0, "BIP-352 column group matches");

        // A matching spend must not conceal a malformed spend later in the
        // same transaction. Compare the accelerated path with the CPU path in
        // both orders; the all-zero compressed key is invalid.
        const std::array<std::uint8_t, 8> expected_prefix{{0x3e, 0x9f, 0xce, 0x73, 0xd4, 0xe7, 0x7a, 0x48}};
        for (int valid_index = 0; valid_index < 2; ++valid_index) {
            std::array<std::uint8_t, 66> ordered_spends{};
            std::memcpy(ordered_spends.data() + valid_index * 33, spend.data(), spend.size());
            std::uint8_t cpu_match = 0xff;
            check(!ufsecp::lbtc::bip352_scan_columns(scan.data(), ordered_spends.data(), 2,
                                                     reinterpret_cast<const std::uint8_t*>(correlates.data()),
                                                     expected_prefix.data(), point.data(), 1, &cpu_match, 1),
                  "BIP-352 CPU rejects invalid spend in either order");
            check(cpu_match == 0, "BIP-352 CPU invalid spend clears match");
            std::uint8_t gpu_match = 0xff;
            check(!ufsecp::lbtc::bip352_scan_columns(scan.data(), ordered_spends.data(), 2,
                                                     reinterpret_cast<const std::uint8_t*>(correlates.data()),
                                                     expected_prefix.data(), point.data(), 1, &gpu_match),
                  "BIP-352 GPU rejects invalid spend in either order");
            check(gpu_match == 0, "BIP-352 GPU invalid spend clears match");
        }

        secp256k1::fast::Scalar scan_scalar;
        secp256k1::fast::Point input_point;
        check(secp256k1::fast::Scalar::parse_bytes_strict_nonzero(scan.data(), scan_scalar) &&
                  ufsecp::lbtc::detail::decompress(point.data(), input_point),
              "BIP-352 infinity fixture parse");
        const auto shared = input_point.scalar_mul(scan_scalar);
        auto serialized = shared.to_compressed();
        std::array<std::uint8_t, 37> tagged_input{};
        std::memcpy(tagged_input.data(), serialized.data(), serialized.size());
        const auto hash = secp256k1::tagged_hash("BIP0352/SharedSecret", tagged_input.data(), tagged_input.size());
        secp256k1::fast::Scalar tweak;
        check(secp256k1::fast::Scalar::parse_bytes_strict(hash.data(), tweak), "BIP-352 infinity fixture tweak");
        const auto inverse = secp256k1::fast::Point::generator().scalar_mul(tweak).negate().to_compressed();
        std::array<std::uint8_t, 66> spends{};
        std::memcpy(spends.data(), inverse.data(), inverse.size());
        std::memcpy(spends.data() + 33, spend.data(), spend.size());
        matches.fill(0);
        check(!ufsecp::lbtc::bip352_scan_columns(scan.data(), spends.data(), 2,
                                                 reinterpret_cast<const std::uint8_t*>(correlates.data()),
                                                 prefixes.data(), points.data(), 3, matches.data()),
              "BIP-352 infinity candidate rejected");
        check(matches[0] == 0, "BIP-352 infinity candidate fails closed");

        points[33] ^= 1;
        check(!ufsecp::lbtc::bip352_scan_columns(scan.data(), spend.data(), 1,
                                                 reinterpret_cast<const std::uint8_t*>(correlates.data()),
                                                 prefixes.data(), points.data(), 3, matches.data()),
              "BIP-352 mismatched group rejected");
    }

    check_preferred_device();

    // (2) Transparent accelerated path: a small valid ECDSA + Schnorr column batch
    // through the unified engine surface. With the hook installed the engine
    // dispatches to the GPU backend when a device exists and transparently falls
    // back to CPU otherwise; the caller sees ONE API and all-valid results either way.
    constexpr int N = 256;
    std::vector<std::uint8_t> cd(N * 32), cp(N * 33), cs(N * 64);  // ecdsa digests/pubkeys/sigs
    std::vector<std::uint8_t> sx(N * 32), ss(N * 64);              // schnorr xonly/sigs (shares cd digests)
    std::uint8_t aux[32]{};
    for (int i = 0; i < N; ++i) {
        std::uint8_t sk[32], msg[32], pub33[33], esig[64], xonly[32], ssig[64];
        rand_sk(sk);
        for (int j = 0; j < 32; ++j) msg[j] = nb();
        check(ufsecp::lbtc::pubkey_create(sk, pub33), "smoke ecdsa pubkey_create");   // CT-backed
        check(ufsecp::lbtc::ecdsa_sign(msg, sk, esig), "smoke ecdsa_sign");           // CT-backed
        std::memcpy(cd.data() + i * 32, msg, 32);
        std::memcpy(cp.data() + i * 33, pub33, 33);
        std::memcpy(cs.data() + i * 64, esig, 64);
        check(ufsecp::lbtc::schnorr_keypair_create(sk, xonly), "smoke schnorr keypair_create");  // CT-backed
        check(ufsecp::lbtc::schnorr_sign(xonly, sk, msg, aux, ssig), "smoke schnorr_sign");      // CT-backed
        std::memcpy(sx.data() + i * 32, xonly, 32);
        std::memcpy(ss.data() + i * 64, ssig, 64);
    }
    std::vector<std::uint8_t> er(N, 0), sr(N, 0);
    check(secp256k1::ecdsa_batch_verify_opaque_columns(cd.data(), cp.data(), cs.data(), N, er.data(), 0),
          "engine ecdsa columns all-valid via installed hook");
    { long ok = 0; for (auto v : er) ok += v; check(ok == N, "ecdsa columns per-row all-valid"); }
    check(secp256k1::schnorr_batch_verify_bip340_columns(cd.data(), sx.data(), ss.data(), N, sr.data(), 0),
          "engine schnorr columns all-valid via installed hook");
    { long ok = 0; for (auto v : sr) ok += v; check(ok == N, "schnorr columns per-row all-valid"); }

    // (3) Fail-closed through the same accelerated path: tamper one row.
    cs[13 * 64] ^= 1;
    std::vector<std::uint8_t> er2(N, 0);
    check(!secp256k1::ecdsa_batch_verify_opaque_columns(cd.data(), cp.data(), cs.data(), N, er2.data(), 0),
          "engine ecdsa columns fail-closed on tamper via installed hook");
    check(er2[13] == 0, "ecdsa tampered row marked invalid");

    if (fails == 0)
        std::printf("test_direct_gpu_columns_hook: ALL PASS (hook installed at startup + transparent columns + fail-closed)\n");
    return fails == 0 ? 0 : 1;
}
