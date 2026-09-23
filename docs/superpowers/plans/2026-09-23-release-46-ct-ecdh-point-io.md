# Release 4.6 CT ECDH and Point-IO Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep ECDH and shim bytes unchanged while removing the secret Jacobian-to-affine variable-time boundary, without a reproducible speed regression.

**Architecture:** Expose the existing internal Jacobian scalar-multiplication result without changing the public `Point` API. A private point-IO helper normalizes that result with constant-time field operations and emits fixed-size byte forms. ECDH and shim consume those bytes without converting through `Point`.

**Tech Stack:** C++20, CMake/Ninja, GCC 14 and Clang 17, Valgrind Memcheck, `bench_unified`.

**Spec:** `docs/superpowers/specs/2026-09-23-release-46-constant-time-boundaries-design.md` (ECDH and point-IO sections). The BIP352 and portable field sections require separate implementation plans.

## Global Constraints

- Preserve the public API/ABI, validation behavior, return codes, callback inputs, and all ECDH bytes.
- Native 5x52 and generic 4x64 paths must both compile; only claim CT for measured profiles.
- Do not call `CTJacobianPoint::to_point()`, `Point::x()`, `Point::to_compressed()`, or `Point::to_uncompressed()` on the secret-derived result in the repaired path.
- Correctness and non-regressing speed are both hard gates. A confirmed slowdown is optimized or reverted before release; a coarse CI smoke pass does not meet the speed gate.
- Benchmark the affected ECDH operations and representative engine suite on the same pinned host/compiler/flags with interleaved before/after runs. Retain the pre-change executable in a separate build directory.
- Implement tests before each production edit, observe the intended failure, then observe a pass. Commit each independently reviewable task.
- Keep PR #432 draft and do not merge or tag while this plan or its companion plans are incomplete.

## Review Focus

- Secret-result infinity: after full computation the helper emits an all-zero/invalid mask without branching on coordinates; Task 2 tests it.
- Non-affine Jacobian input: x/y/33-byte forms equal the public reference exactly; Task 2 tests it.
- Off-curve or infinity public peer and zero private scalar: existing ECDH rejection bytes remain unchanged; Task 3 tests them.
- Shim custom hash callback: it receives the same `x32` and `y32` and its return code survives; Task 3 tests it.
- Secret temporaries on early exits: `kb`, `sk`, raw Jacobian, `xy64`, and hash scratch are erased; Task 3 tests/inspects all paths.

---

### Task 0: Reproducible ECDH baseline harness

**Files:**
- Create: `compat/libsecp256k1_shim/bench/bench_ecdh_gate.cpp`
- Modify: `compat/libsecp256k1_shim/CMakeLists.txt` (register `bench_ecdh_gate` only when benchmarks are enabled)
- Modify: `src/cpu/bench/bench_unified.cpp` (add the missing x-only ECDH row before baseline capture)

**Interfaces:**
- Consumes: shim `secp256k1_ecdh` and existing `bench_unified`.
- Produces: a deterministic `bench_ecdh_gate` executable and retained baseline binaries/results under ignored `out/ct-ecdh-baseline`.

- [ ] **Step 1: Add measurement harnesses and record current speed.** Add `bench_ecdh_gate`, invoking default-hash `secp256k1_ecdh` on 32 deterministic valid scalar inputs against a fixed valid public key; warm up before timing, report ns/call, and retain a volatile output checksum. Register it only when `SECP256K1_BUILD_BENCH` is on. Add the missing `ecdh_compute_xonly` row to `bench_unified` beside its existing ECDH/raw rows. Build the current production code in `out/ct-ecdh-baseline` with Release, tests, shim, and benchmarks enabled; retain its executables and never rebuild that directory after the first production edit. The nested worktree breaks CMake's default relative libsecp path, so set `LIBSECP_SRC_DIR` explicitly. Run both full benchmarks, record CPU model/compiler/flags/affinity and ECDH plus whole-engine rows, then configure a separate candidate directory.

```cpp
#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdio>

int main() {
std::array<std::array<unsigned char, 32>, 32> keys{};
for (std::size_t i = 0; i < keys.size(); ++i)
    keys[i][31] = static_cast<unsigned char>(i + 1);
auto* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
if (ctx == nullptr) return 1;
secp256k1_pubkey pubkey{};
if (secp256k1_ec_pubkey_create(ctx, &pubkey, keys[0].data()) != 1)
    return 1;
unsigned char output[32]{};
volatile unsigned char sink = 0;
for (std::size_t i = 0; i < 1000; ++i)
    if (secp256k1_ecdh(ctx, output, &pubkey, keys[i % 32].data(), nullptr, nullptr) != 1)
        return 1;
auto const start = std::chrono::steady_clock::now();
for (std::size_t i = 0; i < 20000; ++i) {
    if (secp256k1_ecdh(ctx, output, &pubkey, keys[i % 32].data(), nullptr, nullptr) != 1)
        return 1;
    sink = static_cast<unsigned char>(sink ^ output[0]);
}
auto const elapsed = std::chrono::steady_clock::now() - start;
std::printf("shim ECDH %.2f ns/call, checksum=%u\n",
    std::chrono::duration<double, std::nano>(elapsed).count() / 20000.0,
    static_cast<unsigned>(sink));
secp256k1_context_destroy(ctx);
return 0;
}
```

```cmake
if(SECP256K1_BUILD_BENCH)
    add_executable(bench_ecdh_gate bench/bench_ecdh_gate.cpp)
    target_compile_features(bench_ecdh_gate PRIVATE cxx_std_20)
    target_link_libraries(bench_ecdh_gate PRIVATE secp256k1_shim)
endif()
```

```cpp
idx = 0;
double u_ecdh_xonly = bench_ns([&]() {
    auto s = ecdh_compute_xonly(privkeys[idx % POOL], pubkeys[(idx + 1) % POOL]);
    bench::DoNotOptimize(s); ++idx;
}, N_VERIFY);
print_row("ecdh_compute_xonly (SHA256 x-coordinate)", u_ecdh_xonly);
```

```bash
cmake -S . -B out/ct-ecdh-baseline -G Ninja -DCMAKE_BUILD_TYPE=Release -DSECP256K1_BUILD_TESTS=ON -DSECP256K1_BUILD_BENCH=ON -DSECP256K1_BUILD_SHIM=ON -DLIBSECP_SRC_DIR=/home/shrek/Secp256k1/_research_repos/secp256k1/src
cmake --build out/ct-ecdh-baseline --target bench_unified bench_ecdh_gate run_selftest shim_test -j 8
taskset -c 0 out/ct-ecdh-baseline/src/cpu/bench_unified --json out/ct-ecdh-baseline/baseline.json
taskset -c 0 out/ct-ecdh-baseline/compat/libsecp256k1_shim/bench_ecdh_gate
cmake -S . -B out/ct-ecdh-candidate -G Ninja -DCMAKE_BUILD_TYPE=Release -DSECP256K1_BUILD_TESTS=ON -DSECP256K1_BUILD_BENCH=ON -DSECP256K1_BUILD_SHIM=ON -DLIBSECP_SRC_DIR=/home/shrek/Secp256k1/_research_repos/secp256k1/src
```

- [ ] **Step 2: Verify the harness then commit it separately.** Require `bench_ecdh_gate` to return zero and print the same checksum on repeated runs; require the full benchmark JSON to contain all three ECDH rows. If `bench_unified` is absent, fix the `LIBSECP_SRC_DIR` configuration before any production edit.

```bash
git add compat/libsecp256k1_shim/bench/bench_ecdh_gate.cpp compat/libsecp256k1_shim/CMakeLists.txt src/cpu/bench/bench_unified.cpp
git commit -m "bench(ecdh): add reproducible shim baseline gate"
```

### Task 1: Internal Jacobian scalar-multiplication entry point

**Files:**
- Create: `src/cpu/include/secp256k1/detail/ct_point_internal.hpp`
- Modify: `src/cpu/src/ct_point.cpp` (the native `scalar_mul_jac` and both public `scalar_mul` branches)
- Create: `src/cpu/tests/test_ct_point_io.cpp`
- Modify: `src/cpu/CMakeLists.txt` (register `test_ct_point_io_standalone` / `ct_point_io`)

**Interfaces:**
- Consumes: `secp256k1::ct::CTJacobianPoint`, `fast::Point`, `fast::Scalar`.
- Produces: `secp256k1::ct::detail::scalar_mul_jacobian(const fast::Point&, const fast::Scalar&) noexcept -> CTJacobianPoint` in the internal header. The public `ct::scalar_mul(...) -> Point` signature does not change.

- [ ] **Step 1: Write a failing raw-output differential test.** The new standalone test compares `scalar_mul_jacobian(...).to_point()` with the existing public wrapper only in this public-data correctness test. Include scalars 1, 2, `n-1`, deterministic random valid scalars, and a non-affine public input.

```cpp
auto const peer = secp256k1::fast::Point::generator().dbl();
auto const key = secp256k1::fast::Scalar::from_uint64(17);
auto const raw = secp256k1::ct::detail::scalar_mul_jacobian(peer, key);
if (raw.to_point().to_compressed() !=
    secp256k1::ct::scalar_mul(peer, key).to_compressed()) return 1;
```

- [ ] **Step 2: Build the new test and verify the intended red state.** Register it as a standalone CTest target. The compiler must fail on the missing internal function, not on missing includes or unrelated code.

```cmake
add_executable(test_ct_point_io_standalone tests/test_ct_point_io.cpp)
target_link_libraries(test_ct_point_io_standalone PRIVATE ${SECP256K1_LIB_NAME})
add_test(NAME ct_point_io COMMAND test_ct_point_io_standalone)
```

```bash
cmake --build out/ct-ecdh-candidate --target test_ct_point_io_standalone -j 8
```

- [ ] **Step 3: Refactor, do not duplicate, the multiplication core.** In the native 5x52 branch, expose the existing `scalar_mul_jac` through the internal function. In the generic 4x64 branch, move the current fixed-pattern body into the same raw-returning internal function; leave the public wrapper as conversion plus its current declassification. Do not call the public wrapper from the raw function.

```cpp
namespace detail {
CTJacobianPoint scalar_mul_jacobian(const Point& p, const Scalar& k) noexcept {
#if defined(SECP256K1_FAST_52BIT) && !defined(SECP256K1_USE_4X64_POINT_OPS)
    return scalar_mul_jac(p, k);
#else
    return scalar_mul_jac_4x64(p, k);
#endif
}
} // namespace detail

Point scalar_mul(const Point& p, const Scalar& k) noexcept {
    CTJacobianPoint R = detail::scalar_mul_jacobian(p, k);
    Point result = R.to_point();
    SECP256K1_DECLASSIFY(&result, sizeof(result));
    return result;
}
```

For the generic branch, `scalar_mul_jac_4x64` is the current 4x64 `scalar_mul`
body moved without arithmetic edits: its last three lines become `return R;`
after `R.z = field_mul(R.z, global_z);`. The public wrapper above retains the
old `to_point()` and declassification behavior. The native branch calls the
already existing `scalar_mul_jac` body directly.

- [ ] **Step 4: Build and run red-to-green tests in native and forced portable configurations, then commit.** The test must cover all named scalar cases; existing `run_selftest` must remain green.

```bash
cmake --build out/ct-ecdh-candidate --target test_ct_point_io_standalone run_selftest -j 8
ctest --test-dir out/ct-ecdh-candidate -R '^ct_point_io$|^selftest$' --output-on-failure
cmake -S . -B out/ct-ecdh-portable -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS='-U__SIZEOF_INT128__ -DSECP256K1_NO_INT128=1' -DSECP256K1_USE_ASM=OFF -DSECP256K1_USE_LTO=OFF -DSECP256K1_BUILD_TESTS=ON -DSECP256K1_BUILD_BENCH=OFF
cmake --build out/ct-ecdh-portable --target test_ct_point_io_standalone run_selftest -j 8
ctest --test-dir out/ct-ecdh-portable -R '^ct_point_io$|^selftest$' --output-on-failure
git add src/cpu/include/secp256k1/detail/ct_point_internal.hpp src/cpu/src/ct_point.cpp src/cpu/tests/test_ct_point_io.cpp src/cpu/CMakeLists.txt
git commit -m "refactor(ct): expose internal Jacobian scalar result"
```

### Task 2: Fixed-size constant-time point serialization

**Files:**
- Create: `src/cpu/include/secp256k1/detail/ct_point_io.hpp`
- Modify: `src/cpu/tests/test_ct_point_io.cpp`
- Modify: `src/cpu/CMakeLists.txt` only if a separate taint target is required

**Interfaces:**
- Consumes: `CTJacobianPoint` from Task 1.
- Produces: `ct::detail::point_to_x32(const CTJacobianPoint&, std::array<std::uint8_t,32>&) noexcept`, `point_to_compressed33(const CTJacobianPoint&, std::array<std::uint8_t,33>&) noexcept`, and `point_to_xy64(const CTJacobianPoint&, std::array<std::uint8_t,64>&) noexcept`. Each returns an all-ones valid mask or zero. They do not allocate, hash, or convert through `Point`.

- [ ] **Step 1: Add failing byte-equivalence cases.** Compare all three serializers to `Point::generator()`, its double, and a non-affine multiple. Add infinity and `Z=0` cases asserting an invalid mask and zeroed output. Exercise native 5x52 and forced generic 4x64 configurations.

```cpp
auto p = secp256k1::fast::Point::generator().dbl();
auto jac = secp256k1::ct::CTJacobianPoint::from_point(p);
std::array<std::uint8_t, 33> bytes{};
auto mask = secp256k1::ct::detail::point_to_compressed33(jac, bytes);
if (mask != ~std::uint64_t{0} || bytes != p.to_compressed()) return 1;
auto inf = secp256k1::ct::CTJacobianPoint::make_infinity();
bytes.fill(0xa5);
mask = secp256k1::ct::detail::point_to_compressed33(inf, bytes);
if (mask != 0 || std::any_of(bytes.begin(), bytes.end(),
                             [](std::uint8_t b) { return b != 0; })) return 1;
```

- [ ] **Step 2: Run the test to verify it fails because the serializers are absent.**

```bash
cmake --build out/ct-ecdh-candidate --target test_ct_point_io_standalone -j 8
```

- [ ] **Step 3: Implement fixed-work normalization and serialization.** Compute `z^-1`, `z^-2`, and `z^-3` via `ct::field_inv/sqr/mul` (or FE52 operations backed by the CT inverse on native 5x52); normalize x/y and serialize in fixed loops. Build the valid mask from `infinity` and `Z==0` without a conditional branch; mask output bytes to zero on invalid input. On the generic profile, depend on the portable-field plan before claiming this path CT.

```cpp
// x, y, z are converted from FE52 to FieldElement only on the native path;
// on the generic path they already are FieldElement. Keep both conversions
// fixed-work and avoid Point methods.
auto const zi = secp256k1::ct::field_inv(z);
auto const zi2 = secp256k1::ct::field_sqr(zi);
auto const ax = secp256k1::ct::field_mul(x, zi2);
auto const valid = ~(p.infinity | secp256k1::ct::field_is_zero(z));
auto const xb = ax.to_bytes();
auto const keep = static_cast<std::uint8_t>(valid);
for (std::size_t i = 0; i < 32; ++i) out[i] = xb[i] & keep;
// For compressed33/xy64 also compute zi3=zi2*zi and ay=y*zi3;
// prefix is (0x02 | (yb[31] & 1)) & keep.
```

- [ ] **Step 4: Verify bytes and taint behavior.** Re-taint all raw coordinates and the infinity flag after raw multiplication, invoke each serializer under Valgrind with `SECP256K1_CT_VALGRIND=1`, and declassify only after serialization. The expected scoped result is zero conditional/memory errors on native 5x52. Keep generic CT claim deferred until the field plan passes.

```cpp
auto raw = secp256k1::ct::detail::scalar_mul_jacobian(peer, key);
SECP256K1_CLASSIFY(&raw, sizeof(raw));
std::array<std::uint8_t, 64> xy{};
auto valid = secp256k1::ct::detail::point_to_xy64(raw, xy);
SECP256K1_DECLASSIFY(&valid, sizeof(valid));
SECP256K1_DECLASSIFY(xy.data(), xy.size());
```

- [ ] **Step 5: Run the standalone test, Valgrind target, sanitizer build, and commit.** Build a dedicated marker-enabled Valgrind configuration; retain failing Valgrind output from the old conversion and passing output after the helper. A generic wrapper flag without the marker define is not evidence.

```bash
cmake --build out/ct-ecdh-candidate --target test_ct_point_io_standalone -j 8
ctest --test-dir out/ct-ecdh-candidate -R '^ct_point_io$' --output-on-failure
cmake -S . -B out/ct-ecdh-vg -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS=-DSECP256K1_CT_VALGRIND=1 -DSECP256K1_BUILD_TESTS=ON -DSECP256K1_BUILD_BENCH=OFF
cmake --build out/ct-ecdh-vg --target test_ct_point_io_standalone -j 8
valgrind --tool=memcheck --error-exitcode=99 out/ct-ecdh-vg/src/cpu/test_ct_point_io_standalone
cmake -S . -B out/ct-ecdh-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' -DSECP256K1_BUILD_TESTS=ON -DSECP256K1_BUILD_BENCH=OFF
cmake --build out/ct-ecdh-asan --target test_ct_point_io_standalone -j 8
ctest --test-dir out/ct-ecdh-asan -R '^ct_point_io$' --output-on-failure
git add src/cpu/include/secp256k1/detail/ct_point_io.hpp src/cpu/tests/test_ct_point_io.cpp src/cpu/CMakeLists.txt
git commit -m "feat(ct): serialize secret Jacobian points without Point conversion"
```

### Task 3: ECDH and shim wiring, differential tests, and performance gate

**Files:**
- Modify: `src/cpu/src/ecdh.cpp`
- Modify: `compat/libsecp256k1_shim/src/shim_ecdh.cpp`
- Modify: `src/cpu/tests/test_ecdh_recovery_taproot.cpp`
- Modify: `compat/libsecp256k1_shim/tests/shim_test.cpp`
- Modify: `audit/test_regression_ecdh_xy64_erase.cpp` and its existing audit target if needed
- Modify: `docs/SECURITY_CLAIMS.md`, `docs/CT_VERIFICATION.md`, `CHANGELOG.md`, and regenerated `docs/EXTERNAL_AUDIT_BUNDLE.json`/`.sha256` only to match measured scope

**Interfaces:**
- Consumes: raw Jacobian multiplication and point-IO helpers from Tasks 1–2.
- Produces: no new public API; ECDH returns its old 32-byte values and shim invokes its old callback contract.

- [ ] **Step 1: Write failing path-specific tests.** Use a deterministic scalar and non-affine peer. Derive the expected compressed-hash, x-hash and raw x from the pre-change reference. Add zero scalar, infinity peer, and off-curve peer rejection; a custom shim callback copies `x32||y32` to a test buffer and returns `7`, which must remain the returned value.

```cpp
auto const key = secp256k1::fast::Scalar::from_uint64(19);
auto const peer = secp256k1::fast::Point::generator().dbl();
auto const shared = peer.scalar_mul(key); // public-data oracle in this test only
auto const compressed = shared.to_compressed();
auto const expected = secp256k1::SHA256::hash(compressed.data(), compressed.size());
check(secp256k1::ecdh_compute(key, peer) == expected,
      "ECDH compressed-hash bytes match reference");
```

```cpp
struct captured_xy { std::array<unsigned char, 64> bytes{}; };
auto capture = [](unsigned char*, const unsigned char* x32,
                  const unsigned char* y32, void* opaque) -> int {
    auto& dst = *static_cast<captured_xy*>(opaque);
    std::memcpy(dst.bytes.data(), x32, 32);
    std::memcpy(dst.bytes.data() + 32, y32, 32);
    return 7;
};
captured_xy captured{};
int rc = secp256k1_ecdh(ctx, output, &pubkey, seckey32, capture, &captured);
check(rc == 7, "shim preserves custom callback return");
auto const expected_xy = peer.scalar_mul(key).to_uncompressed();
check(std::memcmp(captured.bytes.data(), expected_xy.data() + 1, 64) == 0,
      "shim passes byte-identical x32/y32 to callback");
```

- [ ] **Step 2: Run these tests before wiring and confirm the old byte tests pass but the new taint/path gate fails.** The red condition is the observed secret-result variable-time conversion, not a byte mismatch.

```bash
cmake --build out/ct-ecdh-candidate --target run_selftest test_ct_point_io_standalone -j 8
ctest --test-dir out/ct-ecdh-candidate -R '^ct_point_io$|^selftest$' --output-on-failure
```

- [ ] **Step 3: Wire ECDH and shim to the raw result and point-IO helper.** Keep public validation first, then multiply and serialize without `Point` conversion. Preserve all hash inputs. Use a scope guard so `kb`, `sk`, raw Jacobian, x/y buffers, and default hash scratch are erased on every exit, including parse failure and callback return.

```cpp
auto shared = secp256k1::ct::detail::scalar_mul_jacobian(public_key, private_key);
struct erase_raw {
    secp256k1::ct::CTJacobianPoint& value;
    ~erase_raw() { secp256k1::detail::secure_erase(&value, sizeof(value)); }
} erase_shared{shared};
std::array<std::uint8_t, 33> compressed{};
auto valid = secp256k1::ct::detail::point_to_compressed33(shared, compressed);
auto digest = SHA256::hash(compressed.data(), compressed.size());
secp256k1::detail::secure_erase(compressed.data(), compressed.size());
SECP256K1_DECLASSIFY(&valid, sizeof(valid));
if (valid == 0) return {};
return digest;
```

- [ ] **Step 4: Run byte-differential, C ABI/shim, taint, sanitizer, and full benchmark gates.** Benchmark baseline/candidate A/B/A/B with the same CPU affinity and build flags; compare distributions for `ecdh_compute`, `ecdh_compute_raw`, dedicated shim ECDH, and representative engine rows. A repeatable slowdown, byte difference, or taint finding sends this task back for optimization or rework. Do not substitute `bench_unified --quick` for the gate.

```bash
cmake --build out/ct-ecdh-candidate --target run_selftest test_ct_point_io_standalone shim_test test_regression_ecdh_xy64_erase_standalone bench_unified bench_ecdh_gate -j 8
ctest --test-dir out/ct-ecdh-candidate -R '^ct_point_io$|^selftest$|^secp256k1_shim_test$|^regression_ecdh_xy64_erase$' --output-on-failure
taskset -c 0 out/ct-ecdh-baseline/src/cpu/bench_unified --json out/ct-ecdh-baseline/ab_a1.json
taskset -c 0 out/ct-ecdh-candidate/src/cpu/bench_unified --json out/ct-ecdh-candidate/ab_b1.json
taskset -c 0 out/ct-ecdh-baseline/src/cpu/bench_unified --json out/ct-ecdh-baseline/ab_a2.json
taskset -c 0 out/ct-ecdh-candidate/src/cpu/bench_unified --json out/ct-ecdh-candidate/ab_b2.json
taskset -c 0 out/ct-ecdh-baseline/compat/libsecp256k1_shim/bench_ecdh_gate
taskset -c 0 out/ct-ecdh-candidate/compat/libsecp256k1_shim/bench_ecdh_gate
taskset -c 0 out/ct-ecdh-baseline/compat/libsecp256k1_shim/bench_ecdh_gate
taskset -c 0 out/ct-ecdh-candidate/compat/libsecp256k1_shim/bench_ecdh_gate
python3 ci/sync_all_docs.py --check
```

- [ ] **Step 5: Review the merged diff, update only supported security claims, refresh the external audit bundle, and commit.** Keep the shim custom callback outside the library CT claim and state generic 4x64 coverage only after the portable-field plan supplies evidence. The bundle generator requires the project graph, source graph, and shared library; generate those first, then require the verifier's 12/12 pass.

```bash
cmake --build out/ct-ecdh-candidate --target ufsecp_shared -j 8
python3 ci/build_project_graph.py --rebuild
python3 tools/source_graph_kit/source_graph.py build -i
python3 ci/external_audit_bundle.py
python3 ci/verify_external_audit_bundle.py --bundle docs/EXTERNAL_AUDIT_BUNDLE.json --digest docs/EXTERNAL_AUDIT_BUNDLE.sha256 --json --allow-commit-mismatch
python3 ci/sync_all_docs.py --check
git diff --check
git add src/cpu/src/ecdh.cpp compat/libsecp256k1_shim/src/shim_ecdh.cpp src/cpu/tests/test_ecdh_recovery_taproot.cpp compat/libsecp256k1_shim/tests/shim_test.cpp audit/test_regression_ecdh_xy64_erase.cpp docs/SECURITY_CLAIMS.md docs/CT_VERIFICATION.md CHANGELOG.md docs/EXTERNAL_AUDIT_BUNDLE.json docs/EXTERNAL_AUDIT_BUNDLE.sha256 docs/INCIDENT_DRILL_LOG.json docs/SECURITY_AUTONOMY_KPI.json
git commit -m "fix(ct): keep ECDH Jacobian serialization secret-safe"
```

## Handoff to companion plans

After this plan's independent review, BIP352 may consume `point_to_compressed33` and `point_to_x32` without touching ECDH files. The portable-field plan owns the generic no-`__int128` kernel and the generic-profile CT claim. Neither companion plan may treat this plan's native 5x52 evidence as proof for its own profile or adapter control flow.
