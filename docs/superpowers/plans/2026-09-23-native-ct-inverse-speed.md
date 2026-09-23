# Native Constant-Time Inverse Speed Recovery Plan

> Implement in the isolated `out/release46-integration` worktree. The seven dirty Task 3 ECDH files are a preserved, unaccepted candidate; do not stage, discard, or rewrite them for this experiment.

**Goal:** Recover the measured 0.4–0.6 µs normalization cost without changing inverse bytes, constant-time behavior, or representative engine speed. The companion [design](../specs/2026-09-23-native-ct-inverse-speed-design.md) supplies the contract and decision rule.

**Architecture:** First establish a native C++ primitive baseline and exact-byte differential gate. Then experiment only inside the native `__int128` `ct_divsteps_59` transition-matrix loop: pack independent `(u,v)` and `(q,r)` state into SSE2 64-bit lanes on x86-64. Keep scalar `f,g,zeta` and a non-x86 scalar path. Compare both primitive and wired ECDH/shim against frozen pre-change executables; do not accept an inverse optimization on primitive numbers alone.

## Task 0 — Inverse gate and frozen measurement

**Allowed writes:** new `src/cpu/tests/test_ct_inverse_gate.cpp`, `src/cpu/tests/CMakeLists.txt` only if it exists and owns registration, otherwise `src/cpu/CMakeLists.txt`; new `src/cpu/bench/bench_ct_inverse.cpp` and its registering CMake file. No production source edit.

1. Inspect exact CMake test/bench registration and `ct::field_inv` declaration using indexed Source Graph, then bounded known-file preview. Record compiler, flags, CPU affinity and baseline executable hashes. Never rebuild `out/ct-ecdh-baseline`.
2. Add a deterministic C++ gate for zero, one, `p−1`, limb edges, and at least 1,024 seeded valid inputs. Assert exact 32-byte canonical result against `fast::FieldElement52::inverse_safegcd()` where applicable, and `a * inv(a) == 1` for every nonzero input. Include stable aggregate checksum to compare pre/post binaries. Observe the natural red state from the not-yet-implemented test target, then build and run it green; do not manufacture a wrong expected byte.
3. Add a self-contained native inverse benchmark with fixed seeded field inputs, warmup, `DoNotOptimize`, checksum, and ns/call. Build the unchanged code in a **new** build directory `out/ct-inverse-pre`, and retain its binary and hash. Build identical candidate configuration in `out/ct-inverse-candidate`. Run an initial interleaved pinned A/B/A/B (CPU 0 if allowed) and retain raw outputs under ignored `out/ct-inverse-results/`. Report spread and checksum; do not claim speed from one run.
4. Run new test plus existing `selftest`, `ct_point_io`, and shim gates with the current unaccepted wiring present. Review test coverage and CMake wiring before committing only Task 0 files.

## Task 1 — Native transition-matrix experiment

**Allowed writes:** `src/cpu/src/ct_field.cpp` plus the Task 0 test only if a targeted test is needed. Leave the seven dirty Task 3 files untouched.

1. Add a failing differential case or test-only comparison that exercises inverse byte identity before modifying the kernel. Preserve the scalar `ct_divsteps_59` implementation as the non-x86 `__int128` path. Do not alter the fixed 10 × 59 iterations, `ct_update_de`, `ct_update_fg`, the no-`__int128` fallback, field/scalar public API, or secrecy markers.
2. On x86-64 with `__SIZEOF_INT128__`, use SSE2 intrinsics (`<emmintrin.h>`) to represent `(u,v)` and `(q,r)` as two-lane 64-bit vectors. Scalar `f,g,zeta` determines public-shape all-zero/all-one masks `c1,c2`; broadcast masks to both lanes. Apply lane-wise XOR/subtract/AND/add and left shift in the same order and modulo-2^64 semantics as the scalar code. Extract lanes only after 59 rounds. Keep runtime dispatch absent and no secret-indexed memory. The scalar path remains compiled on other architectures. Do not assume SIMD is faster: this is a measured candidate.
3. Run the 1,024+ differential gate, existing field/point/ECDH/shim tests, forced no-`__int128` build, ASan/UBSan, and marker-enabled Valgrind probe. Inspect optimized kernel assembly for fixed loop branching only, no operand-dependent branch or out-of-line runtime helper. Review integer casts and shifts for exact unsigned wrap semantics.
4. Interleave old/new primitive benchmark on the same pinned core. If slower or statistically indistinguishable, remove only the Task 1 experimental kernel via a bounded patch; retain the Task 0 harness and report negative evidence. If faster, proceed to Task 2; do not commit a speed claim yet.

## Task 2 — End-to-end release decision

**Allowed writes:** no production edit initially; final report under `out/ct-inverse-results/` (ignored) and an exact scoped plan/progress update. ECDH wiring remains uncommitted until accepted.

1. Verify frozen SHA-256 hashes of `out/ct-ecdh-baseline` and compare against current candidate. Run full pinned interleaved A/B/A/B for `bench_unified` ECDH compressed/x-hash/raw-x rows, whole-engine representative rows, and dedicated `bench_ecdh_gate`; require matching checksums.
2. Require raw-x ECDH and shim loss to disappear reproducibly without a new representative slowdown. Re-run native/portable test, sanitizer, taint, source review, and `git diff --check` gates after the final kernel change. Portable byte equality is required; native SSE2 evidence does **not** establish portable constant-time behavior.
3. If all gates pass, independent manager review then exact-file commits, push to the experimental branch, and only then propose release integration. If any speed, byte, or CT hard gate fails, keep the wiring out of `dev`/`main`, preserve the safe accepted branch `origin/experiment/v4.6-ct-ecdh-perf` at `7943f4b7`, record evidence, and open a separate scalar-multiplication design. Do not update release claims or tag 4.6.

## Review checks

- The reference is an **independent public-data oracle**; the same candidate function cannot be its own expected result.
- C++ primitive benchmark uses the same compiler and flags before/after, fixed inputs, warmup, checksum, pinned core, and interleaved runs.
- The native optimized binary, not merely source, is checked for timing shape; marker-enabled Valgrind must remain zero-error.
- A scalar fallback is retained for non-x86 `__int128`, and the forced portable fallback stays untouched.
- Final acceptance requires **both** mathematical/byte/taint correctness and non-regressing end-to-end speed.
