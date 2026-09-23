# Native CT inverse SSE2 experiment: negative result

Date: 2026-09-23. Scope: x86-64 native `ct_divsteps_59` transition matrix only. The experimental kernel is **not** in the committed tree; the original `src/cpu/src/ct_field.cpp` was restored byte-for-byte (SHA-256 `6452c6d58e48676347ac2c3552c68c8a47bf7e29771887f9d820154775194c44`). The seven earlier ECDH candidate files remain uncommitted and untouched by this experiment.

The prototype packed `(u,v)` and `(q,r)` into SSE2 two-lane vectors while keeping scalar `f,g,zeta`, the 59-step fixed loop, ten blocks, field updates, and non-x86/no-`__int128` paths unchanged. GCC 14.2 Release built it. The 1,037-case inverse byte/limb/product gate, `selftest`, and `ct_point_io` passed 3/3. This establishes tested output equality, not side-channel certification.

The frozen scalar binary and candidate used identical compiler/configuration, fixed 64-input pool, 4,096 warmup calls, 32,768 timed calls per invocation, CPU0 affinity, and checksum `931f450e0322db25`. The frozen benchmark SHA-256 is `3848c5441b6dc7f2044ae7b36b1dc9c9961c75f6d5c65a8e5f91c745668e5046`; the SSE2 candidate binary was `48a0c9d6a10a9f0f1809d237d8cf88006d815eac1f2d28ad4814bd29ab54b929`. Full 40-round A/B/B/A output is in [raw measurements](2026-09-23-native-ct-inverse-sse2-raw.txt) (SHA-256 `aeb3830411d9e2b34c1501343be003a7a100ceb4040253b5dca9a82980de903a`).

| Result, 80 runs each | Scalar A | SSE2 B |
| --- | ---: | ---: |
| Mean ns/inverse | 1441.50 | 1484.03 |
| Median ns/inverse | 1463.29 | 1492.04 |

Paired round mean `B−A = +42.52 ns` (+2.95%); median paired delta +44.15 ns; B was slower in 32/40 rounds. An independent manager check of eight A/B pairs found B slower in 7/8, with mean A 1500.50 ns and B 1529.72 ns. The original same-code four-run range was 0.49%; it is not a confidence interval, but the 40-round paired direction and independent check support rejection. The release target needed roughly 0.4–0.6 µs recovery in shared-point normalization; this prototype instead adds ~0.04 µs to the inverse.

**Decision:** reject this kernel and retain the scalar native inverse. Because the primitive speed gate failed, Clang, forced portable, ASan/UBSan, Valgrind taint, optimized-assembly audit, and end-to-end ECDH/shim gates were intentionally not run. No constant-time or release claim is made for the rejected prototype. The accepted inverse baseline harness remains at commit `63fab73e`; the unaccepted ECDH wiring remains out of the release. Next research should examine a different primitive/kernel formulation or separately measured scalar-multiplication work, not assume two-lane SSE2 is an optimization.
