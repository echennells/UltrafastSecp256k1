# Hamburg-path x-only multiplication correctness plan

**Status:** correctness defect confirmed by native C++ RED: the witness returns 32 zero bytes rather than the independent expected x. Do not route ECDH to the Hamburg-specialized path. The earlier SSE2 inverse speed experiment was rejected and its source restored.

**Contract:** for every valid input x and canonical scalar q, `ct::ecmult_const_xonly(x, 1, q)` must equal the x-coordinate of `q·P` for either lift of x, including exceptional unified-add cases. A correctness repair must preserve constant-time treatment of q and must pass the owner's no-reproducible-speed-regression gate before 4.6 acceptance.

## Task 0: Confirm the counterexample, test-first

**Allowed writes:** one new native C++ regression test under `src/cpu/tests/`, registration in `src/cpu/CMakeLists.txt`, ignored evidence under `out/`. No production source or the seven dirty ECDH candidate files.

1. Build an independent expected value from `fast::Point::generator().scalar_mul(q).x()` and pin the externally derived x bytes `5e093bab94092a150225a37a6c5075ca7830ea5cd96960cb106569d83e7adea4` for `q=68f971cf6c8db09d29f617774c1ed4e94a902ad577cfa6b4723ee7b8ea46a06b`; use generator x as `xn`, one as `xd`. Assert input scalar is canonical and nonzero.
2. Test `ct::ecmult_const_xonly(xn,xd,q)` exact bytes against both independent expectations. Register standalone CTest. Run the test against current native code and require a substantive RED (wrong output), not compile/setup failure; preserve printed got/want bytes. Also run a control scalar such as q=1 that must pass.
3. Run existing relevant x-only/ellswift/BIP324 tests and record current baseline speed with retained binaries, but do not modify production or declare a fix. Independent manager confirms the RED and reviews test quality.

**Task 0 evidence:** q=1 control and independent `fast::Point` oracle pass; current `ct::ecmult_const_xonly` returns `0000000000000000000000000000000000000000000000000000000000000000` for the witness. Manager independently reran the executable and observed exit 1. Existing `selftest` and `bip324_transport` pass, demonstrating their former coverage gap. Preliminary pinned baseline: ElligatorSwift XDH 24.48 µs, full handshake 114.30 µs; these single-run figures are orientation only, not an acceptance comparison.

## Task 1: Diagnose and repair the actual exceptional set

Proceed only after Task 0 RED. Prove which window positions can hit `S1+S2=0` for valid q, including φ-related cases. The source comment that `K_CONST` guarantees nondegeneracy is not proof; the witness may refute it. Design a bounded constant-time fix, preferably without paying for a redundant check in every one of 52 additions, but correctness takes priority. Write tests for identified exception classes before implementation. Do not simply replace all `HAMBURG=true` calls with the generic path and claim release-ready: the documented ~0.9 µs loss needs full same-host pinned A/B/A/B evidence and mitigation if reproducible.

## Task 2: Full acceptance

Require exact-byte differential tests against independent reference on edge, witness, and many deterministic scalars/peers; native and forced portable tests; sanitizer; marker-enabled secret-taint Valgrind; optimized-assembly audit; and pinned interleaved BIP324/ellswift plus representative engine benchmarks. No commit to `dev`/`main`, no release tag, and no speed or CT claim if any hard gate fails. Keep the seven dirty ECDH wiring files separate until their own speed gate passes.
