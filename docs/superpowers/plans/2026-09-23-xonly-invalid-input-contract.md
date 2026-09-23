# Public x-only invalid-input contract plan

**Status:** native FE52 contract failure established independently of the
Hamburg correction. `ct::ecmult_const_xonly(5,1,7)` returns nonzero x
`9f78332fb6146066b4bca724c24c1bc88f7190cee8862112fa4d799142b252bb`;
the forced-portable path returns zero. The public header promises zero for an
invalid point. Keep the seven unrelated dirty ECDH/shim files out of scope.

**Goal:** make the public API satisfy its invalid-point contract, while
preserving the byte-identical valid-point result and the performance of
decoder-validated ElligatorSwift/BIP324 XDH. A new check may depend on the
public peer coordinates, never on the secret scalar.

## Task 0 — test and baseline before production edits

**Allowed writes:** a dedicated C++ contract test in `src/cpu/tests/`, its
registration in `src/cpu/CMakeLists.txt`, a focused benchmark in
`src/cpu/bench/` if needed, and ignored `out/` evidence. No production edits.

1. Register a test that requires zero for `xn=5,xd=1,q=7` and `xd=0`, and
   checks exact bytes for valid direct and scaled fractions, scalar zero, and
   the Hamburg witness. Confirm a substantive native RED and portable control.
2. Freeze same-flags pre-fix native direct x-only and decoder-backed XDH
   benchmark binaries. Record compiler, options, hashes and raw runs. Do not
   rebuild the frozen artifacts after production work starts.

## Task 1 — narrow public validation with a trusted decoded path

**Allowed writes:** `src/cpu/src/ct_point.cpp`, a narrowly scoped internal
declaration if required, `src/cpu/src/ellswift.cpp`, `src/cpu/src/bip324.cpp`,
the Task 0 test/benchmark and their CMake registration. Do not touch the
seven dirty ECDH/shim files.

1. In the native public wrapper, reject a zero denominator and validate the
   secp256k1 lift using the public-data criterion `Jacobi(g*xd)==1`, where
   `g=xn^3+7*xd^3`. A zero Jacobi result is invalid. Retain the existing
   multiplication as an internal trusted entry that assumes a validated
   decoded fraction and never bypasses validation for arbitrary callers.
2. Route only the ElligatorSwift and BIP324 call sites whose decoders already
   guarantee a nonzero denominator and valid lift to the trusted entry.
   Document and test that precondition; keep the public three-argument API
   signature and ABI unchanged. Avoid exporting an unsafe trusted symbol if
   the build permits internal visibility.
3. Make portable behavior explicitly reject `xd=0`; test native and forced
   portable. Preserve constant-time handling of q through the multiplication.

## Task 2 — acceptance gates

Require the RED test to turn GREEN, exact-byte differential checks against
independent `fast::Point` results for valid peers, native/portable tests,
ASan/UBSan, and marker-enabled secret-scalar taint inspection. The existing
Valgrind 19-context blocker is separate; no CT-clean claim is allowed until
it is repaired. Run pinned paired direct-public and decoded-XDH/handshake
benchmarks against the frozen binaries. A public validation cost must be
measured and disclosed; the already-validated XDH hot path must not show a
reproducible speed regression. Independent manager review closes the card;
only an experimentally accepted change can be pushed to the experimental
branch. No `main` merge or 4.6 tag at this stage.
