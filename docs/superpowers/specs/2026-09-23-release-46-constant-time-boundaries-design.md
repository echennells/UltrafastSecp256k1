# Release 4.6 constant-time boundary repairs

## Intent and acceptance boundary

Release 4.6 must not present secret-dependent paths as constant-time when the
measured implementation is not. Repair three known boundaries while retaining
byte-for-byte compatibility with the current implementation: ECDH Jacobian
serialization, BIP352 CPU scan-key-derived point addition, and the generic
portable no-`__int128` field multiplication/squaring fallback. The existing
native 5x52 fast path and public ABI remain unchanged. Correctness and
non-regressing speed are both mandatory release conditions: a security repair
that changes reference results or reproducibly slows an affected workload is
redesigned or deferred, not silently accepted.

This is a security-correctness design, not a blanket constant-time claim for
all platforms or all BIP352 control flow. Promotion to `dev`, then `main`, and
the 4.6 tag remain separate release decisions governed by test evidence and
branch protection.

## Current evidence

- The C++ ECDH entry points serialize a `ct::scalar_mul` Jacobian result via
  `Point::to_compressed()` or `.x()`; the shim uses `.to_uncompressed()`.
  Those routes can enter variable-time affine normalization. A taint test
  must re-taint the multiplication result to observe this downstream boundary.
- BIP352 CPU scanning uses `spend.add(offset)` where `offset` derives from a
  private scan key. The existing fast point addition has secret-dependent
  behavior. The two CPU secret-point serialization helpers already repaired
  in PR #432 do not repair this addition.
- With GCC 14, the tested generic 4x64 fallback built using
  `-U__SIZEOF_INT128__ -DSECP256K1_NO_INT128=1` produced 1,703 Valgrind
  conditional errors across 36 contexts after secret-tainting field operands.
  The native 5x52 profile produced zero in the corresponding check. This
  evidence does not certify or indict other 4x64 assembly/MCU profiles.

## Selected architecture

Use a shared internal constant-time point-IO boundary, a complete
constant-time point-add boundary for the scan candidate, and a separate
portable constant-time field kernel. These units can be verified independently
and wired into the existing public API without changing external bytes.

### 1. Point normalization and serialization

An internal `secp256k1/detail/ct_point_io.hpp`-level component accepts a
`CTJacobianPoint` and produces only the needed fixed-size representations:
`x32`, compressed `33` bytes, or `x||y` `64` bytes. It normalizes with
`ct::field_inv`, `ct::field_sqr`, `ct::field_mul`, and fixed-size field
serialization. It must not convert a secret-derived Jacobian point back to
`Point` or call `Point::x()`, `to_compressed()`, or `to_uncompressed()` before
declassification. Infinity and invalid input handling must preserve the
current API's success/failure behavior without secret-dependent branches or
secret-indexed memory access inside the claimed path. Intermediate coordinates
and ECDH shim secret temporaries are explicitly erased after use.

Wire the three C++ ECDH variants, their C ABI wrappers through the existing
C++ calls, and the libsecp256k1 ECDH shim to this boundary. Preserve their
existing outputs exactly: SHA-256 of compressed 33 bytes, SHA-256 of `x32`,
raw `x32`, and the shim's default/custom hash callback input contract. Custom
callbacks are outside the library's constant-time guarantee.

### 2. BIP352 CPU scan candidate

Keep the candidate in the constant-time point representation while adding
the scan-key-derived offset to the public spend point. Use a complete
constant-time addition (`ct::point_add_complete` or a proven equivalent
mixed-add operation) and serialize the resulting candidate via the point-IO
boundary. Test ordinary addition, doubling, inverse pairs, infinity, and
non-affine inputs. Preserve the existing BIP352 shared-secret, tweak,
candidate serialization, and match bytes. Matching, iteration count, and
early-return behavior remain observable; this design does not claim the whole
scan adapter is constant-time.

### 3. Portable field multiplication and squaring

For the generic no-`__int128`/no-assembly profile only, replace delegation to
the fast field operators with a fixed-iteration, branchless field kernel.
The first implementation candidate is 8x32 schoolbook multiplication and
pseudo-Mersenne reduction for `p = 2^256 - 2^32 - 977`, with squaring initially
reusing multiplication. Before implementation is accepted, derive and review
the carry/reduction bounds, including worst-case inputs, and confirm the
compiler's generated control flow is compatible with the claimed
constant-time property. Do not assume that a nominally fixed source loop is
enough. Keep native 5x52 dispatch unchanged, and document the exact portable
profile for which evidence exists. Existing no-`__int128` scalar-inversion
limitations are a distinct issue and must not be represented as repaired.

## Error handling and compatibility

Public signatures, scalar/key validation, return codes, infinity behavior,
callback semantics, and externally visible bytes stay unchanged. A mismatch
against the current reference is a defect unless a separately reviewed
security contract explicitly requires a behavior change. Input validation
may branch on public validity; secret-dependent point and field operations
within the claimed path may not. Internal helper APIs remain private to avoid
an accidental ABI commitment.

## Verification and release gates

1. Capture pre-change reference outputs and edge-case fixtures using the
   current implementation, then require byte-identical ECDH, shim, and BIP352
   results after each wiring change. Include independent libsecp256k1
   differential vectors where applicable.
2. Extend taint tests so secret Jacobian coordinates are re-tainted after
   scalar multiplication, and each portable field operand is tainted
   separately. Use the marker recognized by the tests
   (`SECP256K1_CT_VALGRIND`), not merely the wrapper's
   `VALGRIND_CT_CHECK`. Require zero conditional/memory errors in the scoped
   paths. Keep source/assembly review alongside dynamic checks.
3. Exercise arithmetic edge cases, deterministic random vectors, independent
   field oracles, UBSan/ASan, GCC and Clang, and the forced portable profile.
   Run existing project security, fast, and CI gates. A passing native 5x52
   check alone is insufficient for the portable claim.
4. Before editing each path, capture a reproducible baseline for its affected
   primitives, public operations, and the representative end-to-end engine
   benchmark set. Compare before/after builds with the same compiler, flags,
   machine, CPU affinity, input distributions and warm-up; interleave repeated
   runs, and report distributions for latency and throughput rather than one
   best number. A coarse CI smoke test that detects only large slowdowns does
   not establish this gate. Treat a slowdown
   that repeats beyond observed measurement noise as a regression, however
   small. Increase samples when the result is ambiguous. If any affected
   workload has a confirmed regression, optimize or revert that change and
   remeasure; do not release it under a security exception. Show measurements
   separately for native 5x52 and the forced portable profile so one cannot
   conceal a slowdown in the other.
5. Update security claims and release notes to match only measured coverage.
   Keep PR #432 draft until these gates and full CI pass. Do not bypass required
   code-owner review on protected `main` or claim release readiness from a
   partial CI run.

## Work boundaries

The three repair units are independent for initial implementation and tests,
but ECDH and BIP352 wiring share the point-IO interface. Define that
interface first; after it is fixed, work on ECDH/shim and BIP352 can proceed
without overlapping writes. The portable field kernel can be developed
independently. Integrate sequentially where files or claims overlap, then
review the merged tree as a whole. This document authorizes no unrelated
curve redesign or performance-algorithm replacement.
