# Native Constant-Time Field Inverse Performance Design

## Purpose and measured starting point

The release 4.6 ECDH/shim repair in the isolated integration worktree is
correct in the tested byte, taint, and sanitizer gates, but it fails the
owner's no-regression speed gate. In full pinned A/B/A/B, raw-x ECDH was
2.44% and 2.07% slower, and the shim was slower in six of six paired runs.
The candidate remains uncommitted and must not enter `dev` or `main` in this
state. The accepted pre-wiring work is preserved at
`origin/experiment/v4.6-ct-ecdh-perf` (`7943f4b7`).

Component measurements isolate a 0.4–0.6 µs penalty per affine shared-point
normalization: the old variable-time conversion costs about 0.90–1.03 µs,
the new constant-time serializer about 1.40–1.59 µs. Scalar multiplication
is about 18.7–19.5 µs in both. A non-affine public-peer validation change
saves about 0.8 µs but does not help the common affine-peer case. Therefore
the first optimization target is native constant-time field inversion, not
another ECDH call-site rewrite.

## Chosen scope and alternatives

Optimize the existing native `__int128` Bernstein–Yang SafeGCD inverse in
`src/cpu/src/ct_field.cpp` while preserving its mathematical and timing
contract. Keep the 590 fixed divsteps (10 blocks of 59) unless a separately
reviewed proof establishes another bound. First profile the current inverse
as a C++ primitive and inspect its generated code. Then make one measured
change at a time to conversion, update, or normalization work, retaining the
same public `ct::field_inv(FieldElement) -> FieldElement` interface. Do not
touch the no-`__int128` 25×30 fallback, scalar arithmetic, point formulas,
or the public ABI in this experiment.

An ECDH-specific scalar-multiplication optimization is a second, separate
research unit if native inverse work cannot recover the measured gap. It may
offer a 2–3% end-to-end saving, but it changes the central scalar engine and
has a wider correctness/performance surface. Reusing the old variable-time
inverse is not an option: the old-path taint probe exits 99 while the new
native serializer probe exits 0. A source-level fixed loop without generated
code and taint evidence is also insufficient.

## Contracts

- For every canonical field input, return exactly the same canonical inverse
  as the current `ct::field_inv`; zero remains zero. Test raw limb bytes, not
  only normalized equality.
- Preserve fixed iteration count, fixed memory access, and no secret-dependent
  branch or runtime helper in the native optimized binary. Secret-tainted
  operands must produce zero Valgrind conditional/memory errors without
  declassification inside arithmetic.
- Preserve the forced no-`__int128` output and build path unchanged; no
  portable constant-time claim follows from a native optimization.
- Keep ECDH, shim callback, and all existing public bytes/validation codes
  unchanged. The uncommitted wiring candidate remains experimental until its
  own full gates pass.
- No affected field, ECDH, shim, or representative engine workload may show
  a reproducible slowdown beyond observed measurement noise. A primitive
  speedup alone is not enough; require full pinned interleaved A/B/A/B on the
  final wired candidate and retained old binary, with baseline hashes checked.

## Verification and decision rule

Create a deterministic native C++ inverse gate with zero, one, `p−1`, limb
edges, and at least 1,024 seeded nonzero values. Compare exact output bytes
against the frozen pre-change inverse and the public-data
`fast::FieldElement52::inverse_safegcd` reference;
also require `a·inverse(a)=1` for nonzero `a`. Capture before/after native
inverse latency with the same compiler/flags, pinned core, warmup, and
interleaved runs. Run native/portable unit tests, ASan/UBSan, marker-enabled
Valgrind, and inspect optimized assembly around the inverse for operand-
dependent branches and helper calls.

If the primitive passes but the wired ECDH/shim A/B/A/B still has a repeatable
loss, do not commit the wiring or refresh release claims. Record the result
and open the separate scalar-multiplication design. If the inverse change
itself is not faster without compromising its contract, revert that
experimental change; the accepted `7943f4b7` branch remains the safe base.
