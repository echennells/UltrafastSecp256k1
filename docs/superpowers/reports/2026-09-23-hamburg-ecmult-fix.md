# Hamburg x-only exceptional-add correction — experimental acceptance

Status: accepted **only on the experimental branch**, not for `main` or v4.6.

## Defect and correction

The native FE52 `ecmult_const_xonly` ladder used the Hamburg-shortcut mixed-add
formula for every addition. A canonical scalar
`68f971cf6c8db09d29f617774c1ed4e94a902ad577cfa6b4723ee7b8ea46a06b`
with the generator x-coordinate made the final group's second addition hit
`S1+S2=0`; the old path returned zero instead of the independently computed
`5e093bab94092a150225a37a6c5075ca7830ea5cd96960cb106569d83e7adea4`.

The repaired native ladder keeps the original fixed 25-iteration loop and uses
the shortcut for all but the final second add. Its public loop-index branch
skips that last shortcut; a noinline wrapper then runs the complete,
constant-time mixed-add formula once. The corrected GLV-lattice argument
excludes the exceptional relation at all earlier additions for a valid lifted
curve input. An independent review checked the loop state, final lookup,
aliasing, and branch condition; it found no new semantic or constant-time issue
in this layout.

## Correctness gates

- The pinned witness was RED before the change and GREEN after it. A separate
  near-order scalar that was suspected to fail proved to be a PASS control in
  both binaries; the initial symbolic model for it was corrected against an
  instrumented clean pre-fix FE52 trace.
- The normal witness test covers zero, `n-1`, a fractional representation of
  the pinned witness, and 256 deterministic public peers with full-width
  canonical scalars in both direct and fractional x representations.
- Native Release selftest and witness test pass; the expanded witness passes
  under forced portable arithmetic and ASan/UBSan. Native BIP324 transport
  passes. `git diff --check` passes.

## Performance gates

The pre-fix and candidate binaries were built with the same GCC 14.2 Release,
ASM and LTO options. The pre-fix binaries were frozen and not rebuilt during
the comparisons. All paired runs were externally pinned to CPU 0.

| Workload | Pairs | Baseline | Candidate | Result |
| --- | ---: | ---: | ---: | --- |
| 32-input direct x-only, 50 ABBA blocks | 50 | 21,126.22 ns | 20,649.28 ns | candidate −2.26%; paired 95% estimate −716 to −238 ns |
| Fixed BIP324 XDH, 30 ABBA blocks | 30 | 24,382.25 ns | 24,069.62 ns | candidate −1.28%; interval crosses zero |
| BIP324 full handshake, same 30 blocks | 30 | 105,239.12 ns | 103,091.40 ns | candidate −2.04%; interval crosses zero |

The first ten BIP324 blocks suggested an XDH slowdown, but the next twenty
reversed it; **there is no established downstream speedup or slowdown** from
this noisy sample. The focused benchmark did show a repeatable improvement.
The optimized scalar body is 52,351 bytes versus 53,267 bytes pre-fix; the
complete-add wrapper is separately out of line. Raw measurements are retained
in ignored build output at `out/hamburg-fixed/task1b-abba50.log`,
`out/hamburg-fixed/task1b-bip324-abba10.log`, and
`out/hamburg-fixed/task1b-bip324-abba20-continuation.log`.

## Release blockers not repaired here

- The public x-only API promises zero for invalid curve input, but native
  `xn=5,xd=1,q=7` returns a nonzero twist result while portable returns zero.
  The diagnostic `--offcurve` mode is not registered as a passing CTest.
- A secret-scalar Valgrind marker test reports the same 19 conditional contexts
  in clean pre-fix and candidate binaries, including `Scalar::from_limbs` and
  GLV paths. This change must not be described as establishing a CT guarantee.
- The separate unaccepted ECDH/shim work remains dirty and excluded from this
  acceptance; its earlier same-host speed gate failed.

The v4.6 release requires separate repairs and fresh end-to-end correctness,
side-channel, and performance gates before merging to `main`.
