# X-only public validation — correct candidate, speed gate rejected

Status: **not accepted** for the experimental canonical branch, `main`, or
v4.6. The production candidate remains uncommitted in the isolated release
worktree. The seven pre-existing dirty ECDH/shim files are unrelated.

The committed RED test demonstrates that native `ct::ecmult_const_xonly`
returns a nonzero twist result for invalid `xn=5,xd=1,q=7`, contrary to its
public zero-result contract. A trial repair validates `Jacobi((xn³+7xd³)xd)==1`
on public input, uses a hidden trusted entry only for the two decoder-backed
XDH call sites, and explicitly rejects a zero denominator in portable mode.
An independent review found no correctness, constant-time, or ABI defect in
the trial. Native, forced-portable and ASan/UBSan scoped CTest each pass 3/3;
the manager reran all three profiles. The trial does not clear the pre-existing
19 Valgrind secret-taint contexts.

Same-flags frozen pre-repair binaries were compared with the candidate in
pinned ABBA blocks. The final bounded trial removed an unnecessary native
infinity-result selection after a proof that its flag is always zero on a
normal validated return and that the zero scalar maps through a zero inverse.

| Workload | Blocks | Paired median change | 95% bootstrap interval | Verdict |
| --- | ---: | ---: | ---: | --- |
| Public direct x-only | 20 (before final tiny simplification) | +7.10% | +4.60% to +9.26% | slower |
| Public direct x-only | 8 (final trial) | +6.25% | +1.63% to +7.38% | slower, 8/8 blocks |
| Decoder-backed ElligatorSwift XDH | 20 (final trial) | −0.06% | −5.31% to +4.38% | unresolved; no reproduced regression |
| BIP324 full handshake | 20 (final trial) | −0.01% | −4.24% to +1.38% | unresolved |

The public check has a measured cost and fails the owner's strict speed gate;
therefore the trial must not be described as release-ready merely because its
functional tests pass. The hot decoded path avoids the new Jacobi check, but
its noisy intervals do not prove an absolute speed guarantee either.

Frozen pre-repair benchmark SHA256: direct
`3abeabae105de2df274d71935c95ce054a4f13ae9765899e0657547ba86add98`,
BIP324 `586ae74bd4e54e8aca7c5edc8875d9d1d842935ecfdb07dc0a9658c32bb24fe5`.
Final trial SHA256: direct
`2d7cb40c28d656c5ab23c5fadd8354c0d2daacd999cc409af4fb0284fa45c123`,
BIP324 `72cb4952d7678bce769d15d3ec5c001b74e9f4dcee56708fe9c0bed3566c8950`.
Exact commands, configuration, raw measurements and validation logs are in
ignored `out/xonly-invalid-candidate/README.md` and `out/xonly-task1b/README.md`.

Possible next research is to offset the public Jacobi cost with a separately
proved field/scalar primitive improvement. Fusing Jacobi into the existing
inverse is not a small safe release patch: the current inverse does not track
Jacobi state, and deferring the check would send invalid/twist inputs through
a ladder whose GLV/Hamburg proofs assume the valid order-`n` curve.
