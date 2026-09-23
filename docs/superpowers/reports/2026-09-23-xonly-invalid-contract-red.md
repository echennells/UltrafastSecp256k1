# Public x-only invalid-input contract — intentional RED

Status: diagnostic test only. It must fail in the native build until the
public `ct::ecmult_const_xonly` invalid-point contract is repaired. Do not
merge this state to `main` or call it v4.6-ready.

The new C++ test covers valid direct/scaled generator fractions, scalar zero,
the pinned Hamburg witness, an invalid zero denominator, and off-curve
`xn=5,xd=1,q=7`. Independent manager execution of the native binary produced
only the expected off-curve failure:

```
got=9f78332fb6146066b4bca724c24c1bc88f7190cee8862112fa4d799142b252bb
want=0000000000000000000000000000000000000000000000000000000000000000
```

The same test passes all six cases in the forced-portable build. Existing
Hamburg witness and BIP324 transport tests pass. The zero-denominator check
already passes before repair and is a contract guard, not a RED witness.

Same-flags pre-fix native Release/ASM/LTO benchmark binaries are frozen in
ignored `out/xonly-invalid-prefx/`; direct x-only SHA256 is
`3abeabae105de2df274d71935c95ce054a4f13ae9765899e0657547ba86add98`
and BIP324 SHA256 is
`586ae74bd4e54e8aca7c5edc8875d9d1d842935ecfdb07dc0a9658c32bb24fe5`.
The ignored `README.md` there records exact build/test commands, six raw
orientation runs and caveats. Those runs are **not** an acceptance comparison;
candidate binaries must be compared in pinned interleaved pairs.
