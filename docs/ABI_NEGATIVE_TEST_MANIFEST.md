# ABI Negative-Test Manifest

Generated: 2026-09-22T18:56:12.129399+00:00

Machine-generated hostile-caller coverage manifest for the public `ufsecp_*` ABI.

## Summary

- Exported functions scanned: 206
- Blocking functions: 0
- Null rejection evidence: 206
- Zero-edge evidence: 199
- Invalid-content evidence: 203
- Success-smoke evidence: 206

## Blocking Functions

| Function | Missing Checks | Header |
|----------|----------------|--------|
| *(none)* | | |

## Rule

Every exported `ufsecp_*` function should satisfy the hostile-caller quartet when the contract implies it:

1. `null_rejection`
2. `zero_edge`
3. `invalid_content`
4. `success_smoke`

