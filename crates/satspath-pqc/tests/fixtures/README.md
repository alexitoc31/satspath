# ML-DSA-65 published known-answer fixtures

`mldsa65-acvp.json` contains unmodified test fields selected from NIST's
[ACVP-Server repository](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files),
commit `975de31eb83d87039ec88934fdc47d8c312b892d`. Inputs come from `prompt.json`; expected outputs come from
`expectedResults.json` in each directory below. These are published test keys,
not operational secrets. No expected result was generated with `ml-dsa` or SatsPath.

| Directory | tgId | tcId | Coverage |
| --- | --- | --- | --- |
| ML-DSA-keyGen-FIPS204 | 2 | 26 | Seed to full public and expanded secret key |
| ML-DSA-sigGen-FIPS204 | 3 | 41 | Deterministic external pure signing with nonempty context |
| ML-DSA-sigVer-FIPS204 | 3 | 38, 43 | External pure verification: rejection and acceptance |

The compact subset keeps upstream hex strings, field names, and test IDs;
`tgId` is copied from the containing group. Signing and verification use the
external FIPS 204 interface, including its message/context framing. The project
snapshot tests remain separate. This subset is a regression check, not ACVP
certification or exhaustive FIPS 204 coverage.

## Source file SHA-256 digests

Paths are relative to `gen-val/json-files/` at the pinned commit above.

- `ML-DSA-keyGen-FIPS204/prompt.json`: `43e81ad820e495dbcad086fe27c1008393a8c32100bbbff77c558c3f06dcefef`
- `ML-DSA-keyGen-FIPS204/expectedResults.json`: `361f47ca19d592adcc66ff2cb591686ad785fea157b295648738bed6921a68df`
- `ML-DSA-sigGen-FIPS204/prompt.json`: `447749d72817b211160d243311ce32302f3023e59c355b0f70be2bd3e9e7830d`
- `ML-DSA-sigGen-FIPS204/expectedResults.json`: `228d011bbe274aeb93e22eea1e0d57b78f43795cf6a64fb5ef1e626485a0bedb`
- `ML-DSA-sigVer-FIPS204/prompt.json`: `e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e`
- `ML-DSA-sigVer-FIPS204/expectedResults.json`: `e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6`
