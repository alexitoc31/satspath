# NIST ML-DSA-65 verification vectors

`nist_mldsa65_sigver.json` contains public verification inputs and expected
results from NIST's [ACVP-Server](https://github.com/usnistgov/ACVP-Server), pinned
to commit `975de31eb83d87039ec88934fdc47d8c312b892d`.

Sources under `gen-val/json-files/ML-DSA-sigVer-FIPS204/`:

- [prompt.json](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json)
  (SHA-256 `e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e`)
- [expectedResults.json](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json)
  (SHA-256 `e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6`)

The fixture selects `tgId: 3` (`ML-DSA-65`, `signatureInterface: external`,
`preHash: pure`), cases `tcId: 34, 39, 43`. Every selected prompt field is copied
unchanged; `testPassed` is joined from the expected results by `tgId` and `tcId`.
Cases 34 and 39 must be rejected; case 43 must be accepted. Case 39 has an empty
context; the others exercise nonempty contexts. The test uses FIPS 204 Algorithm
3 (`verify_with_context`), preserving NIST's context and message bytes.

Case `tcId: 35` is additionally selected from the same group and interface at
commit `112690e8484dba7077709a05b1f3af58ddefdd5d`:

- [prompt.json](https://github.com/usnistgov/ACVP-Server/blob/112690e8484dba7077709a05b1f3af58ddefdd5d/gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json)
  (SHA-256 `2a9b7fcbefdd8e69dd6fbe6b4abb7130d855e8429aaa6f4904385e68b7e63d3a`)
- [expectedResults.json](https://github.com/usnistgov/ACVP-Server/blob/112690e8484dba7077709a05b1f3af58ddefdd5d/gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json)
  (SHA-256 `33e0ea7dd9c3b0206712da50286ad746864371433977225ab77e8aae76358842`)

Its prompt fields and expected verdict are copied unchanged. Case 35 must be
accepted with an empty context; it also exercises the context-free `verify` API
used by `hybrid_verify`. The newer pinned group has no passing empty-context case.

These are verification-only fixtures with no private keys or seeds. Tests run
offline and do not generate their expected results using the implementation
under test. This small subset supplements the local regression snapshots; it
does not constitute NIST certification or exhaustive FIPS 204 conformance.
