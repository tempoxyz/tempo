# Native public-read calibration

These 15 presets each make one typed STATICCALL through `NativeReadCalibration`.
The generated `native-read-smoke` preset mixes them uniformly for low-rate runtime
validation. None performs governance, key authorization, token movement or claims.

| Family | Method exercised | Minimum fork for this fixture |
| --- | --- | --- |
| TIP20 | balanceOf(caller) on pathUSD | Genesis |
| TIP20 factory | isTIP20(pathUSD) | Genesis |
| TIP403 | policyIdCounter() | Genesis |
| Fee manager | userTokens(caller) | Genesis |
| DEX | balanceOf(caller, pathUSD) | Genesis |
| Nonce | getNonce(caller, 1) | Genesis |
| Validator config V1 | validatorCount() | Genesis |
| Validator config V2 | validatorCount() | Genesis |
| Keychain | isAdminKey(caller, caller) | T6 |
| Address registry | resolveRecipient(caller) | T3 |
| Channel reserve | storageCredits(caller) | T7 |
| Receive-policy guard | balanceOf(valid unknown receipt) | T6 |
| Storage credits | balanceOf(caller) | T7 |
| Current committee | getCommitteeMembers() | T8 |
| Zone factory | owner() | T10 |

The gates were checked in the system-address registry, native lookup, and each
selected selector's dispatch implementation. Run the combined smoke on T10 or
later; this source-level check is not proof of a live mainnet deployment's fork.
SignatureVerifier is separate: the existing `signature-recover` preset exercises
secp256k1 recovery, and the `precompile-native-*` fixtures add explicit
secp256k1/P256/WebAuthn recover/verify calls with pending runtime validation.
Keychain/admin-key variants still need coverage.

The constructor checks that the factory recognizes pathUSD and that its deployer
has a positive pathUSD balance. Solidity return decoding rejects absent/invalid
ABI responses; it does not independently verify every returned state value.
Caller-dependent reads use the actual funded workload signer, not the wrapper's
address. The guard fixture queries a structurally valid receipt absent from the
fresh benchmark state; its expected balance is zero, and it never claims funds.
Committee/validator cases reflect the benchmark's two-validator state only.

These are public-read coverage points, not complete native gas-price assessments.
They exclude mutation/lifecycle paths, growing state, active-key/policy lookups,
populated DEX/channel positions, larger committees and governance operations.
Existing transaction authentication, fee processing and wrapper costs are still
included, so the rates cannot directly determine a per-method tariff.

Build with `compile.cjs /path/to/solc/package NativeReadCalibration` using the same
solc settings as the other fixtures. `native-presets.py` emits a JSON
filename-to-YAML map for reproducible individual and smoke preset generation.
