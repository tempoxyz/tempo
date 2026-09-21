# Benchmark presets

Expiring-nonce templates use `nonce: { uniform: [0, 18446744073709551615] }`
(TIP-1106) and require Tempo T12 or later, plus a txgen build supporting nonce
generators. Transaction uniqueness comes from a seeded random nonce; fees and
validity bounds are unchanged.

For benchmarks against pre-T12 hardforks, remove the `nonce` entry from each
expiring template in the source preset. This restores txgen's zero nonce and fee-bump
behavior. Protocol-nonce and 2D-nonce presets are unaffected.

A `nonce: null` merge overlay does not remove an inherited nonce generator:
txgen treats null overlays as no-ops.
