# Benchmark presets

Expiring-nonce templates use `randomize_expiring_nonce: true` (TIP-1106) and
require Tempo T12 or later, plus a txgen build supporting that option. Transaction
uniqueness comes from a seeded random nonce; fees and validity bounds are unchanged.

For benchmarks against pre-T12 hardforks, override `randomize_expiring_nonce` to
`false` on each expiring template. This restores txgen's zero nonce and fee-bump
behavior. Protocol-nonce and 2D-nonce presets are unaffected.
