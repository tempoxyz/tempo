---
tempo-precompiles: minor
---

From T14, `SignatureVerifier::{verify_keychain, verify_keychain_admin}` return false for a key ID with a config commitment and require the signature type to match the stored key type, and `AccountKeychain::is_admin_key` no longer treats a committed account's own key as an implicit admin. Earlier forks are unchanged.
