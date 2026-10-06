//! Proof schemes accepted by ZK signatures ([TIP-1131]).
//!
//! [TIP-1131]: https://docs.tempo.xyz/protocol/tips/tip-1131

use crate::groth16::{PreparedVerifyingKey, VERIFYING_KEY_LENGTH, VerifyingKey};
use std::sync::OnceLock;

/// Scheme `0x01`: OIDC ID tokens signed with RS256 ([TIP-1133]).
///
/// [TIP-1133]: https://docs.tempo.xyz/protocol/tips/tip-1133
pub const SCHEME_OIDC_RS256_V1: u8 = 0x01;

/// The OIDC address namespace.
pub const NAMESPACE_OIDC: u8 = 0x01;

/// `VK_OIDC_RS256_V1` from the TIP-1133 trusted setup. It is fixed when the ceremony completes;
/// until then scheme `0x01` has no verifying key and rejects every proof.
const VK_OIDC_RS256_V1: Option<&[u8; VERIFYING_KEY_LENGTH]> = None;

/// A circuit and verifying key for one statement format.
#[derive(Debug)]
pub struct Scheme {
    /// The scheme byte carried in signatures.
    pub id: u8,
    /// The namespace mixed into addresses. Schemes sharing a namespace share addresses.
    pub namespace: u8,
    /// The longest allowed `valid_until - issued_at`, in seconds.
    pub max_window: u64,
    /// Whether the scheme also accepts message signatures.
    pub message_form: bool,
    verifying_key: Option<&'static [u8; VERIFYING_KEY_LENGTH]>,
    prepared: OnceLock<Option<PreparedVerifyingKey>>,
}

static OIDC_RS256_V1: Scheme = Scheme {
    id: SCHEME_OIDC_RS256_V1,
    namespace: NAMESPACE_OIDC,
    max_window: 600,
    message_form: true,
    verifying_key: VK_OIDC_RS256_V1,
    prepared: OnceLock::new(),
};

/// Returns the scheme with the given byte, if one is defined.
pub fn scheme(id: u8) -> Option<&'static Scheme> {
    match id {
        SCHEME_OIDC_RS256_V1 => Some(&OIDC_RS256_V1),
        _ => None,
    }
}

impl Scheme {
    /// Returns the scheme's prepared verifying key, or `None` while it has none.
    pub fn verifying_key(&'static self) -> Option<&'static PreparedVerifyingKey> {
        #[cfg(feature = "test-utils")]
        if let Some(key) = crate::test_utils::verifying_key_override(self.id) {
            return Some(key);
        }
        self.prepared
            .get_or_init(|| {
                let bytes = self.verifying_key?;
                let key = VerifyingKey::decode(bytes).expect("scheme verifying keys are valid");
                Some(key.prepare())
            })
            .as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_scheme_parameters() {
        let scheme = scheme(SCHEME_OIDC_RS256_V1).unwrap();
        assert_eq!(scheme.namespace, NAMESPACE_OIDC);
        assert_eq!(scheme.max_window, 600);
        assert!(scheme.message_form);
        assert!(super::scheme(0x00).is_none());
        assert!(super::scheme(0x02).is_none());
    }
}
