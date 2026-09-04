use super::types::Node;
use commonware_cryptography::{certificate::Scheme, Digest, PublicKey};
use std::collections::{hash_map::Entry, HashMap};

/// Manages the highest-height chunk for each sequencer.
#[derive(Default, Debug)]
pub struct TipManager<C: PublicKey, S: Scheme, D: Digest> {
    // The highest-height chunk for each sequencer.
    // The chunk must have the certificate of its parent.
    // Existence of the chunk implies:
    // - The existence of the sequencer's entire chunk chain (from height zero)
    // - That the chunk has been acked by this validator.
    tips: HashMap<C, Node<C, S, D>>,
}

impl<C: PublicKey, S: Scheme, D: Digest> TipManager<C, S, D> {
    /// Creates a new `TipManager`.
    pub fn new() -> Self {
        Self {
            tips: HashMap::new(),
        }
    }

    /// Inserts a new tip. Returns true if the tip is new.
    /// Panics if the new tip is lower-height than the existing tip.
    pub fn put(&mut self, node: &Node<C, S, D>) -> bool {
        match self.tips.entry(node.chunk.sequencer.clone()) {
            Entry::Vacant(e) => {
                e.insert(node.clone());
                true
            }
            Entry::Occupied(mut e) => {
                let old = e.get();
                if old.chunk.height > node.chunk.height {
                    panic!("Attempted to insert a lower-height tip");
                }
                if old.chunk.height == node.chunk.height {
                    assert!(
                        old.chunk.payload == node.chunk.payload,
                        "New tip has the same height but a different payload"
                    );
                    return false;
                }
                e.insert(node.clone());
                true
            }
        }
    }

    /// Returns the tip for the given sequencer.
    pub fn get(&self, sequencer: &C) -> Option<Node<C, S, D>> {
        self.tips.get(sequencer).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ordered_broadcast::{
            scheme::{bls12381_multisig, bls12381_threshold, ed25519, secp256r1, Scheme},
            types::{Chunk, ChunkSigner},
        },
        types::Height,
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::PublicKey,
        sha256::{Digest as Sha256Digest, Sha256},
        Hasher as _, Signer as _,
    };
    use commonware_math::algebra::Random;
    use commonware_utils::{test_rng, TestRng};
    use std::panic::catch_unwind;

    const NAMESPACE: &[u8] = b"tip_manager_test";

    /// Creates a node for testing with a given scheme.
    fn create_node<S: Scheme<PublicKey, Sha256Digest>>(
        fixture: &Fixture<S>,
        sequencer_idx: usize,
        height: Height,
        payload: &str,
    ) -> Node<PublicKey, S, Sha256Digest> {
        let sequencer = fixture.participants[sequencer_idx].clone();
        let digest = Sha256::hash(payload.as_bytes());
        let chunk = Chunk::new(sequencer, height, digest);

        // Sign the chunk using a deterministic ed25519 key (since Node.signature is P::Signature,
        // which is ed25519::Signature for our PublicKey type)
        let mut rng = TestRng::new(sequencer_idx as u64);
        let private_key = commonware_cryptography::ed25519::PrivateKey::random(&mut rng);
        let mut signer = ChunkSigner::new(b"test", private_key);
        let signature = signer.sign(&chunk);

        Node::new(chunk, signature, None)
    }

    /// Generates a deterministic public key for testing using the provided seed.
    fn deterministic_public_key(seed: u64) -> PublicKey {
        let mut rng = TestRng::new(seed);
        commonware_cryptography::ed25519::PrivateKey::random(&mut rng).public_key()
    }

    fn put_new_tip<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let fixture = fixture(&mut test_rng(), NAMESPACE, 4);
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let node = create_node(&fixture, 0, Height::new(1), "payload");
        let key = node.chunk.sequencer.clone();
        assert!(manager.put(&node));
        let got = manager.get(&key).unwrap();
        assert_eq!(got.chunk, node.chunk);
        assert_eq!(got.signature, node.signature);
        assert_eq!(got.parent, node.parent);
    }

    #[test]
    fn test_put_new_tip() {
        put_new_tip(ed25519::fixture);
        put_new_tip(secp256r1::fixture);
        put_new_tip(bls12381_multisig::fixture::<MinPk, _>);
        put_new_tip(bls12381_multisig::fixture::<MinSig, _>);
        put_new_tip(bls12381_threshold::fixture::<MinPk, _>);
        put_new_tip(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn put_same_height_same_payload<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let fixture = fixture(&mut test_rng(), NAMESPACE, 4);
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let node = create_node(&fixture, 0, Height::new(1), "payload");
        let key = node.chunk.sequencer.clone();
        assert!(manager.put(&node));
        assert!(!manager.put(&node));
        let got = manager.get(&key).unwrap();
        assert_eq!(got.chunk, node.chunk);
        assert_eq!(got.signature, node.signature);
        assert_eq!(got.parent, node.parent);
    }

    #[test]
    fn test_put_same_height_same_payload() {
        put_same_height_same_payload(ed25519::fixture);
        put_same_height_same_payload(secp256r1::fixture);
        put_same_height_same_payload(bls12381_multisig::fixture::<MinPk, _>);
        put_same_height_same_payload(bls12381_multisig::fixture::<MinSig, _>);
        put_same_height_same_payload(bls12381_threshold::fixture::<MinPk, _>);
        put_same_height_same_payload(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn put_higher_tip<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let fixture = fixture(&mut test_rng(), NAMESPACE, 4);
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let node1 = create_node(&fixture, 0, Height::new(1), "payload1");
        let key = node1.chunk.sequencer.clone();
        assert!(manager.put(&node1));
        let node2 = create_node(&fixture, 0, Height::new(2), "payload2");
        assert!(manager.put(&node2));
        let got = manager.get(&key).unwrap();
        assert_eq!(got.chunk, node2.chunk);
        assert_eq!(got.signature, node2.signature);
        assert_eq!(got.parent, node2.parent);
    }

    #[test]
    fn test_put_higher_tip() {
        put_higher_tip(ed25519::fixture);
        put_higher_tip(secp256r1::fixture);
        put_higher_tip(bls12381_multisig::fixture::<MinPk, _>);
        put_higher_tip(bls12381_multisig::fixture::<MinSig, _>);
        put_higher_tip(bls12381_threshold::fixture::<MinPk, _>);
        put_higher_tip(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn put_lower_tip_panics<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let fixture = fixture(&mut test_rng(), NAMESPACE, 4);
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let node1 = create_node(&fixture, 0, Height::new(2), "payload");
        assert!(manager.put(&node1));
        let node2 = create_node(&fixture, 0, Height::new(1), "payload");
        manager.put(&node2); // Should panic
    }

    #[test]
    fn test_put_lower_tip_panics() {
        assert!(catch_unwind(|| put_lower_tip_panics(ed25519::fixture)).is_err());
        assert!(catch_unwind(|| put_lower_tip_panics(secp256r1::fixture)).is_err());
        assert!(
            catch_unwind(|| put_lower_tip_panics(bls12381_multisig::fixture::<MinPk, _>)).is_err()
        );
        assert!(
            catch_unwind(|| put_lower_tip_panics(bls12381_multisig::fixture::<MinSig, _>)).is_err()
        );
        assert!(
            catch_unwind(|| put_lower_tip_panics(bls12381_threshold::fixture::<MinPk, _>)).is_err()
        );
        assert!(
            catch_unwind(|| put_lower_tip_panics(bls12381_threshold::fixture::<MinSig, _>))
                .is_err()
        );
    }

    fn put_same_height_different_payload_panics<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let fixture = fixture(&mut test_rng(), NAMESPACE, 4);
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let node1 = create_node(&fixture, 0, Height::new(1), "payload1");
        assert!(manager.put(&node1));
        let node2 = create_node(&fixture, 0, Height::new(1), "payload2");
        manager.put(&node2); // Should panic
    }

    #[test]
    fn test_put_same_height_different_payload_panics() {
        assert!(
            catch_unwind(|| put_same_height_different_payload_panics(ed25519::fixture)).is_err()
        );
        assert!(
            catch_unwind(|| put_same_height_different_payload_panics(secp256r1::fixture)).is_err()
        );
        assert!(catch_unwind(|| put_same_height_different_payload_panics(
            bls12381_multisig::fixture::<MinPk, _>
        ))
        .is_err());
        assert!(catch_unwind(|| put_same_height_different_payload_panics(
            bls12381_multisig::fixture::<MinSig, _>
        ))
        .is_err());
        assert!(catch_unwind(|| put_same_height_different_payload_panics(
            bls12381_threshold::fixture::<MinPk, _>
        ))
        .is_err());
        assert!(catch_unwind(|| put_same_height_different_payload_panics(
            bls12381_threshold::fixture::<MinSig, _>
        ))
        .is_err());
    }

    fn get_nonexistent<S>()
    where
        S: Scheme<PublicKey, Sha256Digest>,
    {
        let manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let key = deterministic_public_key(6);
        assert!(manager.get(&key).is_none());
    }

    #[test]
    fn test_get_nonexistent() {
        get_nonexistent::<ed25519::Scheme>();
        get_nonexistent::<secp256r1::Scheme<PublicKey>>();
        get_nonexistent::<bls12381_multisig::Scheme<PublicKey, MinPk>>();
        get_nonexistent::<bls12381_multisig::Scheme<PublicKey, MinSig>>();
        get_nonexistent::<bls12381_threshold::Scheme<PublicKey, MinPk>>();
        get_nonexistent::<bls12381_threshold::Scheme<PublicKey, MinSig>>();
    }

    fn multiple_sequencers<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let fixture = fixture(&mut test_rng(), NAMESPACE, 4);
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let node1 = create_node(&fixture, 0, Height::new(1), "payload1");
        let node2 = create_node(&fixture, 1, Height::new(2), "payload2");
        let key1 = node1.chunk.sequencer.clone();
        let key2 = node2.chunk.sequencer.clone();
        manager.put(&node1);
        manager.put(&node2);

        let got1 = manager.get(&key1).unwrap();
        let got2 = manager.get(&key2).unwrap();
        assert_eq!(got1.chunk, node1.chunk);
        assert_eq!(got2.chunk, node2.chunk);
    }

    #[test]
    fn test_multiple_sequencers() {
        multiple_sequencers(ed25519::fixture);
        multiple_sequencers(secp256r1::fixture);
        multiple_sequencers(bls12381_multisig::fixture::<MinPk, _>);
        multiple_sequencers(bls12381_multisig::fixture::<MinSig, _>);
        multiple_sequencers(bls12381_threshold::fixture::<MinPk, _>);
        multiple_sequencers(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn put_multiple_updates<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let fixture = fixture(&mut test_rng(), NAMESPACE, 4);
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();

        // Insert tip with height 1.
        let node1 = create_node(&fixture, 0, Height::new(1), "payload1");
        let key = node1.chunk.sequencer.clone();
        manager.put(&node1);
        let got1 = manager.get(&key).unwrap();
        assert_eq!(got1.chunk.height, Height::new(1));
        assert_eq!(got1.chunk.payload, node1.chunk.payload);

        // Insert tip with height 2.
        let node2 = create_node(&fixture, 0, Height::new(2), "payload2");
        manager.put(&node2);
        let got2 = manager.get(&key).unwrap();
        assert_eq!(got2.chunk.height, Height::new(2));
        assert_eq!(got2.chunk.payload, node2.chunk.payload);

        // Insert tip with height 3.
        let node3 = create_node(&fixture, 0, Height::new(3), "payload3");
        manager.put(&node3);
        let got3 = manager.get(&key).unwrap();
        assert_eq!(got3.chunk.height, Height::new(3));
        assert_eq!(got3.chunk.payload, node3.chunk.payload);

        // Re-inserting the same tip should return false.
        assert!(!manager.put(&node3));

        // Insert tip with height 4.
        let node4 = create_node(&fixture, 0, Height::new(4), "payload4");
        manager.put(&node4);
        let got4 = manager.get(&key).unwrap();
        assert_eq!(got4.chunk.height, Height::new(4));
        assert_eq!(got4.chunk.payload, node4.chunk.payload);
    }

    #[test]
    fn test_put_multiple_updates() {
        put_multiple_updates(ed25519::fixture);
        put_multiple_updates(secp256r1::fixture);
        put_multiple_updates(bls12381_multisig::fixture::<MinPk, _>);
        put_multiple_updates(bls12381_multisig::fixture::<MinSig, _>);
        put_multiple_updates(bls12381_threshold::fixture::<MinPk, _>);
        put_multiple_updates(bls12381_threshold::fixture::<MinSig, _>);
    }
}
