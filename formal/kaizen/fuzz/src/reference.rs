//! Independent reference follower step, written from Tempo's and commonware's Rust sources
//! (not from the Lean code):
//!
//! * decoding: commonware's own Finalization<Scheme<PublicKey, MinSig>, Digest>::decode
//!   (DecodeExt: rejects trailing bytes), as FinalizationVerifier::decode_and_verify does;
//! * payload == block digest, epoch == FixedEpocher::containing(height).epoch()
//!   (crates/consensus/src/finalization_verifier/mod.rs);
//! * identity: SchemeProvider (learned) first, else the network identity when
//!   epoch >= from_epoch, and a fallback success registers the network scheme under the epoch
//!   (FinalizationVerifier::verify_certificate), with SchemeProvider::register's
//!   refuse-to-replace-a-different-identity assertion modelled as a flagged event;
//! * linkage: height == tip + 1 (Height::next), parent hash == tip hash, Round (epoch, view)
//!   strictly increasing using commonware's Ord on Round;
//! * boundary: info.last() == height requires a DKG outcome for epoch.next()
//!   (decode_dkg_outcome_and_register_boundary registers outcome.epoch);
//! * execution: the execution oracle against the tip's state root, after the signature.
//!
//! The order of checks and the result codes follow the follower spec's contract
//! (Kaizen/Follower/Spec.lean result codes 0..12), since that order is the interface.
use std::{collections::BTreeMap, num::NonZeroU64};

use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    Epochable as _,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
    types::{Epoch, Epocher as _, FixedEpocher, Height, Round},
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, ed25519::PublicKey, sha256::Digest,
};

use crate::{Candidate, Config, TipView, oracle};

pub type Fin = Finalization<Scheme<PublicKey, MinSig>, Digest>;

pub mod code {
    pub const ACCEPTED: u8 = 0;
    pub const MALFORMED: u8 = 1;
    pub const DIGEST_MISMATCH: u8 = 2;
    pub const EPOCH_MISMATCH: u8 = 3;
    pub const IDENTITY_UNAVAILABLE: u8 = 4;
    pub const BAD_SIGNATURE: u8 = 5;
    pub const HEIGHT_NOT_NEXT: u8 = 6;
    pub const PARENT_MISMATCH: u8 = 7;
    pub const ROUND_NOT_INCREASING: u8 = 8;
    pub const MISSING_DKG: u8 = 9;
    pub const DKG_EPOCH_MISMATCH: u8 = 10;
    pub const BAD_CONFIG: u8 = 11;
    pub const EXECUTION_INVALID: u8 = 12;
}

#[derive(Clone, Debug)]
pub struct Tip {
    pub height: Height,
    pub digest: Vec<u8>,
    pub round: Round,
    pub state_root: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Code(u8),
    /// An input Tempo's code cannot process (it panics or cannot be configured); the Lean core
    /// still decides it. The harness records these and stops the sequence.
    Unsupported(&'static str),
}

#[derive(Clone, Debug)]
pub struct RefState {
    pub tip: Option<Tip>,
    pub epoch_length: u64,
    pub from_epoch: u64,
    pub network_key: Vec<u8>,
    /// SchemeProvider: epoch -> identity bytes.
    pub schemes: BTreeMap<Epoch, Vec<u8>>,
    /// Events where Tempo's SchemeProvider::register would panic (different identity for an
    /// already registered epoch). The Lean model overwrites instead.
    pub register_conflicts: u64,
}

impl RefState {
    pub fn new(cfg: &Config) -> Self {
        Self {
            tip: None,
            epoch_length: cfg.epoch_length,
            from_epoch: cfg.from_epoch,
            network_key: cfg.network_key.clone(),
            schemes: BTreeMap::new(),
            register_conflicts: 0,
        }
    }

    /// FinalizationVerifier::verify_certificate's identity selection: (identity, used fallback).
    pub fn identity(&self, epoch: Epoch) -> Option<(&[u8], bool)> {
        match self.schemes.get(&epoch) {
            Some(k) => Some((k.as_slice(), false)),
            None if epoch.get() >= self.from_epoch => Some((self.network_key.as_slice(), true)),
            None => None,
        }
    }

    pub fn tip_view(&self) -> TipView {
        self.tip
            .as_ref()
            .map(|t| (t.height.get(), t.digest.clone(), t.state_root.clone()))
    }

    fn register(&mut self, epoch: Epoch, key: Vec<u8>) {
        if let Some(existing) = self.schemes.get(&epoch)
            && *existing != key
        {
            self.register_conflicts += 1;
        }
        self.schemes.insert(epoch, key);
    }

    pub fn step(&mut self, c: &Candidate) -> Outcome {
        use code::*;
        // FixedEpocher takes a NonZeroU64 and panics on length one.
        let Some(len) = NonZeroU64::new(self.epoch_length) else {
            return Outcome::Code(BAD_CONFIG);
        };
        if len.get() == 1 {
            return Outcome::Unsupported("FixedEpocher::new panics for epoch length 1");
        }
        let epocher = FixedEpocher::new(len);

        let Ok(f) = Fin::decode(c.cert.as_slice()) else {
            return Outcome::Code(MALFORMED);
        };
        if f.proposal.payload.0.as_slice() != c.digest.as_slice() {
            return Outcome::Code(DIGEST_MISMATCH);
        }
        // Heights in the final partial epoch belong to no representable epoch.
        let Some(info) = epocher.containing(Height::new(c.height)) else {
            return Outcome::Code(EPOCH_MISMATCH);
        };
        if f.epoch() != info.epoch() {
            return Outcome::Code(EPOCH_MISMATCH);
        }
        if let Some(t) = &self.tip {
            if t.height.get().checked_add(1) != Some(c.height) {
                return Outcome::Code(HEIGHT_NOT_NEXT);
            }
            if t.digest != c.parent {
                return Outcome::Code(PARENT_MISMATCH);
            }
            if f.proposal.round <= t.round {
                return Outcome::Code(ROUND_NOT_INCREASING);
            }
        }
        let boundary = info.last() == Height::new(c.height);
        let outcome = if boundary {
            match &c.dkg {
                None => return Outcome::Code(MISSING_DKG),
                Some((e, k)) => {
                    // Epoch::next panics on overflow; an overflowing epoch has no next outcome.
                    if f.epoch().get().checked_add(1) != Some(*e) {
                        return Outcome::Code(DKG_EPOCH_MISMATCH);
                    }
                    Some((Epoch::new(*e), k.clone()))
                }
            }
        } else {
            None
        };
        let Some((key, used_fallback)) = self.identity(f.epoch()) else {
            return Outcome::Code(IDENTITY_UNAVAILABLE);
        };
        let key = key.to_vec();
        let p = &f.proposal;
        let sig = f.certificate.encode();
        if !oracle::verify_sig(
            &key,
            p.round.epoch().get(),
            p.round.view().get(),
            p.parent.get(),
            &p.payload.0,
            &sig,
        ) {
            return Outcome::Code(BAD_SIGNATURE);
        }
        // verify_certificate registers a successfully used fallback scheme under the epoch as
        // soon as the signature verifies (before any later check of the caller).
        if used_fallback {
            self.register(f.epoch(), key);
        }
        if let Some(t) = &self.tip
            && !oracle::verify_exec(&t.state_root, &c.digest, &c.state_root)
        {
            return Outcome::Code(EXECUTION_INVALID);
        }
        // Accept: register the boundary's outcome for the next epoch.
        if let Some((e, k)) = outcome {
            self.register(e, k);
        }
        self.tip = Some(Tip {
            height: Height::new(c.height),
            digest: c.digest.clone(),
            round: p.round,
            state_root: c.state_root.clone(),
        });
        Outcome::Code(ACCEPTED)
    }
}
