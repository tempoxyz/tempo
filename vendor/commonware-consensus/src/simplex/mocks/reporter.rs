//! Mock `Reporter` for tests: tracks participants/leaders, verifies activities,
//! records votes/faults, and exposes a simple subscription.
use crate::{
    simplex::{
        elector::{Config as ElectorConfig, Elector},
        scheme,
        types::{
            Activity, Attributable, ConflictingFinalize, ConflictingNotarize, Finalization,
            Finalize, Notarization, Notarize, Nullification, Nullify, NullifyFinalize, Subject,
        },
    },
    types::{Round, View},
    Monitor, Viewable,
};
use commonware_actor::Feedback;
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::{
    certificate::{Scheme, Verifier},
    Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::{
    channel::{
        fallible::AsyncFallibleExt,
        mpsc::{Receiver, Sender},
    },
    ordered::{Quorum, Set},
    sync::Mutex,
    N3f1,
};
use rand_core::CryptoRng;
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::Arc,
};

// Records which validators have participated in a given view/payload pair.
type Participation<P, D> = HashMap<View, HashMap<D, HashSet<P>>>;
type Faults<S, D> = HashMap<<S as Verifier>::PublicKey, HashMap<View, HashSet<Activity<S, D>>>>;

/// Reporter configuration used in tests.
#[derive(Clone, Debug)]
pub struct Config<S: Scheme, L: ElectorConfig<S>> {
    pub participants: Set<S::PublicKey>,
    pub scheme: S,
    pub elector: L,
}

pub struct Reporter<E: CryptoRng, S: Scheme, L: ElectorConfig<S>, D: Digest> {
    context: Arc<Mutex<E>>,
    pub participants: Set<S::PublicKey>,
    scheme: S,
    elector: L::Elector,

    pub leaders: Arc<Mutex<HashMap<View, S::PublicKey>>>,
    pub certified: Arc<Mutex<HashSet<View>>>,
    pub notarizes: Arc<Mutex<Participation<S::PublicKey, D>>>,
    pub notarizations: Arc<Mutex<HashMap<View, Notarization<S, D>>>>,
    pub nullifies: Arc<Mutex<HashMap<View, HashSet<S::PublicKey>>>>,
    pub nullifications: Arc<Mutex<HashMap<View, Nullification<S>>>>,
    pub finalizes: Arc<Mutex<Participation<S::PublicKey, D>>>,
    pub finalizations: Arc<Mutex<HashMap<View, Finalization<S, D>>>>,
    pub faults: Arc<Mutex<Faults<S, D>>>,
    pub invalid_votes: Arc<Mutex<usize>>,
    pub invalid_certificates: Arc<Mutex<usize>>,

    latest: Arc<Mutex<View>>,
    subscribers: Arc<Mutex<Vec<Sender<View>>>>,
}

impl<E, S, L, D> Clone for Reporter<E, S, L, D>
where
    E: CryptoRng,
    S: Scheme,
    L: ElectorConfig<S>,
    L::Elector: Clone,
    D: Digest,
{
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            participants: self.participants.clone(),
            scheme: self.scheme.clone(),
            elector: self.elector.clone(),
            leaders: self.leaders.clone(),
            certified: self.certified.clone(),
            notarizes: self.notarizes.clone(),
            notarizations: self.notarizations.clone(),
            nullifies: self.nullifies.clone(),
            nullifications: self.nullifications.clone(),
            finalizes: self.finalizes.clone(),
            finalizations: self.finalizations.clone(),
            faults: self.faults.clone(),
            invalid_votes: self.invalid_votes.clone(),
            invalid_certificates: self.invalid_certificates.clone(),
            latest: self.latest.clone(),
            subscribers: self.subscribers.clone(),
        }
    }
}

impl<E, S, L, D> Reporter<E, S, L, D>
where
    E: CryptoRng,
    S: Scheme,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
{
    pub fn new(context: E, cfg: Config<S, L>) -> Self {
        // Build elector with participants
        let elector = cfg.elector.build(&cfg.participants);

        Self {
            context: Arc::new(Mutex::new(context)),
            participants: cfg.participants,
            scheme: cfg.scheme,
            elector,
            leaders: Arc::new(Mutex::new(HashMap::new())),
            certified: Arc::new(Mutex::new(HashSet::new())),
            notarizes: Arc::new(Mutex::new(HashMap::new())),
            notarizations: Arc::new(Mutex::new(HashMap::new())),
            nullifies: Arc::new(Mutex::new(HashMap::new())),
            nullifications: Arc::new(Mutex::new(HashMap::new())),
            finalizes: Arc::new(Mutex::new(HashMap::new())),
            finalizations: Arc::new(Mutex::new(HashMap::new())),
            faults: Arc::new(Mutex::new(HashMap::new())),
            invalid_votes: Arc::new(Mutex::new(0)),
            invalid_certificates: Arc::new(Mutex::new(0)),
            latest: Arc::new(Mutex::new(View::zero())),
            subscribers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn certified(&self, round: Round, certificate: &S::Certificate) {
        // Record that this view has a certificate
        self.certified.lock().insert(round.view());

        // We use the certificate from view N to determine the leader for view N+1.
        let next_round = Round::new(round.epoch(), round.view().next());
        let mut leaders = self.leaders.lock();
        leaders.entry(next_round.view()).or_insert_with(|| {
            let leader = self.elector.elect(next_round, Some(certificate));
            self.participants.key(leader).cloned().unwrap()
        });
    }

    pub fn assert_no_faults(&self) {
        let faults = self.faults.lock();
        assert!(faults.is_empty(), "faults detected");
    }

    pub fn assert_no_invalid(&self) {
        let invalid_votes = self.invalid_votes.lock();
        let invalid_certificates = self.invalid_certificates.lock();
        assert_eq!(*invalid_votes, 0, "invalid votes detected");
        assert_eq!(*invalid_certificates, 0, "invalid certificates detected");
    }
}

impl<E, S, L, D> crate::Reporter for Reporter<E, S, L, D>
where
    E: CryptoRng + Send + Sync + 'static,
    S: scheme::Scheme<D>,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
{
    type Activity = Activity<S, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // We check signatures for all messages to ensure that the prover is working correctly
        // but in production this isn't necessary (as signatures are already verified in
        // consensus).
        match &activity {
            Activity::Notarize(notarize) => {
                if !notarize.verify(&mut *self.context.lock(), &self.scheme, &Sequential) {
                    *self.invalid_votes.lock() += 1;
                    return Feedback::Ok;
                }
                let encoded = notarize.encode();
                Notarize::<S, D>::decode(encoded).unwrap();
                let public_key = self.participants.key(notarize.signer()).unwrap().clone();
                self.notarizes
                    .lock()
                    .entry(notarize.view())
                    .or_default()
                    .entry(notarize.proposal.payload)
                    .or_default()
                    .insert(public_key);
            }
            Activity::Notarization(notarization) | Activity::Certification(notarization) => {
                // Verify notarization
                let view = notarization.view();
                if !self.scheme.verify_certificate::<_, D, N3f1>(
                    &mut *self.context.lock(),
                    Subject::Notarize {
                        proposal: &notarization.proposal,
                    },
                    &notarization.certificate,
                    &Sequential,
                ) {
                    *self.invalid_certificates.lock() += 1;
                    return Feedback::Ok;
                }
                let encoded = notarization.encode();
                Notarization::<S, D>::decode_cfg(encoded, &self.scheme.certificate_codec_config())
                    .unwrap();
                self.notarizations.lock().insert(view, notarization.clone());
                self.certified(notarization.round(), &notarization.certificate);
            }
            Activity::Nullify(nullify) => {
                if !nullify.verify(&mut *self.context.lock(), &self.scheme, &Sequential) {
                    *self.invalid_votes.lock() += 1;
                    return Feedback::Ok;
                }
                let encoded = nullify.encode();
                Nullify::<S>::decode(encoded).unwrap();
                let public_key = self.participants.key(nullify.signer()).unwrap().clone();
                self.nullifies
                    .lock()
                    .entry(nullify.view())
                    .or_default()
                    .insert(public_key);
            }
            Activity::Nullification(nullification) => {
                // Verify nullification
                let view = nullification.view();
                if !self.scheme.verify_certificate::<_, D, N3f1>(
                    &mut *self.context.lock(),
                    Subject::Nullify {
                        round: nullification.round,
                    },
                    &nullification.certificate,
                    &Sequential,
                ) {
                    *self.invalid_certificates.lock() += 1;
                    return Feedback::Ok;
                }
                let encoded = nullification.encode();
                Nullification::<S>::decode_cfg(encoded, &self.scheme.certificate_codec_config())
                    .unwrap();
                self.nullifications
                    .lock()
                    .insert(view, nullification.clone());
                self.certified(nullification.round, &nullification.certificate);
            }
            Activity::Finalize(finalize) => {
                if !finalize.verify(&mut *self.context.lock(), &self.scheme, &Sequential) {
                    *self.invalid_votes.lock() += 1;
                    return Feedback::Ok;
                }
                let encoded = finalize.encode();
                Finalize::<S, D>::decode(encoded).unwrap();
                let public_key = self.participants.key(finalize.signer()).unwrap().clone();
                self.finalizes
                    .lock()
                    .entry(finalize.view())
                    .or_default()
                    .entry(finalize.proposal.payload)
                    .or_default()
                    .insert(public_key);
            }
            Activity::Finalization(finalization) => {
                // Verify finalization
                let view = finalization.view();
                if !self.scheme.verify_certificate::<_, D, N3f1>(
                    &mut *self.context.lock(),
                    Subject::Finalize {
                        proposal: &finalization.proposal,
                    },
                    &finalization.certificate,
                    &Sequential,
                ) {
                    *self.invalid_certificates.lock() += 1;
                    return Feedback::Ok;
                }
                let encoded = finalization.encode();
                Finalization::<S, D>::decode_cfg(encoded, &self.scheme.certificate_codec_config())
                    .unwrap();
                self.finalizations.lock().insert(view, finalization.clone());
                self.certified(finalization.round(), &finalization.certificate);

                // Send message to subscribers
                *self.latest.lock() = finalization.view();
                let mut subscribers = self.subscribers.lock();
                for subscriber in subscribers.iter_mut() {
                    subscriber.try_send_lossy(finalization.view());
                }
            }
            Activity::ConflictingNotarize(conflicting) => {
                let view = conflicting.view();
                if !conflicting.verify(&mut *self.context.lock(), &self.scheme, &Sequential) {
                    *self.invalid_votes.lock() += 1;
                    return Feedback::Ok;
                }
                let encoded = conflicting.encode();
                ConflictingNotarize::<S, D>::decode(encoded).unwrap();
                let public_key = self.participants.key(conflicting.signer()).unwrap().clone();
                self.faults
                    .lock()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
            Activity::ConflictingFinalize(conflicting) => {
                let view = conflicting.view();
                if !conflicting.verify(&mut *self.context.lock(), &self.scheme, &Sequential) {
                    *self.invalid_votes.lock() += 1;
                    return Feedback::Ok;
                }
                let encoded = conflicting.encode();
                ConflictingFinalize::<S, D>::decode(encoded).unwrap();
                let public_key = self.participants.key(conflicting.signer()).unwrap().clone();
                self.faults
                    .lock()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
            Activity::NullifyFinalize(conflicting) => {
                let view = conflicting.view();
                if !conflicting.verify(&mut *self.context.lock(), &self.scheme, &Sequential) {
                    *self.invalid_votes.lock() += 1;
                    return Feedback::Ok;
                }
                let encoded = conflicting.encode();
                NullifyFinalize::<S, D>::decode(encoded).unwrap();
                let public_key = self.participants.key(conflicting.signer()).unwrap().clone();
                self.faults
                    .lock()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(activity);
            }
        }
        Feedback::Ok
    }
}

impl<E, S, L, D> Monitor for Reporter<E, S, L, D>
where
    E: CryptoRng + Send + Sync + 'static,
    S: Scheme,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
{
    type Index = View;

    async fn subscribe(&mut self) -> (Self::Index, Receiver<Self::Index>) {
        let (tx, rx) = commonware_utils::channel::mpsc::channel(128);
        self.subscribers.lock().push(tx);
        let latest = *self.latest.lock();
        (latest, rx)
    }
}
