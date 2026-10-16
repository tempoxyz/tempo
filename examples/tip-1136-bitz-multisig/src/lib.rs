//! TIP-1136 `PrivateAuthorizationV1`, private weighted multisig profile, proved
//! with BitZ: integer rank-1 constraints over bit-decomposed witnesses,
//! committed in GF(2^128) and opened with Ligerito (binary-field WHIR-style
//! proximity testing) through Flock.
//!
//! Research prototype. Unaudited, not zero-knowledge (see the README), and
//! must not secure funds.

pub mod ecdsa;
pub mod ecdsa_fast;
pub mod policy;
pub mod relation;

pub use bitz_cli::end_to_end::{CircuitProofSystem, Error, Proof};
pub use pcs::SecurityLevel;

use policy::{Profile, Statement, Witness};
use relation::{PrivateAuthorization, witness_bits};

/// The proof system for one circuit profile.
///
/// Public values are input bits checked by a PCS opening, so one system serves
/// every statement: provers and verifiers build it once per profile, not per
/// proof.
pub struct Authorizer {
    profile: Profile,
    system: CircuitProofSystem<PrivateAuthorization>,
}

impl Authorizer {
    /// Builds the profile's constraint system.
    pub fn new(profile: Profile) -> Result<Self, Error> {
        ecdsa_fast::prepare();
        let system = CircuitProofSystem::new(
            PrivateAuthorization {
                profile,
                statement: Statement::default(),
            },
            SecurityLevel::Bits100,
        )?;
        Ok(Self { profile, system })
    }

    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// The underlying BitZ system, for statistics and staged proving.
    pub fn system(&self) -> &CircuitProofSystem<PrivateAuthorization> {
        &self.system
    }

    /// Checks that `witness` satisfies every constraint for `statement`.
    pub fn check(&self, statement: &Statement, witness: &Witness) -> Result<(), Error> {
        self.system
            .witness(&witness_bits(statement, witness))
            .map(|_| ())
    }

    /// Proves that `witness` authorizes `statement`.
    pub fn prove(&mut self, statement: Statement, witness: &Witness) -> Result<Proof, Error> {
        self.bind(statement);
        let witness = self.system.witness(&witness_bits(&statement, witness))?;
        let commitment = self.system.commit(&witness)?;
        self.system.prove(witness, commitment)
    }

    /// Verifies a proof for `statement`.
    pub fn verify(&mut self, statement: Statement, proof: &Proof) -> Result<(), Error> {
        self.bind(statement);
        self.system.verify(proof)
    }

    /// Selects the statement for staged proving through [`Self::system`].
    pub fn bind(&mut self, statement: Statement) {
        self.system.set_statement(PrivateAuthorization {
            profile: self.profile,
            statement,
        });
    }
}
