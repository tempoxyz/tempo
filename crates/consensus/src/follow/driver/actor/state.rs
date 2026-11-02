//! Driver-local identity state retained across follower restarts.
//!
//! This metadata is never part of a downloadable consensus snapshot.

use commonware_codec::{EncodeSize, Read, ReadExt as _, Write};
use commonware_cryptography::bls12381::primitives::variant::{MinSig, Variant};
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_storage::metadata;
use commonware_utils::futures::rebind;
use eyre::WrapErr as _;
use tempo_chainspec::NetworkIdentity;
use tracing::instrument;

/// Identity transitions observed by the driver.
pub(in crate::follow::driver) struct State<C: Clock + Metrics + Storage + BufferPooler> {
    storage: Option<metadata::Metadata<C, u64, StoredIdentity>>,
    identity: Option<NetworkIdentity>,
}

impl<C: Clock + Metrics + Storage + BufferPooler> State<C> {
    #[instrument(skip_all, err)]
    pub(in crate::follow::driver) async fn init(
        context: C,
        partition_prefix: &str,
    ) -> eyre::Result<Self> {
        let states_metadata_partition = format!("{partition_prefix}_states_metadata");
        let storage = metadata::Metadata::<_, u64, StoredIdentity>::init(
            context,
            metadata::Config {
                partition: states_metadata_partition,
                codec_config: (),
            },
        )
        .await
        .wrap_err("failed opening storage")?;

        let identity = storage.get(&0).map(|stored| stored.0.clone());
        Ok(Self {
            storage: Some(storage),
            identity,
        })
    }

    pub(in crate::follow::driver) fn identity(&self) -> Option<&NetworkIdentity> {
        self.identity.as_ref()
    }

    /// Persist a registered key change, retaining the original epoch when the key is unchanged.
    /// The caller must validate identity conflicts and epoch ordering before calling.
    #[instrument(skip_all, err)]
    pub(in crate::follow::driver) async fn observe(
        &mut self,
        identity: NetworkIdentity,
    ) -> eyre::Result<()> {
        if self
            .identity
            .as_ref()
            .is_some_and(|persisted| persisted.identity == identity.identity)
        {
            return Ok(());
        }

        let stored = StoredIdentity(identity.clone());
        rebind(&mut self.storage, |storage| storage.put_sync(0, stored))
            .await
            .wrap_err("failed persisting local authentication record")?;

        self.identity = Some(identity);
        Ok(())
    }
}

#[derive(Clone)]
struct StoredIdentity(NetworkIdentity);

impl EncodeSize for StoredIdentity {
    fn encode_size(&self) -> usize {
        1 + self.0.from_epoch.encode_size() + self.0.identity.encode_size()
    }
}

impl Write for StoredIdentity {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        1u8.write(buf);
        self.0.from_epoch.write(buf);
        self.0.identity.write(buf);
    }
}

impl Read for StoredIdentity {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let version = u8::read(buf)?;
        if version != 1 {
            return Err(commonware_codec::Error::InvalidEnum(version));
        }
        Ok(Self(NetworkIdentity {
            from_epoch: u64::read(buf)?,
            identity: <MinSig as Variant>::Public::read(buf)?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::dkg_fixture;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_consensus::types::Epoch;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    #[test]
    fn opening_state_does_not_create_an_identity() {
        deterministic::Runner::default().start(|context| async move {
            let state = State::init(context.child("first"), "engine").await.unwrap();
            assert_eq!(state.identity(), None);
            drop(state);
            let state = State::init(context.child("restart"), "engine")
                .await
                .unwrap();
            assert_eq!(state.identity(), None);
        });
    }

    #[test]
    fn key_changes_survive_restart_and_resharing_keeps_the_original_epoch() {
        deterministic::Runner::default().start(|mut context| async move {
            let old = dkg_fixture(&mut context, Epoch::new(2));
            let new = dkg_fixture(&mut context, Epoch::new(5));
            let old = NetworkIdentity {
                from_epoch: 2,
                identity: *old.outcome.network_identity(),
            };
            let new = NetworkIdentity {
                from_epoch: 5,
                identity: *new.outcome.network_identity(),
            };
            let mut state = State::init(context.child("first"), "engine").await.unwrap();
            state.observe(old.clone()).await.unwrap();
            state.observe(new.clone()).await.unwrap();
            state
                .observe(NetworkIdentity {
                    from_epoch: 6,
                    identity: new.identity,
                })
                .await
                .unwrap();
            assert_eq!(state.identity(), Some(&new));
            drop(state);
            let state = State::init(context.child("restart"), "engine")
                .await
                .unwrap();
            assert_eq!(state.identity(), Some(&new));
        });
    }

    #[test]
    fn record_codec_rejects_truncation_trailing_bytes_and_unknown_versions() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = dkg_fixture(&mut context, Epoch::zero());
            for epoch in [0, 1, u64::MAX] {
                let value = StoredIdentity(NetworkIdentity {
                    from_epoch: epoch,
                    identity: *fixture.outcome.network_identity(),
                });
                let encoded = value.encode();
                assert_eq!(StoredIdentity::decode(encoded.clone()).unwrap().0, value.0);
                for length in 0..encoded.len() {
                    assert!(StoredIdentity::decode(&encoded[..length]).is_err());
                }
                let mut trailing = encoded.to_vec();
                trailing.push(0);
                assert!(StoredIdentity::decode(trailing.as_slice()).is_err());
                let mut wrong_version = encoded.to_vec();
                wrong_version[0] = 2;
                assert!(matches!(
                    StoredIdentity::decode(wrong_version.as_slice()),
                    Err(commonware_codec::Error::InvalidEnum(2))
                ));
            }
        });
    }
}
