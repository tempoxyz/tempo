use std::net::SocketAddr;

use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg::{self, Info},
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519::PrivateKey,
    transcript::{Summary, Transcript},
};
use commonware_macros::test_traced;
use commonware_math::algebra::Random as _;
use commonware_runtime::{
    Metrics, Runner as _, Storage,
    buffer::PoolRef,
    deterministic::{Config, Runner},
};
use commonware_storage::journal::{contiguous, segmented};
use commonware_utils::{NZU64, ordered};
use futures::{StreamExt as _, pin_mut};
use tempo_commonware_node_config::EncryptionKey;

use crate::dkg::manager::actor::state::READ_BUFFER;

use super::{Event, PAGE_SIZE, POOL_CAPACITY, State};

const PARTITION_PREFIX: &str = "test";

fn buffer_pool() -> PoolRef {
    PoolRef::new(PAGE_SIZE, POOL_CAPACITY)
}

async fn write_state_unencrypted<TContext>(context: &mut TContext, state: State)
where
    TContext: Metrics + Storage,
{
    let mut journal = contiguous::variable::Journal::<_, State>::init(
        context.with_label("states"),
        contiguous::variable::Config {
            partition: format!("{PARTITION_PREFIX}_states"),
            compression: None,
            codec_config: (),
            buffer_pool: buffer_pool(),
            write_buffer: super::WRITE_BUFFER,
            items_per_section: NZU64!(1),
        },
    )
    .await
    .unwrap();
    journal.append(state).await.unwrap();
}

async fn write_events_unencrypted<TContext>(context: &mut TContext, epoch: u64, events: Vec<Event>)
where
    TContext: Metrics + Storage,
{
    let mut journal = segmented::variable::Journal::<_, Event>::init(
        context.with_label("events"),
        segmented::variable::Config {
            partition: format!("{PARTITION_PREFIX}_events"),
            compression: None,
            codec_config: (),
            buffer_pool: buffer_pool(),
            write_buffer: super::WRITE_BUFFER,
        },
    )
    .await
    .unwrap();
    for event in events {
        journal.append(epoch, event).await.unwrap();
    }
    journal.sync_all().await.unwrap();
}

#[test_traced]
fn can_encrypt_state() {
    Runner::from(Config::default().with_seed(42)).start(|mut context| async move {
        let signers = (0..10)
            .map(|_| PrivateKey::random(&mut context))
            .collect::<Vec<_>>();
        let peers = ordered::Map::from_iter_dedup(
            signers
                .into_iter()
                .map(|key| (key.public_key(), SocketAddr::from(([127, 0, 0, 1], 0)))),
        );
        let (output, shares) =
            dkg::deal::<MinSig, _>(&mut context, Mode::NonZeroCounter, peers.keys().clone())
                .unwrap();
        let unencrypted_state = State {
            epoch: Epoch::new(42),
            seed: Summary::random(&mut context),
            output,
            share: Some(shares.value(0).unwrap().clone()),
            dealers: peers.clone(),
            players: peers.clone(),
            syncers: peers.clone(),
            is_full_dkg: false,
        };
        write_state_unencrypted(&mut context, unencrypted_state.clone()).await;

        let encryption_key = EncryptionKey::random(&mut context);
        let metadata = super::open_or_encrypt_state(
            &mut context,
            buffer_pool(),
            PARTITION_PREFIX,
            &encryption_key,
        )
        .await
        .unwrap();

        let encrypted_state = metadata.get(&super::STATE_KEY).unwrap();
        assert_eq!(
            encrypted_state.decrypt_decode(&encryption_key).unwrap(),
            unencrypted_state,
        )
    });
}

#[test_traced]
fn does_not_reencrypt_state() {
    Runner::from(Config::default().with_seed(42)).start(|mut context| async move {
        let signers = (0..10)
            .map(|_| PrivateKey::random(&mut context))
            .collect::<Vec<_>>();
        let peers = ordered::Map::from_iter_dedup(
            signers
                .into_iter()
                .map(|key| (key.public_key(), SocketAddr::from(([127, 0, 0, 1], 0)))),
        );
        let (output, shares) =
            dkg::deal::<MinSig, _>(&mut context, Mode::NonZeroCounter, peers.keys().clone())
                .unwrap();
        let unencrypted_state = State {
            epoch: Epoch::new(42),
            seed: Summary::random(&mut context),
            output,
            share: Some(shares.value(0).unwrap().clone()),
            dealers: peers.clone(),
            players: peers.clone(),
            syncers: peers.clone(),
            is_full_dkg: false,
        };
        write_state_unencrypted(&mut context, unencrypted_state.clone()).await;

        let encryption_key = EncryptionKey::random(&mut context);
        let encrypted_state = {
            let metadata = super::open_or_encrypt_state(
                &mut context,
                buffer_pool(),
                PARTITION_PREFIX,
                &encryption_key,
            )
            .await
            .unwrap();
            metadata.get(&super::STATE_KEY).cloned().unwrap()
        };

        let read_again = super::open_or_encrypt_state(
            &mut context,
            buffer_pool(),
            PARTITION_PREFIX,
            &encryption_key,
        )
        .await
        .unwrap()
        .get(&super::STATE_KEY)
        .cloned()
        .unwrap();

        assert_eq!(
            read_again, encrypted_state,
            "the nonce is randomly generated during encryption; if this fails, \
            then the data was re-encrypted"
        );
    });
}

#[test_traced]
fn can_encrypt_events() {
    Runner::from(Config::default().with_seed(42)).start(|mut context| async move {
        let alice = PrivateKey::random(&mut context);
        let bob = PrivateKey::random(&mut context);
        let peers = ordered::Set::from_iter_dedup([alice.public_key(), bob.public_key()]);

        let (initial_output, initial_shares) =
            dkg::deal::<MinSig, _>(&mut context, Mode::NonZeroCounter, peers.clone()).unwrap();

        // Create events in a DKG round to populate Alice's events cache.
        let info = Info::new(
            b"test",
            42,
            Some(initial_output),
            Mode::NonZeroCounter,
            peers.clone(),
            peers.clone(),
        )
        .unwrap();

        let (_, alice_pub_msg, alice_priv_msgs) = dkg::Dealer::start(
            Transcript::resume(Summary::random(&mut context)).noise(b"dealer-rng"),
            info.clone(),
            alice.clone(),
            Some(
                initial_shares
                    .get_value(&alice.public_key())
                    .unwrap()
                    .clone(),
            ),
        )
        .unwrap();
        let mut alice_player = dkg::Player::new(info.clone(), alice.clone()).unwrap();

        let (_, bob_pub_msg, bob_priv_msgs) = dkg::Dealer::start(
            Transcript::resume(Summary::random(&mut context)).noise(b"dealer-rng"),
            info.clone(),
            bob.clone(),
            Some(initial_shares.get_value(&bob.public_key()).unwrap().clone()),
        )
        .unwrap();
        let mut bob_player = dkg::Player::new(info.clone(), bob.clone()).unwrap();

        let mut unencrypted_events = Vec::new();
        for (pub_key, priv_msg) in alice_priv_msgs {
            let ack = {
                let player = if pub_key == alice.public_key() {
                    unencrypted_events.push(Event::Dealing {
                        dealer: alice.public_key(),
                        public_msg: alice_pub_msg.clone(),
                        private_msg: priv_msg.clone(),
                    });
                    &mut alice_player
                } else {
                    &mut bob_player
                };
                player
                    .dealer_message(alice.public_key(), alice_pub_msg.clone(), priv_msg)
                    .unwrap()
            };
            unencrypted_events.push(Event::Ack {
                player: pub_key.clone(),
                ack,
            });
        }
        for (pub_key, priv_msg) in bob_priv_msgs {
            if pub_key == alice.public_key() {
                unencrypted_events.push(Event::Dealing {
                    dealer: bob.public_key(),
                    public_msg: bob_pub_msg.clone(),
                    private_msg: priv_msg,
                });
            }
        }

        write_events_unencrypted(&mut context, 42, unencrypted_events.clone()).await;

        let encryption_key = EncryptionKey::random(&mut context);
        let encrypted_journal = super::open_or_encrypt_events(
            &mut context,
            buffer_pool(),
            PARTITION_PREFIX,
            &encryption_key,
        )
        .await
        .unwrap();

        let mut decrypted_events = Vec::new();
        {
            let replay = encrypted_journal.replay(0, 0, READ_BUFFER).await.unwrap();
            pin_mut!(replay);
            while let Some(result) = replay.next().await {
                let (_, _, _, event) = result.unwrap();
                decrypted_events.push(event.decrypt_decode(&encryption_key).unwrap());
            }
        }
        assert_eq!(decrypted_events, unencrypted_events,);
    });
}

#[test_traced]
fn does_not_reencrypt() {
    Runner::from(Config::default().with_seed(42)).start(|mut context| async move {
        let alice = PrivateKey::random(&mut context);
        let bob = PrivateKey::random(&mut context);
        let peers = ordered::Set::from_iter_dedup([alice.public_key(), bob.public_key()]);

        let (initial_output, initial_shares) =
            dkg::deal::<MinSig, _>(&mut context, Mode::NonZeroCounter, peers.clone()).unwrap();

        // Create events in a DKG round to populate Alice's events cache.
        let info = Info::new(
            b"test",
            42,
            Some(initial_output),
            Mode::NonZeroCounter,
            peers.clone(),
            peers.clone(),
        )
        .unwrap();

        let (_, alice_pub_msg, alice_priv_msgs) = dkg::Dealer::start(
            Transcript::resume(Summary::random(&mut context)).noise(b"dealer-rng"),
            info.clone(),
            alice.clone(),
            Some(
                initial_shares
                    .get_value(&alice.public_key())
                    .unwrap()
                    .clone(),
            ),
        )
        .unwrap();
        let mut alice_player = dkg::Player::new(info.clone(), alice.clone()).unwrap();

        let (_, bob_pub_msg, bob_priv_msgs) = dkg::Dealer::start(
            Transcript::resume(Summary::random(&mut context)).noise(b"dealer-rng"),
            info.clone(),
            bob.clone(),
            Some(initial_shares.get_value(&bob.public_key()).unwrap().clone()),
        )
        .unwrap();
        let mut bob_player = dkg::Player::new(info.clone(), bob.clone()).unwrap();

        let mut unencrypted_events = Vec::new();
        for (pub_key, priv_msg) in alice_priv_msgs {
            let ack = {
                let player = if pub_key == alice.public_key() {
                    unencrypted_events.push(Event::Dealing {
                        dealer: alice.public_key(),
                        public_msg: alice_pub_msg.clone(),
                        private_msg: priv_msg.clone(),
                    });
                    &mut alice_player
                } else {
                    &mut bob_player
                };
                player
                    .dealer_message(alice.public_key(), alice_pub_msg.clone(), priv_msg)
                    .unwrap()
            };
            unencrypted_events.push(Event::Ack {
                player: pub_key.clone(),
                ack,
            });
        }
        for (pub_key, priv_msg) in bob_priv_msgs {
            if pub_key == alice.public_key() {
                unencrypted_events.push(Event::Dealing {
                    dealer: bob.public_key(),
                    public_msg: bob_pub_msg.clone(),
                    private_msg: priv_msg,
                });
            }
        }

        write_events_unencrypted(&mut context, 42, unencrypted_events.clone()).await;

        let encryption_key = EncryptionKey::random(&mut context);
        let mut encrypted_events = Vec::new();
        {
            let encrypted_journal = super::open_or_encrypt_events(
                &mut context,
                buffer_pool(),
                PARTITION_PREFIX,
                &encryption_key,
            )
            .await
            .unwrap();
            let replay = encrypted_journal.replay(0, 0, READ_BUFFER).await.unwrap();
            pin_mut!(replay);
            while let Some(result) = replay.next().await {
                let (_, _, _, event) = result.unwrap();
                encrypted_events.push(event);
            }
        }
        let mut second_time = Vec::new();
        {
            let encrypted_journal = super::open_or_encrypt_events(
                &mut context,
                buffer_pool(),
                PARTITION_PREFIX,
                &encryption_key,
            )
            .await
            .unwrap();
            let replay = encrypted_journal.replay(0, 0, READ_BUFFER).await.unwrap();
            pin_mut!(replay);
            while let Some(result) = replay.next().await {
                let (_, _, _, event) = result.unwrap();
                second_time.push(event);
            }
        }
        assert_eq!(
            second_time, encrypted_events,
            "the nonce is randomly generated during encryption; if this fails, \
            then the data was re-encrypted"
        );
    });
}

#[test_traced]
fn continues_encryption() {
    Runner::from(Config::default().with_seed(42)).start(|mut context| async move {
        let alice = PrivateKey::random(&mut context);
        let bob = PrivateKey::random(&mut context);
        let peers = ordered::Set::from_iter_dedup([alice.public_key(), bob.public_key()]);

        let (initial_output, initial_shares) =
            dkg::deal::<MinSig, _>(&mut context, Mode::NonZeroCounter, peers.clone()).unwrap();

        // Create events in a DKG round to populate Alice's events cache.
        let info = Info::new(
            b"test",
            42,
            Some(initial_output),
            Mode::NonZeroCounter,
            peers.clone(),
            peers.clone(),
        )
        .unwrap();

        let (_, alice_pub_msg, alice_priv_msgs) = dkg::Dealer::start(
            Transcript::resume(Summary::random(&mut context)).noise(b"dealer-rng"),
            info.clone(),
            alice.clone(),
            Some(
                initial_shares
                    .get_value(&alice.public_key())
                    .unwrap()
                    .clone(),
            ),
        )
        .unwrap();
        let mut alice_player = dkg::Player::new(info.clone(), alice.clone()).unwrap();

        let (_, bob_pub_msg, bob_priv_msgs) = dkg::Dealer::start(
            Transcript::resume(Summary::random(&mut context)).noise(b"dealer-rng"),
            info.clone(),
            bob.clone(),
            Some(initial_shares.get_value(&bob.public_key()).unwrap().clone()),
        )
        .unwrap();
        let mut bob_player = dkg::Player::new(info.clone(), bob.clone()).unwrap();

        let mut unencrypted_events = Vec::new();
        for (pub_key, priv_msg) in alice_priv_msgs {
            let ack = {
                let player = if pub_key == alice.public_key() {
                    unencrypted_events.push(Event::Dealing {
                        dealer: alice.public_key(),
                        public_msg: alice_pub_msg.clone(),
                        private_msg: priv_msg.clone(),
                    });
                    &mut alice_player
                } else {
                    &mut bob_player
                };
                player
                    .dealer_message(alice.public_key(), alice_pub_msg.clone(), priv_msg)
                    .unwrap()
            };
            unencrypted_events.push(Event::Ack {
                player: pub_key.clone(),
                ack,
            });
        }
        for (pub_key, priv_msg) in bob_priv_msgs {
            if pub_key == alice.public_key() {
                unencrypted_events.push(Event::Dealing {
                    dealer: bob.public_key(),
                    public_msg: bob_pub_msg.clone(),
                    private_msg: priv_msg,
                });
            }
        }

        write_events_unencrypted(&mut context, 42, unencrypted_events.clone()).await;

        let encryption_key = EncryptionKey::random(&mut context);
        {
            let mut encrypted_journal = super::open_or_encrypt_events(
                &mut context,
                buffer_pool(),
                PARTITION_PREFIX,
                &encryption_key,
            )
            .await
            .unwrap();
            let mut pre_to_last_offset = 0;
            let mut last_section = 0;
            {
                let replay = encrypted_journal
                    .replay(0, 0, READ_BUFFER)
                    .await
                    .unwrap()
                    .peekable();
                pin_mut!(replay);
                while let Some(result) = replay.next().await {
                    if replay.as_mut().peek().await.is_none() {
                        break;
                    }
                    let (section, offset, _, _) = result.unwrap();
                    pre_to_last_offset = offset;
                    last_section = section;
                }
            }
            // Delete the last 2 encrypted events and recreate the unencrypted
            // journal to simulate migration having stopped halfway in between
            // and to check it picks up from the correct offset.
            encrypted_journal
                .rewind_to_offset(last_section, pre_to_last_offset)
                .await
                .unwrap();
            encrypted_journal.sync_all().await.unwrap();
            {
                let replay = encrypted_journal.replay(0, 0, READ_BUFFER).await.unwrap();
                pin_mut!(replay);
                while let Some(result) = replay.next().await {
                    let (section, offset, _, _) = result.unwrap();
                    tracing::debug!(section, offset);
                }
            }
        }

        write_events_unencrypted(&mut context, 42, unencrypted_events.clone()).await;

        let encrypted_journal = super::open_or_encrypt_events(
            &mut context,
            buffer_pool(),
            PARTITION_PREFIX,
            &encryption_key,
        )
        .await
        .unwrap();
        let mut decrypted_events = Vec::new();
        {
            let replay = encrypted_journal.replay(0, 0, READ_BUFFER).await.unwrap();
            pin_mut!(replay);
            while let Some(result) = replay.next().await {
                let (_, _, _, event) = result.unwrap();
                decrypted_events.push(event.decrypt_decode(&encryption_key).unwrap());
            }
        }
        assert_eq!(decrypted_events, unencrypted_events,);
    });
}
