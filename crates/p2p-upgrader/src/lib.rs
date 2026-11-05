//! A stream upgrader that accepts several SAKE/CUPS versions on inbound connections.
//!
//! Commonware does not negotiate stream versions: a SAKE V1 dialer cannot connect to a V0
//! listener, nor the reverse. Both versions share one handshake wire format and differ only in
//! the signed transcript, so a dialer's Syn signature verifies under exactly one of them.
//! [MultiVersion] uses that to accept every version in [Accept] on inbound connections, and
//! frames records with the CUPS version paired with the one it detected. Outbound connections
//! use a single version and are never retried with another, so a man in the middle cannot force
//! a downgrade.
//!
//! This moves a network from V0 to V1 in rolling restarts:
//!
//! 1. every node accepts V0 and V1 and dials V0;
//! 2. once every node runs step 1, nodes dial V1;
//! 3. nodes accept V1 only.

use std::{
    future::Future,
    marker::PhantomData,
    sync::{Arc, Mutex},
    time::Duration,
};

use commonware_codec::{DecodeExt as _, Encode as _, FixedSize};
use commonware_cryptography::{
    Cipher, Signer,
    handshake::sake::{Ack, Context, Error as SakeError, Syn, SynAck, listen_end, listen_start},
    transcript::Transcript,
};
use commonware_runtime::{Clock, Sink, Stream};
use commonware_stream::{
    Handshake, Upgrader,
    cups::{self, Cups},
    sake::{self, Sake},
    utils::codec::{Error as FrameError, recv_frame, send_frame},
};
use commonware_utils::{DurationExt as _, SystemTimeExt as _};
use rand_core::CryptoRng;

/// Dials with one version and accepts any of several on inbound connections.
pub struct MultiVersion<S, C> {
    signer: S,
    synchrony_bound: Duration,
    max_handshake_age: Duration,
    dial: Version,
    accept: Accept,
    _cipher: PhantomData<fn() -> C>,
}

impl<S, C> MultiVersion<S, C> {
    /// Creates an upgrader for the signer that dials with one version and accepts several.
    ///
    /// Peer timestamps must lie in [now - max_handshake_age, now + synchrony_bound), as with
    /// commonware's SAKE.
    pub const fn new(
        signer: S,
        synchrony_bound: Duration,
        max_handshake_age: Duration,
        dial: Version,
        accept: Accept,
    ) -> Self {
        Self {
            signer,
            synchrony_bound,
            max_handshake_age,
            dial,
            accept,
            _cipher: PhantomData,
        }
    }
}

impl<S: Signer, C: Cipher> MultiVersion<S, C> {
    /// Runs the listener side of SAKE, accepting any version in [Accept].
    ///
    /// Mirrors commonware's SAKE listener, except that the dialer's Syn is checked against
    /// each accepted version until one verifies.
    async fn listen_sake<E, I, O, B, F>(
        &self,
        context: &mut E,
        namespace: &[u8],
        bouncer: B,
        stream: &mut I,
        sink: &mut O,
    ) -> Result<(S::PublicKey, Transcript, Version), Error>
    where
        E: Clock + CryptoRng,
        I: Stream,
        O: Sink,
        B: FnOnce(S::PublicKey) -> F + Send,
        F: Future<Output = bool> + Send,
    {
        // Consult the bouncer on the unauthenticated claim before any handshake work.
        let peer = S::PublicKey::decode(recv_frame(stream, frame_size::<S::PublicKey>()).await?)?;
        if !bouncer(peer.clone()).await {
            return Err(Error::PeerRejected);
        }

        // Every version shares the Syn encoding, so keep the frame and decode it per attempt.
        let syn_frame = recv_frame(stream, frame_size::<Syn<S::Signature>>())
            .await?
            .coalesce();

        // Read the clock once the Syn arrives, as SAKE does.
        let current_time = context.current().epoch().as_millis_u64();
        let ok_timestamps = current_time.saturating_sub(self.max_handshake_age.as_millis_u64())
            ..current_time.saturating_add(self.synchrony_bound.as_millis_u64());

        let mut accepted = None;
        for &version in &self.accept.0 {
            let syn = Syn::<S::Signature>::decode(syn_frame.clone())?;
            let ctx = Context::new(
                namespace,
                current_time,
                ok_timestamps.clone(),
                self.signer.clone(),
                peer.clone(),
                version.sake(),
            );
            match listen_start(&mut *context, ctx, syn) {
                Ok(started) => {
                    accepted = Some((version, started));
                    break;
                }
                // A signature over another version's transcript fails here: try the next one.
                Err(SakeError::InvalidSignature) => continue,
                Err(other) => return Err(other.into()),
            }
        }
        let Some((version, (state, syn_ack))) = accepted else {
            return Err(Error::NoAcceptedVersion);
        };

        send_frame(sink, syn_ack.encode(), frame_size::<SynAck<S::Signature>>()).await?;
        let ack = Ack::decode(recv_frame(stream, frame_size::<Ack>()).await?)?;
        let transcript = listen_end(state, ack)?;
        Ok((peer, transcript, version))
    }
}

impl<S: Clone, C> Clone for MultiVersion<S, C> {
    fn clone(&self) -> Self {
        Self {
            signer: self.signer.clone(),
            synchrony_bound: self.synchrony_bound,
            max_handshake_age: self.max_handshake_age,
            dial: self.dial,
            accept: self.accept.clone(),
            _cipher: PhantomData,
        }
    }
}

impl<S: Signer, C: Cipher> Upgrader for MultiVersion<S, C> {
    const MAX_SIZE: u32 = Cups::<Sake<S>, C>::MAX_SIZE;

    type PublicKey = S::PublicKey;
    type Error = Error;
    type Sender<I: Stream, O: Sink> = cups::Sender<C, O>;
    type Receiver<I: Stream, O: Sink> = cups::Receiver<C, I>;

    fn public_key(&self) -> S::PublicKey {
        self.signer.public_key()
    }

    async fn dial<E, I, O>(
        self,
        context: E,
        namespace: &[u8],
        max_message_size: u32,
        peer: S::PublicKey,
        stream: I,
        sink: O,
    ) -> Result<(Self::Sender<I, O>, Self::Receiver<I, O>), Error>
    where
        E: Clock + CryptoRng,
        I: Stream,
        O: Sink,
    {
        let sake = Sake {
            signer: self.signer,
            synchrony_bound: self.synchrony_bound,
            max_handshake_age: self.max_handshake_age,
            version: self.dial.sake(),
        };
        Ok(Cups::<_, C>::new(sake, self.dial.cups())
            .dial(context, namespace, max_message_size, peer, stream, sink)
            .await?)
    }

    async fn listen<E, I, O, B, F>(
        self,
        mut context: E,
        namespace: &[u8],
        max_message_size: u32,
        bouncer: B,
        mut stream: I,
        mut sink: O,
    ) -> Result<(S::PublicKey, Self::Sender<I, O>, Self::Receiver<I, O>), Error>
    where
        E: Clock + CryptoRng,
        I: Stream,
        O: Sink,
        B: FnOnce(S::PublicKey) -> F + Send,
        F: Future<Output = bool> + Send,
    {
        assert!(
            max_message_size <= Self::MAX_SIZE,
            "maximum message size exceeds stream limit"
        );
        let (peer, transcript, version) = self
            .listen_sake(&mut context, namespace, bouncer, &mut stream, &mut sink)
            .await?;
        tracing::debug!(?peer, ?version, "accepted inbound connection");

        // Stock CUPS derives the ciphers and frames records for the detected version.
        let replay = Replay {
            public_key: self.signer.public_key(),
            done: Arc::new(Mutex::new(Some((peer, transcript)))),
        };
        Cups::<_, C>::new(replay, version.cups())
            .listen(
                context,
                namespace,
                max_message_size,
                |_| async { true },
                stream,
                sink,
            )
            .await
    }
}

/// A SAKE handshake version paired with the CUPS record version it runs under.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Version {
    /// SAKE V0 with CUPS V0: the wire protocol of commonware v2026.9.0.
    V0,
    /// SAKE V1 with CUPS V1.
    V1,
}

impl Version {
    /// Returns the SAKE handshake version.
    pub const fn sake(self) -> sake::Version {
        match self {
            Self::V0 => sake::Version::V0,
            Self::V1 => sake::Version::V1,
        }
    }

    /// Returns the CUPS record version.
    pub const fn cups(self) -> cups::Version {
        match self {
            Self::V0 => cups::Version::V0,
            Self::V1 => cups::Version::V1,
        }
    }
}

/// Versions accepted on inbound connections, tried in order. Never empty.
#[derive(Clone, Debug)]
pub struct Accept(Vec<Version>);

impl Accept {
    /// Accepts the given versions, tried in order, or returns None when there are none.
    pub fn new(versions: Vec<Version>) -> Option<Self> {
        (!versions.is_empty()).then_some(Self(versions))
    }
}

/// Errors from a [MultiVersion] connection attempt.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An outbound handshake failed.
    #[error(transparent)]
    Sake(#[from] sake::Error),
    /// The inbound handshake failed after a version was detected.
    #[error("handshake error: {0}")]
    Handshake(#[from] SakeError),
    /// Reading or writing a handshake frame failed.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// A handshake frame did not decode.
    #[error("unable to decode: {0}")]
    Decode(#[from] commonware_codec::Error),
    /// The bouncer rejected the peer's claimed identity.
    #[error("peer rejected by bouncer")]
    PeerRejected,
    /// The peer's Syn signature verifies under none of the accepted versions.
    #[error("no accepted version verifies the peer's handshake")]
    NoAcceptedVersion,
}

/// A Handshake that hands a listen [MultiVersion] already completed to [Cups].
struct Replay<P> {
    public_key: P,
    done: Arc<Mutex<Option<(P, Transcript)>>>,
}

impl<P: Clone> Clone for Replay<P> {
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key.clone(),
            done: self.done.clone(),
        }
    }
}

impl<P: Clone + Send + Sync + 'static> Handshake for Replay<P> {
    type PublicKey = P;
    type Error = Error;

    fn public_key(&self) -> P {
        self.public_key.clone()
    }

    async fn dial<E, I, O>(
        self,
        _: E,
        _: &[u8],
        _: P,
        _: &mut I,
        _: &mut O,
    ) -> Result<Transcript, Error>
    where
        E: Clock + CryptoRng,
        I: Stream,
        O: Sink,
    {
        unreachable!("MultiVersion only listens through a replay")
    }

    async fn listen<E, I, O, B, F>(
        self,
        _: E,
        _: &[u8],
        _: B,
        _: &mut I,
        _: &mut O,
    ) -> Result<(P, Transcript), Error>
    where
        E: Clock + CryptoRng,
        I: Stream,
        O: Sink,
        B: FnOnce(P) -> F + Send,
        F: Future<Output = bool> + Send,
    {
        Ok(self
            .done
            .lock()
            .expect("replay lock is never poisoned")
            .take()
            .expect("MultiVersion listens through each replay once"))
    }
}

fn frame_size<M: FixedSize>() -> u32 {
    u32::try_from(M::SIZE).expect("handshake frames fit in u32")
}

#[cfg(test)]
mod tests;
