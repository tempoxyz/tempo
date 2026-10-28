//! Types for erasure coding.

use crate::{
    Block, CertifiableBlock, Heightable,
    types::{Height, coding::Commitment},
};
use commonware_codec::{BufsMut, EncodeSize, Read, ReadExt, Write};
use commonware_coding::{Config as CodingConfig, Scheme};
use commonware_cryptography::{Committable, Digestible, Hasher};
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::{Faults, N3f1, NZU16};
use std::{
    marker::PhantomData,
    sync::{Arc, OnceLock},
};

/// A broadcastable shard of erasure coded data, including the coding commitment and
/// the configuration used to code the data.
pub struct Shard<B: Digestible, C: Scheme, H: Hasher> {
    /// The coding commitment
    pub(crate) commitment: Commitment<B, C, H>,
    /// The index of this shard within the commitment.
    pub(crate) index: u16,
    /// An individual shard within the commitment.
    pub(crate) inner: C::Shard,
}

impl<B: Digestible, C: Scheme, H: Hasher> Shard<B, C, H> {
    pub const fn new(commitment: Commitment<B, C, H>, index: u16, inner: C::Shard) -> Self {
        Self {
            commitment,
            index,
            inner,
        }
    }

    /// Returns the index of this shard within the commitment.
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Returns the [`Commitment`] for this shard.
    pub const fn commitment(&self) -> Commitment<B, C, H> {
        self.commitment
    }

    /// Takes the inner shard.
    pub fn into_inner(self) -> C::Shard {
        self.inner
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Clone for Shard<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            index: self.index,
            inner: self.inner.clone(),
        }
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Committable for Shard<B, C, H> {
    type Commitment = Commitment<B, C, H>;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Write for Shard<B, C, H> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
        self.index.write(buf);
        self.inner.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.commitment.write(buf);
        self.index.write(buf);
        self.inner.write_bufs(buf);
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> EncodeSize for Shard<B, C, H> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.index.encode_size() + self.inner.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.commitment.encode_size() + self.index.encode_size() + self.inner.encode_inline_size()
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Read for Shard<B, C, H> {
    type Cfg = commonware_coding::CodecConfig;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let commitment = Commitment::<B, C, H>::read(buf)?;
        let index = u16::read(buf)?;
        let inner = C::Shard::read_cfg(buf, cfg)?;

        Ok(Self {
            commitment,
            index,
            inner,
        })
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> PartialEq for Shard<B, C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment
            && self.index == other.index
            && self.inner == other.inner
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Eq for Shard<B, C, H> {}

#[cfg(feature = "arbitrary")]
impl<B: Digestible, C: Scheme, H: Hasher> arbitrary::Arbitrary<'_> for Shard<B, C, H>
where
    Commitment<B, C, H>: for<'a> arbitrary::Arbitrary<'a>,
    C::Shard: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            commitment: u.arbitrary()?,
            index: u.arbitrary()?,
            inner: u.arbitrary()?,
        })
    }
}

/// An envelope type for an erasure coded [`Block`].
#[derive(Debug)]
pub struct CodedBlock<B: Block, C: Scheme, H: Hasher> {
    /// The inner block type.
    inner: Arc<B>,
    /// The erasure coding configuration.
    config: CodingConfig,
    /// The erasure coding commitment.
    commitment: C::Commitment,
    /// The coded shards.
    ///
    /// These shards are lazily-constructed when [`CodedBlock`] is formed with [`Self::new_trusted`].
    shards: OnceLock<Arc<[C::Shard]>>,
    /// Phantom data for the hasher.
    _hasher: PhantomData<H>,
}

impl<B: Block, C: Scheme, H: Hasher> CodedBlock<B, C, H> {
    /// Erasure codes the block.
    fn encode(
        inner: &B,
        config: CodingConfig,
        strategy: &impl Strategy,
    ) -> (C::Commitment, Vec<C::Shard>) {
        let mut buf = Vec::with_capacity(inner.encode_size() + config.encode_size());
        inner.write(&mut buf);
        config.write(&mut buf);

        C::encode(&config, buf.as_slice(), strategy).expect("must encode block successfully")
    }

    /// Create a new [`CodedBlock`] from a [`Block`] and a configuration.
    pub fn new(inner: B, config: CodingConfig, strategy: &impl Strategy) -> Self {
        let (commitment, shards) = Self::encode(&inner, config, strategy);
        Self {
            inner: Arc::new(inner),
            config,
            commitment,
            shards: OnceLock::from(Arc::<[C::Shard]>::from(shards)),
            _hasher: PhantomData,
        }
    }

    /// Create a new [`CodedBlock`] from a [`Block`] and trusted [`Commitment`].
    pub fn new_trusted(inner: B, commitment: Commitment<B, C, H>) -> Self {
        Self::new_trusted_shared(Arc::new(inner), commitment)
    }

    fn new_trusted_shared(inner: Arc<B>, commitment: Commitment<B, C, H>) -> Self {
        Self {
            inner,
            config: commitment.config(),
            commitment: commitment.root(),
            shards: OnceLock::new(),
            _hasher: PhantomData,
        }
    }

    /// Returns the coding configuration for the data committed.
    pub const fn config(&self) -> CodingConfig {
        self.config
    }

    /// Returns a reference to the shards in this coded block.
    ///
    /// If the shards have not yet been generated, they will be created via [`Scheme::encode`].
    pub fn shards(&self, strategy: &impl Strategy) -> &[C::Shard] {
        self.shards.get_or_init(|| {
            let (commitment, shards) = Self::encode(&self.inner, self.config, strategy);

            assert_eq!(
                commitment, self.commitment,
                "coded block constructed with trusted commitment does not match commitment"
            );

            shards.into()
        })
    }

    /// Returns a [`Shard`] at the given index, if the index is valid.
    pub fn shard(&self, index: u16) -> Option<Shard<B, C, H>>
    where
        B: CertifiableBlock,
    {
        Some(Shard::new(
            self.commitment(),
            index,
            self.shards.get()?.get(usize::from(index))?.clone(),
        ))
    }

    /// Returns a reference to the inner [`Block`].
    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Returns a shared reference to the inner [`Block`].
    pub fn inner_shared(&self) -> Arc<B> {
        Arc::clone(&self.inner)
    }

    /// Takes the shared inner [`Block`].
    pub fn into_inner_shared(self) -> Arc<B> {
        self.inner
    }

    /// Takes the inner [`Block`].
    pub fn into_inner(self) -> B {
        Arc::unwrap_or_clone(self.inner)
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> From<CodedBlock<B, C, H>>
    for StoredCodedBlock<B, C, H>
{
    fn from(block: CodedBlock<B, C, H>) -> Self {
        Self::new(block)
    }
}

impl<B: Block, C: Scheme, H: Hasher> Clone for CodedBlock<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            config: self.config,
            commitment: self.commitment,
            shards: self.shards.clone(),
            _hasher: PhantomData,
        }
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> Committable for CodedBlock<B, C, H> {
    type Commitment = Commitment<B, C, H>;

    fn commitment(&self) -> Self::Commitment {
        Commitment::<B, C, H>::from((
            self.digest(),
            self.commitment,
            hash_context::<H, _>(&self.inner.context()),
            self.config,
        ))
    }
}

impl<B: Block, C: Scheme, H: Hasher> Digestible for CodedBlock<B, C, H> {
    type Digest = B::Digest;

    fn digest(&self) -> Self::Digest {
        self.inner.digest()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Write for CodedBlock<B, C, H> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
        self.config.write(buf);
    }
}

impl<B: Block, C: Scheme, H: Hasher> EncodeSize for CodedBlock<B, C, H> {
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.config.encode_size()
    }
}

/// Codec configuration for decoding a [`CodedBlock`] from the wire.
///
/// Pairs the inner block's codec config with the [`Commitment`] that the
/// decoded block must match. The [`Read`] impl re-encodes the block and
/// rejects it unless its block digest, coding configuration, and coding root match
/// `expected`.
pub struct CodedBlockCfg<B: Block, C: Scheme, H: Hasher> {
    /// Codec configuration for the inner application block.
    pub inner: <B as Read>::Cfg,
    /// The commitment the decoded block must match.
    pub expected: Commitment<B, C, H>,
}

impl<B: Block, C: Scheme, H: Hasher> Clone for CodedBlockCfg<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            expected: self.expected,
        }
    }
}

impl<B: Block, C: Scheme, H: Hasher> Read for CodedBlock<B, C, H> {
    type Cfg = CodedBlockCfg<B, C, H>;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let inner = B::read_cfg(buf, &cfg.inner)?;
        let config = CodingConfig::read(buf)?;

        if config != cfg.expected.config() {
            return Err(commonware_codec::Error::Invalid(
                "CodedBlock",
                "config mismatch",
            ));
        }
        if inner.digest() != cfg.expected.block() {
            return Err(commonware_codec::Error::Invalid(
                "CodedBlock",
                "block digest mismatch",
            ));
        }

        // Recompute the coding root and require it to match the expected
        // commitment.
        //
        // The context digest is not checkable here because [`Block`] does not
        // expose a context, so callers that need the full commitment to match
        // must compare it after decoding.
        let mut buf = Vec::with_capacity(inner.encode_size() + config.encode_size());
        inner.write(&mut buf);
        config.write(&mut buf);
        let (commitment, shards) =
            C::encode(&config, buf.as_slice(), &Sequential).map_err(|_| {
                commonware_codec::Error::Invalid("CodedBlock", "Failed to re-commit to block")
            })?;
        if commitment != cfg.expected.root() {
            return Err(commonware_codec::Error::Invalid(
                "CodedBlock",
                "coding root mismatch",
            ));
        }

        Ok(Self {
            inner: Arc::new(inner),
            config,
            commitment,
            shards: OnceLock::from(Arc::<[C::Shard]>::from(shards)),
            _hasher: PhantomData,
        })
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> Block for CodedBlock<B, C, H> {
    fn parent(&self) -> Self::Digest {
        self.inner.parent()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Heightable for CodedBlock<B, C, H> {
    fn height(&self) -> Height {
        self.inner.height()
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> CertifiableBlock for CodedBlock<B, C, H> {
    type Context = B::Context;

    fn context(&self) -> Self::Context {
        self.inner.context()
    }
}

/// Hashes a consensus context for inclusion in a [`Commitment`].
pub fn hash_context<H: Hasher, C: EncodeSize + Write>(context: &C) -> H::Digest {
    let mut buf = Vec::with_capacity(context.encode_size());
    context.write(&mut buf);
    H::hash(&[&buf])
}

impl<B: Block + PartialEq, C: Scheme, H: Hasher> PartialEq for CodedBlock<B, C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
            && self.config == other.config
            && self.commitment == other.commitment
            && self.shards == other.shards
    }
}

impl<B: Block + Eq, C: Scheme, H: Hasher> Eq for CodedBlock<B, C, H> {}

/// A [`CodedBlock`] paired with its [`Commitment`] for efficient storage and retrieval.
///
/// This type should be preferred for storing verified [`CodedBlock`]s on disk - it
/// should never be sent over the network. Use [`CodedBlock`] for network transmission,
/// as it re-encodes the block with [`Scheme::encode`] on deserialization to ensure integrity.
///
/// When reading from storage, we don't need to re-encode the block to compute
/// the commitment - we stored it alongside the block when we first verified it.
/// This avoids expensive erasure coding operations on the read path.
///
/// The [`Read`] implementation performs a light verification (block digest check)
/// to detect storage corruption, but does not re-encode the block.
pub struct StoredCodedBlock<B: Block, C: Scheme, H: Hasher> {
    inner: Arc<B>,
    commitment: Commitment<B, C, H>,
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> StoredCodedBlock<B, C, H> {
    /// Create a [`StoredCodedBlock`] from a verified [`CodedBlock`].
    ///
    /// The caller must ensure the [`CodedBlock`] has been properly verified
    /// (i.e., its commitment was computed or validated against a trusted source).
    pub fn new(block: CodedBlock<B, C, H>) -> Self {
        Self {
            commitment: block.commitment(),
            inner: block.inner,
        }
    }

    /// Convert back to a [`CodedBlock`] using the trusted commitment.
    ///
    /// The returned [`CodedBlock`] generates shards lazily if they are needed.
    pub fn into_coded_block(self) -> CodedBlock<B, C, H> {
        CodedBlock::new_trusted_shared(self.inner, self.commitment)
    }

    /// Returns a reference to the inner block.
    pub fn inner(&self) -> &B {
        &self.inner
    }
}

/// Converts a [`StoredCodedBlock`] back to a [`CodedBlock`].
impl<B: Block, C: Scheme, H: Hasher> From<StoredCodedBlock<B, C, H>> for CodedBlock<B, C, H> {
    fn from(stored: StoredCodedBlock<B, C, H>) -> Self {
        Self::new_trusted_shared(stored.inner, stored.commitment)
    }
}

impl<B: Block, C: Scheme, H: Hasher> Clone for StoredCodedBlock<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<B: Block, C: Scheme, H: Hasher> Committable for StoredCodedBlock<B, C, H> {
    type Commitment = Commitment<B, C, H>;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<B: Block, C: Scheme, H: Hasher> Digestible for StoredCodedBlock<B, C, H> {
    type Digest = B::Digest;

    fn digest(&self) -> Self::Digest {
        self.inner.digest()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Write for StoredCodedBlock<B, C, H> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
        self.commitment.write(buf);
    }
}

impl<B: Block, C: Scheme, H: Hasher> EncodeSize for StoredCodedBlock<B, C, H> {
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.commitment.encode_size()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Read for StoredCodedBlock<B, C, H> {
    // Note: No concurrency parameter needed since we don't re-encode!
    type Cfg = B::Cfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        block_cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let inner = B::read_cfg(buf, block_cfg)?;
        let commitment = Commitment::<B, C, H>::read(buf)?;

        // Light verification to detect storage corruption
        if inner.digest() != commitment.block() {
            return Err(commonware_codec::Error::Invalid(
                "StoredCodedBlock",
                "storage corruption: block digest mismatch",
            ));
        }

        Ok(Self {
            commitment,
            inner: Arc::new(inner),
        })
    }
}

impl<B: Block, C: Scheme, H: Hasher> Block for StoredCodedBlock<B, C, H> {
    fn parent(&self) -> Self::Digest {
        self.inner.parent()
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> CertifiableBlock for StoredCodedBlock<B, C, H> {
    type Context = B::Context;

    fn context(&self) -> Self::Context {
        self.inner.context()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Heightable for StoredCodedBlock<B, C, H> {
    fn height(&self) -> Height {
        self.inner.height()
    }
}

impl<B: Block + PartialEq, C: Scheme, H: Hasher> PartialEq for StoredCodedBlock<B, C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment && self.inner == other.inner
    }
}

impl<B: Block + Eq, C: Scheme, H: Hasher> Eq for StoredCodedBlock<B, C, H> {}

/// Compute the [`CodingConfig`] for a given number of participants.
///
/// Panics if `n_participants < 4`.
pub fn coding_config_for_participants(n_participants: u16) -> CodingConfig {
    let max_faults = N3f1::max_faults(n_participants);
    assert!(
        max_faults >= 1,
        "Need at least 4 participants to maintain fault tolerance"
    );
    let max_faults = u16::try_from(max_faults).expect("max_faults must fit in u16");
    let minimum_shards = NZU16!(max_faults + 1);
    CodingConfig {
        minimum_shards,
        extra_shards: NZU16!(n_participants - minimum_shards.get()),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::marshal::mocks::block::EmptyBlock;
    use bytes::Buf;
    use commonware_codec::{Decode, Encode, Error};
    use commonware_coding::{CodecConfig, ReedSolomon};
    use commonware_cryptography::{Digest, Sha256, sha256::Digest as Sha256Digest};
    use commonware_runtime::{BufferPooler, Runner, deterministic, iobuf::EncodeExt};

    const MAX_SHARD_SIZE: CodecConfig = CodecConfig {
        maximum_shard_size: 1024 * 1024, // 1 MiB
    };

    type H = Sha256;
    type RS = ReedSolomon<H>;
    type TestBlock = EmptyBlock<H>;
    type RShard = Shard<TestBlock, RS, H>;

    #[test]
    fn test_shard_wrapper_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"commonware shape rotator club";
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let (commitment, shards) = RS::encode(&CONFIG, MOCK_BLOCK_DATA, &Sequential).unwrap();
        let raw_shard = shards.first().cloned().unwrap();

        let commitment =
            Commitment::from((Sha256Digest::EMPTY, commitment, Sha256Digest::EMPTY, CONFIG));
        let shard = RShard::new(commitment, 0, raw_shard);
        let encoded = shard.encode();
        let decoded = RShard::decode_cfg(&mut encoded.as_ref(), &MAX_SHARD_SIZE).unwrap();
        assert!(shard == decoded);
    }

    #[test]
    fn test_shard_decode_truncated_returns_error() {
        let decode = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut buf = &[][..];
            RShard::decode_cfg(&mut buf, &MAX_SHARD_SIZE)
        }));
        assert!(decode.is_ok(), "decode must not panic on truncated input");
        assert!(decode.unwrap().is_err());
    }

    #[test]
    fn test_coding_config_for_participants_valid_for_minimum_set() {
        let config = coding_config_for_participants(4);
        assert_eq!(config.minimum_shards.get(), 2);
        assert_eq!(config.extra_shards.get(), 2);
    }

    #[test]
    #[should_panic(expected = "Need at least 4 participants to maintain fault tolerance")]
    fn test_coding_config_for_participants_panics_for_small_sets() {
        let _ = coding_config_for_participants(3);
    }

    #[test]
    fn test_shard_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"deadc0de";
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let (commitment, shards) = RS::encode(&CONFIG, MOCK_BLOCK_DATA, &Sequential).unwrap();
        let raw_shard = shards.first().cloned().unwrap();

        let commitment =
            Commitment::from((Sha256Digest::EMPTY, commitment, Sha256Digest::EMPTY, CONFIG));
        let shard = RShard::new(commitment, 0, raw_shard);
        let encoded = shard.encode();
        let decoded = RShard::decode_cfg(&mut encoded.as_ref(), &MAX_SHARD_SIZE).unwrap();
        assert!(shard == decoded);
    }

    #[test]
    fn test_coded_block_codec_roundtrip() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = CodedBlock::<TestBlock, RS, H>::new(block, CONFIG, &Sequential);

        let encoded = coded_block.encode();
        let decoded = CodedBlock::<TestBlock, RS, H>::decode_cfg(
            encoded,
            &CodedBlockCfg {
                inner: (),
                expected: coded_block.commitment(),
            },
        )
        .unwrap();

        assert!(coded_block == decoded);
    }

    #[test]
    fn test_coded_block_decode_rejects_config_mismatch() {
        const EXPECTED_CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(3),
        };
        const EMBEDDED_CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let expected =
            CodedBlock::<TestBlock, RS, H>::new(block.clone(), EXPECTED_CONFIG, &Sequential)
                .commitment();
        let encoded = (block, EMBEDDED_CONFIG).encode();

        let Err(err) = CodedBlock::<TestBlock, RS, H>::decode_cfg(
            encoded.as_ref(),
            &CodedBlockCfg {
                inner: (),
                expected,
            },
        ) else {
            panic!("config mismatch should be rejected");
        };

        assert!(
            matches!(err, Error::Invalid("CodedBlock", "config mismatch")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_coded_block_decode_rejects_coding_root_mismatch() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        // Build an expected commitment that differs only in its coding root.
        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded = CodedBlock::<TestBlock, RS, H>::new(block, CONFIG, &Sequential);
        let commitment = coded.commitment();
        let wrong_root = Sha256::hash(&[b"wrong root"]);
        assert_ne!(wrong_root, commitment.root());
        let expected = Commitment::<TestBlock, RS, H>::from((
            commitment.block(),
            wrong_root,
            commitment.context(),
            commitment.config(),
        ));

        // Decoding must reject bytes that do not satisfy the exact expected
        // commitment.
        let Err(err) = CodedBlock::<TestBlock, RS, H>::decode_cfg(
            coded.encode(),
            &CodedBlockCfg {
                inner: (),
                expected,
            },
        ) else {
            panic!("coding root mismatch should be rejected");
        };

        assert!(
            matches!(err, Error::Invalid("CodedBlock", "coding root mismatch")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_coded_block_clone_shares_shards() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = CodedBlock::<TestBlock, RS, H>::new(block, CONFIG, &Sequential);
        let cloned = coded_block.clone();

        assert!(Arc::ptr_eq(&coded_block.inner, &cloned.inner));
        assert!(Arc::ptr_eq(
            coded_block.shards.get().unwrap(),
            cloned.shards.get().unwrap()
        ));
    }

    #[test]
    fn test_stored_coded_block_codec_roundtrip() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = CodedBlock::<TestBlock, RS, H>::new(block, CONFIG, &Sequential);
        let stored = StoredCodedBlock::<TestBlock, RS, H>::new(coded_block.clone());

        assert_eq!(stored.commitment(), coded_block.commitment());
        assert_eq!(stored.digest(), coded_block.digest());
        assert_eq!(stored.height(), coded_block.height());
        assert_eq!(stored.parent(), coded_block.parent());

        let encoded = stored.encode();
        let decoded = StoredCodedBlock::<TestBlock, RS, H>::decode_cfg(encoded, &()).unwrap();

        assert!(stored == decoded);
        assert_eq!(decoded.commitment(), coded_block.commitment());
        assert_eq!(decoded.digest(), coded_block.digest());
    }

    #[test]
    fn test_stored_coded_block_into_coded_block() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = CodedBlock::<TestBlock, RS, H>::new(block, CONFIG, &Sequential);
        let original_commitment = coded_block.commitment();
        let original_digest = coded_block.digest();

        let stored = StoredCodedBlock::<TestBlock, RS, H>::new(coded_block);
        let encoded = stored.encode();
        let decoded = StoredCodedBlock::<TestBlock, RS, H>::decode_cfg(encoded, &()).unwrap();
        let restored = decoded.into_coded_block();

        assert_eq!(restored.commitment(), original_commitment);
        assert_eq!(restored.digest(), original_digest);
    }

    #[test]
    fn test_stored_coded_block_corruption_detection() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = CodedBlock::<TestBlock, RS, H>::new(block, CONFIG, &Sequential);
        let stored = StoredCodedBlock::<TestBlock, RS, H>::new(coded_block);

        let mut encoded = stored.encode().to_vec();

        // Corrupt the commitment (located after the block bytes)
        let block_size = stored.inner().encode_size();
        encoded[block_size] ^= 0xFF;

        // Decoding should fail due to digest mismatch
        let result = StoredCodedBlock::<TestBlock, RS, H>::decode_cfg(&mut encoded.as_slice(), &());
        assert!(result.is_err());
    }

    #[test]
    fn test_shard_encode_with_pool_matches_encode() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pool = context.network_buffer_pool();

            const CONFIG: CodingConfig = CodingConfig {
                minimum_shards: NZU16!(1),
                extra_shards: NZU16!(2),
            };

            let (commitment, shards) =
                RS::encode(&CONFIG, b"pool encoding test".as_slice(), &Sequential).unwrap();
            let commitment =
                Commitment::from((Sha256Digest::EMPTY, commitment, Sha256Digest::EMPTY, CONFIG));
            let shard = RShard::new(commitment, 0, shards.into_iter().next().unwrap());

            let encoded = shard.encode();
            let mut encoded_pool = shard.encode_with_pool(pool);
            let mut encoded_pool_bytes = vec![0u8; encoded_pool.remaining()];
            encoded_pool.copy_to_slice(&mut encoded_pool_bytes);
            assert_eq!(encoded_pool_bytes, encoded.as_ref());
        });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Shard<TestBlock, ReedSolomon<Sha256>, Sha256>>,
        }
    }
}
