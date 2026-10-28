use crate::types::Height;
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Error, Read, ReadExt, Write, varint::UInt};
use commonware_cryptography::{Digest, Digestible, Hasher};
use std::fmt::Debug;

/// A mock block with no explicit consensus context.
/// Its parent digest also serves as its certification context.
pub struct EmptyBlock<H: Hasher> {
    /// The parent block's digest.
    pub parent: H::Digest,

    /// The height of the block in the blockchain.
    pub height: Height,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    pub timestamp: u64,
}

impl<H: Hasher> EmptyBlock<H> {
    pub const fn new(parent: H::Digest, height: Height, timestamp: u64) -> Self {
        Self {
            parent,
            height,
            timestamp,
        }
    }
}

impl<H: Hasher> Clone for EmptyBlock<H> {
    fn clone(&self) -> Self {
        Self {
            parent: self.parent,
            height: self.height,
            timestamp: self.timestamp,
        }
    }
}

impl<H: Hasher> Debug for EmptyBlock<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmptyBlock")
            .field("parent", &self.parent)
            .field("height", &self.height)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

impl<H: Hasher> PartialEq for EmptyBlock<H> {
    fn eq(&self, other: &Self) -> bool {
        self.parent == other.parent
            && self.height == other.height
            && self.timestamp == other.timestamp
    }
}

impl<H: Hasher> Eq for EmptyBlock<H> {}

impl<H: Hasher> Write for EmptyBlock<H> {
    fn write(&self, writer: &mut impl BufMut) {
        self.parent.write(writer);
        self.height.write(writer);
        UInt(self.timestamp).write(writer);
    }
}

impl<H: Hasher> Read for EmptyBlock<H> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let parent = H::Digest::read(reader)?;
        let height = Height::read(reader)?;
        let timestamp = UInt::read(reader)?.into();

        Ok(Self {
            parent,
            height,
            timestamp,
        })
    }
}

impl<H: Hasher> EncodeSize for EmptyBlock<H> {
    fn encode_size(&self) -> usize {
        self.parent.encode_size() + self.height.encode_size() + UInt(self.timestamp).encode_size()
    }
}

impl<H: Hasher> Digestible for EmptyBlock<H> {
    type Digest = H::Digest;

    fn digest(&self) -> H::Digest {
        H::hash(&[
            self.parent.as_ref(),
            &self.height.get().to_be_bytes(),
            &self.timestamp.to_be_bytes(),
        ])
    }
}

impl<H: Hasher> crate::Heightable for EmptyBlock<H> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<H: Hasher> crate::Block for EmptyBlock<H> {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl<H: Hasher> crate::CertifiableBlock for EmptyBlock<H> {
    type Context = H::Digest;

    fn context(&self) -> Self::Context {
        self.parent
    }
}

/// A mock block type for testing that stores consensus context.
///
/// The context type `C` should be the consensus context (e.g., `simplex::types::Context`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block<D: Digest, C> {
    /// The consensus context that was used when this block was proposed.
    pub context: C,

    /// The parent block's digest.
    pub parent: D,

    /// The height of the block in the blockchain.
    pub height: Height,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    pub timestamp: u64,

    /// Pre-computed digest of the block.
    digest: D,
}

impl<D: Digest, C: Codec> Block<D, C> {
    fn compute_digest<H: Hasher<Digest = D>>(
        context: &C,
        parent: &D,
        height: Height,
        timestamp: u64,
    ) -> D {
        H::hash(&[
            parent.as_ref(),
            &height.get().to_be_bytes(),
            &context.encode(),
            &timestamp.to_be_bytes(),
        ])
    }

    pub fn new<H: Hasher<Digest = D>>(
        context: C,
        parent: D,
        height: Height,
        timestamp: u64,
    ) -> Self {
        let digest = Self::compute_digest::<H>(&context, &parent, height, timestamp);
        Self {
            context,
            parent,
            height,
            timestamp,
            digest,
        }
    }
}

impl<D: Digest, C: Write> Write for Block<D, C> {
    fn write(&self, writer: &mut impl BufMut) {
        self.context.write(writer);
        self.parent.write(writer);
        self.height.write(writer);
        UInt(self.timestamp).write(writer);
        self.digest.write(writer);
    }
}

impl<D: Digest, C: Read<Cfg = ()>> Read for Block<D, C> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let context = C::read(reader)?;
        let parent = D::read(reader)?;
        let height = Height::read(reader)?;
        let timestamp = UInt::read(reader)?.into();
        let digest = D::read(reader)?;

        Ok(Self {
            context,
            parent,
            height,
            timestamp,
            digest,
        })
    }
}

impl<D: Digest, C: EncodeSize> EncodeSize for Block<D, C> {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + UInt(self.timestamp).encode_size()
            + self.digest.encode_size()
    }
}

impl<D: Digest, C: Clone + Send + Sync + 'static> Digestible for Block<D, C> {
    type Digest = D;

    fn digest(&self) -> D {
        self.digest
    }
}

impl<D: Digest, C: Clone + Send + Sync + 'static> crate::Heightable for Block<D, C> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<D: Digest, C: Codec<Cfg = ()> + Clone + Send + Sync + 'static> crate::Block for Block<D, C> {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl<D: Digest, C: Codec<Cfg = ()> + Clone + Send + Sync + 'static> crate::CertifiableBlock
    for Block<D, C>
{
    type Context = C;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}
