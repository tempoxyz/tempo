use commonware_consensus::marshal::Update;

use crate::consensus::{Digest, block::Block};

pub(crate) trait UpdateExt {
    type TheBlock;
    type TheTip: Copy;

    fn as_block(&self) -> Option<&Self::TheBlock>;
    fn into_block(self) -> Option<Self::TheBlock>;
}

impl UpdateExt for Update<Block> {
    type TheBlock = Block;

    type TheTip = (u64, Digest);

    fn as_block(&self) -> Option<&Self::TheBlock> {
        match self {
            Self::Block(block) => Some(block),
            _ => None,
        }
    }

    fn into_block(self) -> Option<Self::TheBlock> {
        match self {
            Self::Block(block) => Some(block),
            _ => None,
        }
    }
}
