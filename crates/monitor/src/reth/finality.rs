use crate::{
    facts::BlockNumHash,
    reth::{AdapterError, AdapterResult},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FinalizedWatermark {
    last: Option<BlockNumHash>,
}

impl FinalizedWatermark {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn last(&self) -> Option<BlockNumHash> {
        self.last
    }

    pub fn observe(&mut self, next: Option<BlockNumHash>) -> AdapterResult<Option<BlockNumHash>> {
        let Some(next) = next else {
            return Ok(self.last);
        };
        if let Some(last) = self.last {
            if next.number < last.number {
                return Err(AdapterError::Halt(format!(
                    "finalized watermark regressed from {last:?} to {next:?}"
                )));
            }
            if next.number == last.number && next.hash != last.hash {
                return Err(AdapterError::Halt(format!(
                    "finalized watermark changed hash at height {}",
                    next.number
                )));
            }
        }
        self.last = Some(next);
        Ok(self.last)
    }
}
