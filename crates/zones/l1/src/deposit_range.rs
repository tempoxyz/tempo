use super::*;
use tempo_precompiles::{
    storage::{StorableType as _, packing::extract_from_word},
    zone_factory::portal::slots,
};
use zone_primitives::deposit_queue::DepositRangeEnd;

/// Returns how many of the `owed` entries fall in the range of the full Zone import at `anchor`.
pub async fn fetch_range_len(
    l1_provider: &impl Provider<TempoNetwork>,
    portal_address: Address,
    anchor: NumHash,
    owed: usize,
) -> eyre::Result<usize> {
    let read = |slot: U256| {
        l1_provider
            .get_storage_at(portal_address, slot)
            .block_id(BlockId::hash_canonical(anchor.hash))
            .into_future()
    };
    let (count_word, buckets_word, base_word) = futures::try_join!(
        read(slots::DEPOSIT_COUNT),
        read(slots::DEPOSIT_BUCKETS),
        read(slots::DEPOSIT_BUCKET_BASE),
    )?;
    let head: u64 = extract_from_word(count_word, slots::DEPOSIT_COUNT_OFFSET, u64::BYTES)?;
    let checkpoint_base = (!buckets_word.is_zero())
        .then(|| extract_from_word(base_word, slots::DEPOSIT_BUCKET_BASE_OFFSET, u64::BYTES))
        .transpose()?;
    let processed = head
        .checked_sub(u64::try_from(owed)?)
        .ok_or_else(|| eyre::eyre!("{owed} owed entries exceed Portal deposit count {head}"))?;
    let end = DepositRangeEnd::new(processed, head, checkpoint_base)
        .ok_or_else(|| eyre::eyre!("no deposit range after entry {processed}"))?;
    Ok(usize::try_from(end.target - processed)?)
}
