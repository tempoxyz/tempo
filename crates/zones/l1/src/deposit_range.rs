use super::*;
use alloy_rpc_types_eth::Filter;
use eyre::OptionExt as _;
use tempo_precompiles::{
    storage::{StorableType as _, packing::extract_from_word},
    zone_factory::portal::slots,
};
use zone_primitives::deposit_queue::DepositRangeEnd;

/// Blocks per `eth_getLogs` request.
const ENTRY_SEARCH_BLOCKS: u64 = 10_000;

/// A deposit-queue position on L1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositQueuePosition {
    /// L1 block that appends the entries around the position.
    pub block_number: u64,
    /// Entries that block appends before the position.
    pub entries_in_block: usize,
}

impl DepositQueuePosition {
    /// Returns the position after entry `number`, whose event carries `queue_hash`, searching back
    /// from L1 block `through`.
    pub async fn find(
        l1_provider: &impl Provider<TempoNetwork>,
        portal_address: Address,
        through: u64,
        number: u64,
        queue_hash: B256,
    ) -> eyre::Result<Self> {
        let entry_events = Filter::new().address(portal_address).event_signature(vec![
            DepositMade::SIGNATURE_HASH,
            WithdrawalBounceBack::SIGNATURE_HASH,
        ]);
        let mut to = through;
        let block_number = loop {
            let from = to.saturating_sub(ENTRY_SEARCH_BLOCKS - 1);
            let logs = l1_provider
                .get_logs(
                    &entry_events
                        .clone()
                        .topic1(queue_hash)
                        .from_block(from)
                        .to_block(to),
                )
                .await?;
            if let Some(log) = logs.last() {
                break log.block_number.ok_or_eyre("log without block number")?;
            }
            to = from.checked_sub(1).ok_or_else(|| {
                eyre::eyre!("queue entry {number} not found at or before L1 block {through}")
            })?;
        };

        let mut entries = Vec::new();
        for log in &l1_provider
            .get_logs(&entry_events.from_block(block_number).to_block(block_number))
            .await?
        {
            match ZonePortalEvents::decode_log(&log.inner)?.data {
                ZonePortalEvents::DepositMade(event) => entries.push(event.depositNumber),
                ZonePortalEvents::WithdrawalBounceBack(event) => entries.push(event.depositNumber),
                _ => {}
            }
        }
        let entries_in_block = entries
            .iter()
            .position(|&entry| entry == number)
            .ok_or_else(|| {
                eyre::eyre!("L1 block {block_number} did not append queue entry {number}")
            })?
            + 1;
        Ok(Self {
            block_number,
            entries_in_block,
        })
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_transport::mock::Asserter;
    use test_case::test_case;

    #[test_case(ENTRY_SEARCH_BLOCKS + 5, &[&[], &[(3, 7)], &[(3, 5), (3, 6), (3, 7), (3, 8)]] => Ok(DepositQueuePosition { block_number: 3, entries_in_block: 3 }))]
    #[test_case(5, &[&[]] => Err("queue entry 7 not found at or before L1 block 5".to_owned()))]
    #[test_case(5, &[&[(3, 7)], &[(3, 6)]] => Err("L1 block 3 did not append queue entry 7".to_owned()))]
    #[tokio::test]
    async fn find(
        through: u64,
        responses: &[&[(u64, u64)]],
    ) -> Result<DepositQueuePosition, String> {
        let asserter = Asserter::new();
        for logs in responses {
            let logs: Vec<_> = logs
                .iter()
                .map(|&(block_number, number)| Log {
                    inner: alloy_primitives::Log {
                        address: Address::ZERO,
                        data: WithdrawalBounceBack {
                            newCurrentDepositQueueHash: B256::ZERO,
                            fallbackNonce: 0,
                            token: Address::ZERO,
                            amount: 1,
                            depositNumber: number,
                        }
                        .encode_log_data(),
                    },
                    block_number: Some(block_number),
                    ..Default::default()
                })
                .collect();
            asserter.push_success(&logs);
        }
        let provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter);

        DepositQueuePosition::find(&provider, Address::ZERO, through, 7, B256::ZERO)
            .await
            .map_err(|error| error.to_string())
    }
}
