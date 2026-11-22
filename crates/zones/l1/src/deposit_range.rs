use super::*;
use crate::{abi::ZonePortal, state::L1StateProvider};
use eyre::OptionExt as _;
use tempo_precompiles::{
    storage::{StorableType as _, packing::extract_from_word},
    zone_factory::portal::slots,
};
use zone_primitives::deposit_queue::DepositRangeEnd;

/// Blocks per backward search window. A window the RPC rejects is split into smaller requests.
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
    /// Returns the position of the first entry after the last executed entry, searching back
    /// from L1 block `through`, or the start of `through + 1` if no later entry was appended.
    pub async fn find(
        l1_provider: &impl Provider<TempoNetwork>,
        portal_address: Address,
        through: u64,
        last_processed: Option<u64>,
    ) -> eyre::Result<Self> {
        let after_through = Self {
            block_number: through.saturating_add(1),
            entries_in_block: 0,
        };
        let Some(last_processed) = last_processed else {
            return Ok(after_through);
        };
        let portal = ZonePortal::new(portal_address, l1_provider);
        let deposit_count = portal
            .depositCount()
            .block(BlockId::number(through))
            .call()
            .await?;
        if deposit_count <= last_processed {
            return Ok(after_through);
        }
        let first_owed = last_processed + 1;

        // Search for the first owed entry, so recovery never reads blocks without owed work.
        let mut to = through;
        loop {
            let from = to.saturating_sub(ENTRY_SEARCH_BLOCKS - 1);
            let logs = portal
                .DepositMade_filter()
                .event_signature(vec![
                    DepositMade::SIGNATURE_HASH,
                    WithdrawalBounceBack::SIGNATURE_HASH,
                    VirtualDepositMade::SIGNATURE_HASH,
                ])
                .select(from..=to)
                .chunked()
                .query_raw()
                .await?;

            let mut entries = Vec::new();
            for log in &logs {
                let entry = match ZonePortalEvents::decode_log(&log.inner)?.data {
                    ZonePortalEvents::DepositMade(event) => event.depositNumber,
                    ZonePortalEvents::WithdrawalBounceBack(event) => event.depositNumber,
                    ZonePortalEvents::VirtualDepositMade(event) => event.depositNumber,
                    // TODO: match against forced exits when added
                    _ => continue,
                };
                entries.push((log.block_number.ok_or_eyre("missing block number")?, entry));
            }
            if let Some(&(block_number, _)) = entries.iter().find(|(_, e)| *e == first_owed) {
                let entries_in_block = entries
                    .iter()
                    .filter(|&&(b, e)| b == block_number && e < first_owed)
                    .count();
                return Ok(Self {
                    block_number,
                    entries_in_block,
                });
            }
            to = from.checked_sub(1).ok_or_else(|| {
                eyre::eyre!("queue entry {first_owed} not found at or before L1 block {through}")
            })?;
        }
    }
}

/// Returns how many of the `owed` entries fall in the range of the full Zone import at `anchor`.
pub async fn fetch_range_len(
    l1_state: &L1StateProvider,
    portal_address: Address,
    anchor: NumHash,
    owed: usize,
) -> eyre::Result<usize> {
    let read = |slot: U256| async move {
        l1_state
            .get_storage_async(portal_address, slot.into(), anchor.number)
            .await
            .map(|word| word.into())
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
    use alloy_primitives::Bytes;
    use alloy_sol_types::SolCall as _;
    use alloy_transport::mock::Asserter;
    use test_case::test_case;

    #[test_case(ENTRY_SEARCH_BLOCKS + 5, Some(7), 10, &[&[(9, 10)], &[(2, 6), (2, 7), (4, 8), (4, 9)]] => Ok(DepositQueuePosition { block_number: 4, entries_in_block: 0 }))]
    #[test_case(5, Some(7), 8, &[&[(3, 5), (3, 6), (3, 7), (3, 8)]] => Ok(DepositQueuePosition { block_number: 3, entries_in_block: 3 }))]
    #[test_case(5, Some(7), 7, &[] => Ok(DepositQueuePosition { block_number: 6, entries_in_block: 0 }))]
    #[test_case(5, None, 0, &[] => Ok(DepositQueuePosition { block_number: 6, entries_in_block: 0 }))]
    #[test_case(5, Some(7), 8, &[&[(3, 7)]] => Err("queue entry 8 not found at or before L1 block 5".to_owned()))]
    #[tokio::test]
    async fn find(
        through: u64,
        last_processed: Option<u64>,
        deposit_count: u64,
        responses: &[&[(u64, u64)]],
    ) -> Result<DepositQueuePosition, String> {
        let asserter = Asserter::new();
        asserter.push_success(&Bytes::from(
            ZonePortal::depositCountCall::abi_encode_returns(&deposit_count),
        ));
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

        DepositQueuePosition::find(&provider, Address::ZERO, through, last_processed)
            .await
            .map_err(|error| error.to_string())
    }

    /// The first owed entry is a virtual deposit, after a bounce-back and a virtual deposit in the
    /// same block.
    #[tokio::test]
    async fn find_counts_virtual_deposits() {
        let asserter = Asserter::new();
        asserter.push_success(&Bytes::from(
            ZonePortal::depositCountCall::abi_encode_returns(&9),
        ));
        let virtual_log = |number: u64| Log {
            inner: alloy_primitives::Log {
                address: Address::ZERO,
                data: VirtualDepositMade {
                    newCurrentDepositQueueHash: B256::ZERO,
                    originator: Address::ZERO,
                    token: Address::ZERO,
                    destination: Address::ZERO,
                    netAmount: 1,
                    fee: 0,
                    depositNumber: number,
                    hasMemo: false,
                    memo: B256::ZERO,
                }
                .encode_log_data(),
            },
            block_number: Some(3),
            ..Default::default()
        };
        let bounce = Log {
            inner: alloy_primitives::Log {
                address: Address::ZERO,
                data: WithdrawalBounceBack {
                    newCurrentDepositQueueHash: B256::ZERO,
                    fallbackNonce: 0,
                    token: Address::ZERO,
                    amount: 1,
                    depositNumber: 6,
                }
                .encode_log_data(),
            },
            block_number: Some(3),
            ..Default::default()
        };
        asserter.push_success(&vec![bounce, virtual_log(7), virtual_log(8)]);
        let provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter);

        assert_eq!(
            DepositQueuePosition::find(&provider, Address::ZERO, 5, Some(7))
                .await
                .unwrap(),
            DepositQueuePosition {
                block_number: 3,
                entries_in_block: 2
            }
        );
    }
}
