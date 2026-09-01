//! Address checks for transaction pool admission.

use crate::transaction::{TempoPoolTransactionError, TempoPooledTransaction};
use alloy_primitives::{Address, map::AddressSet};
use reth_transaction_pool::PoolTransaction;
use std::str::FromStr;

/// Addresses checked against transaction senders and direct call targets.
///
/// Ordinary Ethereum-style transactions have at most one direct call target. Tempo
/// transactions may contain multiple calls, so every direct target is checked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressFilter {
    addresses: AddressSet,
}

impl AddressFilter {
    /// Creates a filter from the given addresses.
    pub fn new(addresses: impl IntoIterator<Item = Address>) -> Self {
        Self {
            addresses: addresses.into_iter().collect(),
        }
    }

    /// Returns whether no address checks are configured.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Returns the number of unique configured addresses.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Returns whether the address is configured.
    pub fn contains(&self, address: &Address) -> bool {
        self.addresses.contains(address)
    }

    /// Checks the recovered sender and every direct call target in the transaction.
    pub fn check(
        &self,
        transaction: &TempoPooledTransaction,
    ) -> Result<(), TempoPoolTransactionError> {
        if self.is_empty() {
            return Ok(());
        }

        let matched = self
            .contains(transaction.sender_ref())
            .then_some(*transaction.sender_ref())
            .or_else(|| {
                transaction
                    .inner()
                    .calls()
                    .filter_map(|(kind, _)| kind.into_to())
                    .find(|address| self.contains(address))
            });

        match matched {
            Some(address) => Err(TempoPoolTransactionError::AddressCheck { address }),
            None => Ok(()),
        }
    }
}

impl FromIterator<Address> for AddressFilter {
    fn from_iter<T: IntoIterator<Item = Address>>(iter: T) -> Self {
        Self::new(iter)
    }
}

impl From<Vec<Address>> for AddressFilter {
    fn from(addresses: Vec<Address>) -> Self {
        Self::new(addresses)
    }
}

impl FromStr for AddressFilter {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut addresses = Vec::new();

        for (line, values) in value.trim_start_matches('\u{feff}').lines().enumerate() {
            for value in values
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                let address = value.parse::<Address>().map_err(|error| {
                    format!("invalid address `{value}` on line {}: {error}", line + 1)
                })?;
                addresses.push(address);
            }
        }

        if addresses.is_empty() {
            return Err("no addresses provided".to_string());
        }

        Ok(Self::new(addresses))
    }
}

#[cfg(test)]
mod tests {
    use super::AddressFilter;
    use crate::{test_utils::TxBuilder, transaction::TempoPoolTransactionError};
    use alloy_primitives::{Address, Bytes, TxKind, U256};
    use reth_transaction_pool::PoolTransaction;
    use tempo_primitives::transaction::tempo_transaction::Call;

    fn assert_address_check(result: Result<(), TempoPoolTransactionError>, expected: Address) {
        assert!(matches!(
            result,
            Err(TempoPoolTransactionError::AddressCheck { address }) if address == expected
        ));
    }

    #[test]
    fn empty_filter_allows_transactions() {
        let transaction = TxBuilder::eip1559(Address::with_last_byte(1)).build_eip1559();

        assert!(AddressFilter::default().check(&transaction).is_ok());
    }

    #[test]
    fn checks_recovered_sender() {
        let transaction = TxBuilder::eip1559(Address::with_last_byte(1)).build_eip1559();
        let sender = *transaction.sender_ref();
        let filter = AddressFilter::new([sender]);

        assert_address_check(filter.check(&transaction), sender);
    }

    #[test]
    fn checks_ethereum_call_target() {
        let target = Address::with_last_byte(2);
        let transaction = TxBuilder::eip1559(target).build_eip1559();
        let filter = AddressFilter::new([target]);

        assert_address_check(filter.check(&transaction), target);
    }

    #[test]
    fn checks_every_tempo_call_target() {
        let sender = Address::with_last_byte(3);
        let first_target = Address::with_last_byte(4);
        let later_target = Address::with_last_byte(5);
        let transaction = TxBuilder::aa(sender)
            .calls(vec![
                Call {
                    to: TxKind::Call(first_target),
                    value: U256::ZERO,
                    input: Bytes::new(),
                },
                Call {
                    to: TxKind::Call(later_target),
                    value: U256::ZERO,
                    input: Bytes::new(),
                },
            ])
            .build();
        let filter = AddressFilter::new([later_target]);

        assert_address_check(filter.check(&transaction), later_target);
    }

    #[test]
    fn ignores_unlisted_addresses_and_create_calls() {
        let transaction = TxBuilder::aa(Address::with_last_byte(6))
            .calls(vec![
                Call {
                    to: TxKind::Create,
                    value: U256::ZERO,
                    input: Bytes::new(),
                },
                Call {
                    to: TxKind::Call(Address::with_last_byte(7)),
                    value: U256::ZERO,
                    input: Bytes::new(),
                },
            ])
            .build();
        let filter = AddressFilter::new([Address::with_last_byte(8)]);

        assert!(filter.check(&transaction).is_ok());
    }

    #[test]
    fn deduplicates_configured_addresses() {
        let address = Address::with_last_byte(9);
        let filter = AddressFilter::new([address, address]);

        assert_eq!(filter.len(), 1);
        assert!(filter.contains(&address));
    }

    #[test]
    fn parses_comma_and_newline_separated_addresses() {
        let first = Address::with_last_byte(10);
        let second = Address::with_last_byte(11);
        let filter = format!("{first}, {second}\n\n{first},")
            .parse::<AddressFilter>()
            .unwrap();

        assert_eq!(filter.len(), 2);
        assert!(filter.contains(&first));
        assert!(filter.contains(&second));
    }

    #[test]
    fn rejects_empty_and_invalid_address_lists() {
        assert_eq!(
            "\n, \n".parse::<AddressFilter>().unwrap_err(),
            "no addresses provided"
        );
        assert!(
            "0x0000000000000000000000000000000000000001\nnot-an-address"
                .parse::<AddressFilter>()
                .unwrap_err()
                .contains("invalid address `not-an-address` on line 2")
        );
    }
}
