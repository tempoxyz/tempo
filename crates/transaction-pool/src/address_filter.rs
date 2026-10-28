//! Address checks for transaction pool admission.

use crate::transaction::{TempoPoolTransactionError, TempoPooledTransaction};
use alloy_consensus::Transaction;
use alloy_primitives::{Address, map::AddressSet};
use reth_transaction_pool::PoolTransaction;
use std::{iter, str::FromStr};

/// Addresses checked against every address a transaction names.
///
/// These are the recovered sender, the fee payer, every direct call target, the delegate and
/// recovered authority of every EIP-7702 or Tempo authorization, and every access list entry.
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

    /// Checks the addresses the transaction names without signature recovery.
    ///
    /// These are the recovered sender, every direct call target, every EIP-7702 or Tempo
    /// authorization delegate, and every access list entry. Fee payer and authorization
    /// authorities need signature recovery and are checked by [`Self::check_recovered`].
    pub fn check(
        &self,
        transaction: &TempoPooledTransaction,
    ) -> Result<(), TempoPoolTransactionError> {
        if self.is_empty() {
            return Ok(());
        }

        let inner = transaction.inner();
        let call_targets = inner.calls().filter_map(|(kind, _)| kind.into_to());
        let eip7702_delegates = inner
            .authorization_list()
            .unwrap_or_default()
            .iter()
            .map(|auth| auth.address);
        let tempo_delegates = inner
            .tempo_authorization_list()
            .unwrap_or_default()
            .iter()
            .map(|auth| auth.address);
        let access_list = transaction
            .access_list()
            .into_iter()
            .flat_map(|list| list.iter().map(|item| item.address));

        self.find_match(
            iter::once(*transaction.sender_ref())
                .chain(call_targets)
                .chain(eip7702_delegates)
                .chain(tempo_delegates)
                .chain(access_list),
        )
    }

    /// Checks the fee payer and the recovered authorization authorities.
    ///
    /// Called once validation has cached the transaction environment and recovered the
    /// authorities, so neither signature is recovered again. A fee payer that fails to recover
    /// was already rejected by validation.
    pub fn check_recovered(
        &self,
        transaction: &TempoPooledTransaction,
        authorities: &[Address],
    ) -> Result<(), TempoPoolTransactionError> {
        if self.is_empty() {
            return Ok(());
        }

        self.find_match(
            transaction
                .fee_payer()
                .ok()
                .into_iter()
                .chain(authorities.iter().copied()),
        )
    }

    fn find_match(
        &self,
        mut addresses: impl Iterator<Item = Address>,
    ) -> Result<(), TempoPoolTransactionError> {
        match addresses.find(|address| self.contains(address)) {
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
    use crate::{
        test_utils::TxBuilder,
        transaction::{TempoPoolTransactionError, TempoPooledTransaction},
    };
    use alloy_consensus::{SignableTransaction, TxEip7702};
    use alloy_eips::{
        eip2930::{AccessList, AccessListItem},
        eip7702::Authorization,
    };
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use reth_primitives_traits::Recovered;
    use reth_transaction_pool::PoolTransaction;
    use tempo_primitives::{
        TempoTxEnvelope,
        transaction::{TempoSignedAuthorization, tempo_transaction::Call},
    };

    fn authorization(delegate: Address) -> Authorization {
        Authorization {
            chain_id: U256::ONE,
            nonce: 0,
            address: delegate,
        }
    }

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
    fn checks_fee_payer_only_after_recovery() {
        let sender = Address::with_last_byte(12);
        let TempoTxEnvelope::AA(mut signed) =
            TxBuilder::aa(sender).build().inner().clone().into_inner()
        else {
            panic!("expected AA transaction");
        };
        let fee_payer = PrivateKeySigner::random();
        let fee_payer_hash = signed.tx().fee_payer_signature_hash(sender);
        signed.tx_mut().fee_payer_signature = Some(
            fee_payer
                .sign_hash_sync(&fee_payer_hash)
                .expect("fee payer signing should succeed"),
        );
        let transaction = TempoPooledTransaction::new(Recovered::new_unchecked(
            TempoTxEnvelope::AA(signed),
            sender,
        ));
        let filter = AddressFilter::new([fee_payer.address()]);

        assert!(filter.check(&transaction).is_ok());
        assert_address_check(
            filter.check_recovered(&transaction, &[]),
            fee_payer.address(),
        );
    }

    #[test]
    fn checks_recovered_authorities() {
        let authority = Address::with_last_byte(13);
        let transaction = TxBuilder::aa(Address::with_last_byte(14)).build();
        let filter = AddressFilter::new([authority]);

        assert_address_check(
            filter.check_recovered(&transaction, &[Address::with_last_byte(15), authority]),
            authority,
        );
    }

    #[test]
    fn checks_tempo_authorization_delegate() {
        let delegate = Address::with_last_byte(16);
        let transaction = TxBuilder::aa(Address::with_last_byte(17))
            .authorization_list(vec![TempoSignedAuthorization::new_unchecked(
                authorization(delegate),
                Signature::test_signature().into(),
            )])
            .build();

        assert_address_check(AddressFilter::new([delegate]).check(&transaction), delegate);
    }

    #[test]
    fn checks_eip7702_authorization_delegate() {
        let delegate = Address::with_last_byte(18);
        let tx = TxEip7702 {
            chain_id: 1,
            to: Address::with_last_byte(19),
            authorization_list: vec![
                authorization(delegate).into_signed(Signature::test_signature()),
            ],
            ..Default::default()
        };
        let transaction = TempoPooledTransaction::new(Recovered::new_unchecked(
            TempoTxEnvelope::Eip7702(tx.into_signed(Signature::test_signature())),
            Address::with_last_byte(20),
        ));

        assert_address_check(AddressFilter::new([delegate]).check(&transaction), delegate);
    }

    #[test]
    fn checks_access_list_entries() {
        let listed = Address::with_last_byte(21);
        let transaction = TxBuilder::aa(Address::with_last_byte(22))
            .access_list(AccessList(vec![AccessListItem {
                address: listed,
                storage_keys: Vec::new(),
            }]))
            .build();

        assert_address_check(AddressFilter::new([listed]).check(&transaction), listed);
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
