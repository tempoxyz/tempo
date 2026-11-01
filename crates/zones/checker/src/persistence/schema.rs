//! MDBX tables and fixed-width checker keys.

use alloy_primitives::{Address, U256};
use reth_codecs::{Compress, Decompress, DecompressError};
use reth_db::{
    DatabaseError, TableSet,
    table::{Decode, Encode, Table, TableInfo},
};
use serde::{Deserialize, Serialize};

use crate::accounting::{AccountKey, TokenState};

use super::model::Metadata;

/// Fixed single-byte key discriminating schema metadata rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum MetaKey {
    Version,
    Metadata,
}

impl Encode for MetaKey {
    type Encoded = [u8; 1];

    fn encode(self) -> Self::Encoded {
        [match self {
            Self::Version => 0,
            Self::Metadata => 1,
        }]
    }
}

impl Decode for MetaKey {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        match value {
            [0] => Ok(Self::Version),
            [1] => Ok(Self::Metadata),
            _ => Err(DatabaseError::Decode),
        }
    }
}

/// Versioned payload stored under a `MetaKey`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum MetaValue {
    Version(u32),
    Metadata(Box<Metadata>),
}

/// Durable row wrapper for one token's aggregate state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TokenValue(pub(crate) TokenState);

/// Big-endian `U256` balance row, compressed without the version/bincode envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AccountValue(pub(crate) U256);

impl Compress for AccountValue {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        buf.put_slice(&self.0.to_be_bytes::<32>());
    }
}

impl Decompress for AccountValue {
    fn decompress(value: &[u8]) -> Result<Self, DecompressError> {
        if value.len() != 32 {
            return Err(DecompressError::new(std::io::Error::other(
                "invalid account value width",
            )));
        }
        Ok(Self(U256::from_be_slice(value)))
    }
}

impl Encode for AccountKey {
    type Encoded = [u8; 40];

    fn encode(self) -> Self::Encoded {
        let mut encoded = [0; 40];
        encoded[..20].copy_from_slice(self.token.as_slice());
        encoded[20..].copy_from_slice(self.account.as_slice());
        encoded
    }
}

impl Decode for AccountKey {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.len() != 40 {
            return Err(DatabaseError::Decode);
        }
        Ok(Self::new(
            Address::from_slice(&value[..20]),
            Address::from_slice(&value[20..]),
        ))
    }
}

macro_rules! table {
    ($name:ident, $key:ty, $value:ty, $db:literal) => {
        #[derive(Debug)]
        pub(crate) struct $name;

        impl Table for $name {
            const NAME: &'static str = $db;
            const DUPSORT: bool = false;
            type Key = $key;
            type Value = $value;
        }

        impl TableInfo for $name {
            fn name(&self) -> &'static str {
                Self::NAME
            }

            fn is_dupsort(&self) -> bool {
                false
            }
        }
    };
}

table!(Meta, MetaKey, MetaValue, "CheckerMeta");
table!(Accounts, AccountKey, AccountValue, "CheckerAccounts");
table!(Tokens, Address, TokenValue, "CheckerTokens");

/// All MDBX tables owned by the checker database.
pub(crate) struct Tables;

impl TableSet for Tables {
    fn tables() -> Box<dyn Iterator<Item = Box<dyn TableInfo>>> {
        Box::new(
            vec![
                Box::new(Meta) as Box<dyn TableInfo>,
                Box::new(Accounts),
                Box::new(Tokens),
            ]
            .into_iter(),
        )
    }
}
