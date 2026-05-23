//! Support for the [`diesel`](https://crates.io/crates/diesel) crate.
//!
//! Supports big-endian binary serialization via into sql_types::Binary.
//! Similar to [`ruint`'s implementation](https://github.com/recmo/uint/blob/fd57517b36cda8341f7740dacab4b1ec186af948/src/support/diesel.rs)

use crate::{FixedBytes, Signature, SignatureError};

use diesel::{
    backend::Backend,
    deserialize::{FromSql, Result as DeserResult},
    query_builder::bind_collector::RawBytesBindCollector,
    serialize::{IsNull, Output, Result as SerResult, ToSql},
    sql_types::Binary,
};
use std::io::Write;

impl<const BYTES: usize, Db> ToSql<Binary, Db> for FixedBytes<BYTES>
where
    Db: Backend,
    [u8]: ToSql<Binary, Db>,
{
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Db>) -> SerResult {
        (&self.0 as &[u8]).to_sql(out)
    }
}

impl<const BYTES: usize, Db: Backend> FromSql<Binary, Db> for FixedBytes<BYTES>
where
    *const [u8]: FromSql<Binary, Db>,
{
    fn from_sql(bytes: Db::RawValue<'_>) -> DeserResult<Self> {
        let bytes: *const [u8] = FromSql::<Binary, Db>::from_sql(bytes)?;
        let bytes = unsafe { &*bytes };
        Self::try_from(bytes).map_err(|e| e.into())
    }
}

impl<Db: Backend> ToSql<Binary, Db> for Signature
where
    for<'c> Db: Backend<BindCollector<'c> = RawBytesBindCollector<Db>>,
{
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Db>) -> SerResult {
        out.write_all(&self.as_erc2098())?;
        Ok(IsNull::No)
    }
}

impl<Db: Backend> FromSql<Binary, Db> for Signature
where
    *const [u8]: FromSql<Binary, Db>,
{
    fn from_sql(bytes: Db::RawValue<'_>) -> DeserResult<Self> {
        let bytes: *const [u8] = FromSql::<Binary, Db>::from_sql(bytes)?;
        let bytes = unsafe { &*bytes };
        if bytes.len() != 64 {
            return Err(SignatureError::FromBytes("Invalid length").into());
        }
        Ok(Self::from_erc2098(bytes))
    }
}
