//! Read committed progress without initializing static-file or RocksDB providers.
use reth_db::{Database, mdbx::DatabaseArguments, open_db_read_only, tables, transaction::DbTx};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().ok_or("expected existing MDBX directory")?;
    if args.next().is_some() {
        return Err("expected exactly one MDBX directory".into());
    }
    let db = open_db_read_only(path, DatabaseArguments::default())?;
    let tx = db.tx()?;
    let checkpoint = tx
        .get::<tables::StageCheckpoints>("Finish".to_owned())?
        .ok_or("missing Finish checkpoint")?;
    println!("{}", serde_json::to_string(&checkpoint)?);
    Ok(())
}
