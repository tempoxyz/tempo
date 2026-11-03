//! Reclaims the SlateDB files a complete corpus no longer needs.
//!
//! Writers keep superseded checkpoints, compacted sorted runs, WAL SSTs and manifests, so a
//! finished corpus holds far more than its live records.

use crate::store::{SLATEDB_RETRIES, Store};
use eyre::OptionExt;
use futures::TryStreamExt;
use object_store::ObjectStoreExt;
use slatedb::{
    admin::Admin,
    config::{GarbageCollectorDirectoryOptions, GarbageCollectorOptions},
};
use std::{collections::BTreeMap, time::Duration};
use tracing::info;

/// Deletes every checkpoint except the one the catalog pins and retired ones still within
/// their grace lifetime, then garbage collects the manifests, WAL SSTs, compacted SSTs and
/// compactor state nothing references any more, and logs the objects and bytes of each data
/// directory before and after.
///
/// Fails unless the corpus is complete: a fill clears it before opening its writer, so
/// collection needs no minimum file age as long as no fill starts meanwhile. Run it after a
/// fill, not alongside one. Fails as well if the catalog changed meanwhile or its checkpoint
/// no longer opens.
pub async fn gc(store: &Store) -> eyre::Result<()> {
    let (catalog, version) = store.catalog().await?.ok_or_eyre("no corpus catalog")?;
    eyre::ensure!(
        catalog.complete,
        "corpus is not complete; its writer may still be running"
    );
    let pinned = catalog
        .checkpoint
        .as_deref()
        .ok_or_eyre("corpus has no published checkpoint")?;
    let before = usage(store).await?;
    let admin = Admin::builder(store.data(), store.objects.clone()).build();
    let checkpoints = admin.list_checkpoints(None).await?;
    eyre::ensure!(
        checkpoints.iter().any(|c| c.id.to_string() == pinned),
        "catalog checkpoint is missing from the corpus manifest"
    );
    let started = std::time::SystemTime::now();
    // A checkpoint a fill retired keeps its grace lifetime, so replays still pinned to it
    // finish; collection keeps the files it references until it expires.
    for checkpoint in checkpoints.iter().filter(|c| {
        c.id.to_string() != pinned
            && c.expire_time
                .is_none_or(|expiry| std::time::SystemTime::from(expiry) <= started)
    }) {
        admin.delete_checkpoint(checkpoint.id).await?;
    }
    let now = GarbageCollectorDirectoryOptions {
        interval: None,
        min_age: Duration::ZERO,
        dry_run: false,
    };
    // SlateDB logs and skips a directory whose collection fails, so the sizes below are the
    // outcome.
    admin
        .run_gc_once(GarbageCollectorOptions {
            manifest_options: Some(now),
            wal_options: Some(now),
            compacted_options: Some(now),
            compactions_options: Some(now),
            wal_fence_options: None,
            detach_options: None,
            // Boundaries fence stalled writers, which a complete corpus has none of, and need
            // conditional overwrites, which local stores lack.
            boundary_files_enabled: false,
            object_store_max_retries: SLATEDB_RETRIES,
            ..Default::default()
        })
        .await?;
    let after = usage(store).await?;
    for (directory, (objects, bytes)) in &before {
        let (objects_after, bytes_after) = after.get(directory).copied().unwrap_or_default();
        info!(
            %directory,
            objects,
            bytes,
            objects_after,
            bytes_after,
            "Collected corpus garbage"
        );
    }
    let current = store.objects.head(&store.catalog_path()).await?;
    eyre::ensure!(
        current.e_tag == version.e_tag,
        "corpus catalog changed during gc; another writer published"
    );
    store.reader(&catalog).await?.close().await?;
    Ok(())
}

/// Object count and bytes under each top-level directory of the corpus data.
async fn usage(store: &Store) -> eyre::Result<BTreeMap<String, (u64, u64)>> {
    let data = store.data();
    let mut usage = BTreeMap::<String, (u64, u64)>::new();
    let mut objects = store.objects.list(Some(&data));
    while let Some(object) = objects.try_next().await? {
        let directory = object
            .location
            .prefix_match(&data)
            .and_then(|mut parts| parts.next())
            .map_or_else(String::new, |part| part.as_ref().to_owned());
        let entry = usage.entry(directory).or_default();
        entry.0 += 1;
        entry.1 += object.size;
    }
    Ok(usage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::{catalog, in_memory, open_db};

    #[tokio::test]
    async fn keeps_only_the_published_checkpoint_of_a_complete_corpus() -> eyre::Result<()> {
        let store = in_memory("gc");
        let mut catalog = catalog(1, 1, 0);
        catalog.seal()?;
        let db = open_db(&store, &catalog).await?;
        store.checkpoint(&db).await?;
        catalog.checkpoint = Some(store.checkpoint(&db).await?);
        db.close().await?;
        catalog.complete = false;
        let version = store.publish(&catalog, None).await?;
        assert_eq!(
            gc(&store).await.unwrap_err().to_string(),
            "corpus is not complete; its writer may still be running"
        );
        catalog.complete = true;
        store.publish(&catalog, Some(version)).await?;
        gc(&store).await?;
        let checkpoints = Admin::builder(store.data(), store.objects.clone())
            .build()
            .list_checkpoints(None)
            .await?;
        assert_eq!(
            checkpoints
                .iter()
                .map(|c| Some(c.id.to_string()))
                .collect::<Vec<_>>(),
            [catalog.checkpoint]
        );
        Ok(())
    }
}
