#[cfg(test)]
mod tests {
    use crate::{
        nonce::{NonceManager, abi::INonce::Calls},
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };

    #[test]
    fn test_nonce_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut nonce_manager = NonceManager::new();

            let unsupported = check_selector_coverage(
                &mut nonce_manager,
                Calls::SELECTORS,
                "INonce",
                Calls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
            Ok(())
        })
    }
}
