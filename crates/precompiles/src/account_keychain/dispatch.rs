#[cfg(test)]
mod tests {
    use crate::{
        account_keychain::{AccountKeychain, abi::IAccountKeychain::Calls},
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };

    #[test]
    fn test_account_keychain_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();

            let unsupported = check_selector_coverage(
                &mut keychain,
                Calls::SELECTORS,
                "IAccountKeychain",
                Calls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }
}
