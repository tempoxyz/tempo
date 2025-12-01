//! String storage tests.

use super::*;

#[test]
fn test_string() {
    #[contract]
    pub struct Layout {
        pub one_string: String,
        pub another_string: String,
    }

    let (mut storage, address) = setup_storage();
    StorageContext::enter(&mut storage, || {
        let mut layout = Layout::__new(address);

        // Test empty string
        layout.another_string.write(String::new()).unwrap();
        assert_eq!(layout.another_string.read().unwrap(), "");

        // Test short string
        let short = "Hello Tempo!".to_string();
        layout.one_string.write(short.clone()).unwrap();
        assert_eq!(layout.one_string.read().unwrap(), short);

        // Test max length (31 bytes)
        let short_max = "a".repeat(31);
        layout.one_string.write(short_max.clone()).unwrap();
        assert_eq!(layout.one_string.read().unwrap(), short_max);

        // Test long string (32 bytes)
        let long_min = "b".repeat(32);
        layout.one_string.write(long_min.clone()).unwrap();
        assert_eq!(layout.one_string.read().unwrap(), long_min);

        // Test long string (100 bytes)
        let long = "c".repeat(100);
        layout.one_string.write(long.clone()).unwrap();
        assert_eq!(layout.one_string.read().unwrap(), long);

        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    #[allow(clippy::redundant_clone)]
    fn proptest_one_string(
        str1 in arb_string(),
        str2 in arb_string()
    ) {
        #[contract]
        pub struct Layout {
            pub one_string: String,
            pub another_string: String,
        }

        let (mut storage, address) = setup_storage();
        StorageContext::enter(&mut storage, || {
            let mut layout = Layout::__new(address);

            // Store arbitrary strings
            layout.one_string.write(str1.clone())?;
            layout.another_string.write(str2.clone())?;

            // Roundtrip property
            prop_assert_eq!(layout.one_string.read()?, str1);
            prop_assert_eq!(layout.another_string.read()?, str2.clone());

            // Delete property
            layout.one_string.delete()?;
            prop_assert_eq!(layout.one_string.read()?, String::new());

            // Other field should be unaffected (isolation)
            prop_assert_eq!(layout.another_string.read()?, str2.clone());

            Ok(())
        })?;
    }
}
