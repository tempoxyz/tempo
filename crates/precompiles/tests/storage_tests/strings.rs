//! String storage tests.

use super::*;

#[test]
fn test_string() {
    #[contract]
    pub struct Layout {
        pub one_string: String,
        pub another_string: String,
    }

    let mut s = setup_storage();
    let mut layout = Layout::_new(s.address, s.storage());

    // Test empty string
    layout.sstore_another_string(String::new()).unwrap();
    assert_eq!(layout.sload_another_string().unwrap(), "");

    // Test short string
    let short = "Hello Tempo!".to_string();
    layout.sstore_one_string(short.clone()).unwrap();
    assert_eq!(layout.sload_one_string().unwrap(), short);

    // Test max length (31 bytes)
    let short_max = "a".repeat(31);
    layout.sstore_one_string(short_max.clone()).unwrap();
    assert_eq!(layout.sload_one_string().unwrap(), short_max);

    // Test long string (32 bytes)
    let long_min = "b".repeat(32);
    layout.sstore_one_string(long_min.clone()).unwrap();
    assert_eq!(layout.sload_one_string().unwrap(), long_min);

    // Test long string (100 bytes)
    let long = "c".repeat(100);
    layout.sstore_one_string(long.clone()).unwrap();
    assert_eq!(layout.sload_one_string().unwrap(), long);
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

        let mut s = setup_storage();
        {
            let mut layout = Layout::_new(s.address, s.storage());

            // Store arbitrary strings
            layout.sstore_one_string(str1.clone())?;
            layout.sstore_another_string(str2.clone())?;

            // Roundtrip property
            prop_assert_eq!(layout.sload_one_string()?, str1);
            prop_assert_eq!(layout.sload_another_string()?, str2.clone());

            // Delete property
            layout.clear_one_string()?;
            prop_assert_eq!(layout.sload_one_string()?, String::new());

            // Other field should be unaffected (isolation)
            prop_assert_eq!(layout.sload_another_string()?, str2.clone());
        }
    }
}
