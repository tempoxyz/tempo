mod framework;
mod invariants;
mod strategies;

use proptest::test_runner::Config;
use strategies::executor::DexStateMachineTest;

prop_state_machine! {
    #![proptest_config(Config {
        cases: 500,
        .. Config::default()
    })]

    #[test]
    fn invariant_stablecoin_dex(sequential 1..50 => DexStateMachineTest);
}
