//! Reusable command-line arguments for Tempo hardfork activations in genesis generators.

use alloy_genesis::ChainConfig;
use serde_json::Value;
use tempo_hardfork::TempoHardfork;

/// Generates [`TempoHardforkArgs`] with one `--<fork>-time` flag per post-Genesis hardfork.
macro_rules! tempo_hardfork_args {
    ($($variant:ident),* $(,)?) => {
        paste::paste! {
            /// Tempo hardfork activation arguments for genesis generators.
            ///
            /// Every hardfork activates at genesis unless `--hardfork` disables later forks or an
            /// individual `--<fork>-time` flag overrides it.
            #[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
            pub struct TempoHardforkArgs {
                /// Latest Tempo hardfork to enable, for example `T13`. Later hardforks are
                /// disabled unless their `--<fork>-time` flag is passed.
                #[arg(long, value_name = "HARDFORK")]
                pub hardfork: Option<TempoHardfork>,

                $(
                    #[doc = concat!(stringify!($variant), " hardfork activation timestamp (0 = genesis).")]
                    #[arg(long, value_name = "TIMESTAMP")]
                    pub [<$variant:lower _time>]: Option<u64>,
                )*
            }

            impl TempoHardforkArgs {
                /// Returns the explicitly passed `--<fork>-time` flag.
                fn explicit_time(&self, fork: TempoHardfork) -> Option<u64> {
                    match fork {
                        $(TempoHardfork::$variant => self.[<$variant:lower _time>],)*
                        _ => None,
                    }
                }
            }
        }
    };
}

tempo_hardfork::tempo_post_genesis_hardforks!(tempo_hardfork_args);

impl TempoHardforkArgs {
    /// Returns the activation timestamp of `fork`, or `None` if it is disabled.
    ///
    /// An explicit `--<fork>-time` flag takes precedence. Otherwise forks after `--hardfork` are
    /// disabled and all other forks activate at genesis.
    pub fn fork_time(&self, fork: TempoHardfork) -> Option<u64> {
        if fork == TempoHardfork::Genesis {
            return Some(0);
        }
        self.explicit_time(fork).or(match self.hardfork {
            Some(latest) if fork > latest => None,
            _ => Some(0),
        })
    }

    /// Returns `true` if `fork` activates at genesis.
    pub fn active_at_genesis(&self, fork: TempoHardfork) -> bool {
        self.fork_time(fork) == Some(0)
    }

    /// Writes every post-Genesis hardfork activation into `config`, using `null` for disabled
    /// forks so they cannot be inherited from a parent chain. Other fields are left untouched.
    pub fn write_to(&self, config: &mut ChainConfig) {
        for &fork in TempoHardfork::VARIANTS {
            if let Some(key) = fork.genesis_key() {
                let value = self.fork_time(fork).map_or(Value::Null, Value::from);
                config.extra_fields.insert(key.to_owned(), value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;
    use tempo_hardfork::TempoHardfork::*;

    #[derive(Debug, Parser)]
    struct Cli {
        #[command(flatten)]
        forks: TempoHardforkArgs,
    }

    fn parse(args: &[&str]) -> Result<TempoHardforkArgs, clap::Error> {
        Cli::try_parse_from(core::iter::once("test").chain(args.iter().copied()))
            .map(|cli| cli.forks)
    }

    fn times(args: &TempoHardforkArgs) -> Vec<(TempoHardfork, Option<u64>)> {
        TempoHardfork::VARIANTS
            .iter()
            .map(|&fork| (fork, args.fork_time(fork)))
            .collect()
    }

    #[test]
    fn forks_default_to_genesis_and_flags_override_independently() {
        let args = parse(&["--t3-time", "100", "--t14-time=200"]).unwrap();
        for (fork, time) in times(&args) {
            let expected = match fork {
                T3 => 100,
                T14 => 200,
                _ => 0,
            };
            assert_eq!(time, Some(expected), "{fork}");
        }
    }

    #[test]
    fn duplicate_flags_are_rejected() {
        assert!(parse(&["--t3-time", "1", "--t3-time=2"]).is_err());
    }

    #[test]
    fn hardfork_disables_later_forks() {
        let args = parse(&["--hardfork", "t13"]).unwrap();
        for (fork, time) in times(&args) {
            assert_eq!(time, (fork <= T13).then_some(0), "{fork}");
            assert_eq!(args.active_at_genesis(fork), fork <= T13, "{fork}");
        }
    }

    #[test]
    fn explicit_flags_override_hardfork() {
        let args = parse(&["--hardfork", "T12", "--t13-time", "100"]).unwrap();
        assert_eq!(args.fork_time(T12), Some(0));
        assert_eq!(args.fork_time(T13), Some(100));
        assert_eq!(args.fork_time(T14), None);
    }

    #[test]
    fn write_to_writes_every_fork_and_preserves_other_fields() {
        let mut config: ChainConfig =
            serde_json::from_value(json!({ "chainId": 1, "osakaTime": 7, "epochLength": 5 }))
                .unwrap();
        parse(&["--hardfork", "T13", "--t13-time", "100"])
            .unwrap()
            .write_to(&mut config);

        assert_eq!(config.osaka_time, Some(7));
        assert_eq!(config.extra_fields.get("epochLength"), Some(&json!(5)));
        assert_eq!(config.extra_fields.get("t12Time"), Some(&json!(0)));
        assert_eq!(config.extra_fields.get("t13Time"), Some(&json!(100)));
        assert_eq!(config.extra_fields.get("t14Time"), Some(&Value::Null));
        for &fork in TempoHardfork::VARIANTS {
            if let Some(key) = fork.genesis_key() {
                assert!(config.extra_fields.contains_key(key), "{key}");
            }
        }
    }
}
