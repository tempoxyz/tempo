//! Experimental JSON exploration guidance, not a pass/fail assertion.
//!
//! This crate always enables the SDK's `full` feature. `guidance_helper!` catalogs a
//! `hit=false` entry, emitted by `antithesis_init()` or the first regular assertion, and emits
//! every observation with `hit=true`, without
//! the first-success filtering of `assert_sometimes!`. JSON guidance is an SDK implementation
//! API; its effect on Antithesis search is deliberately left for platform validation.

/// Emits a structural shape at a stable, const message identity, with no local deduplication.
macro_rules! sometimes_each {
    ($message:expr, $shape:expr $(,)?) => {{
        let shape = $shape;
        antithesis_sdk::guidance_helper!(
            antithesis_sdk::assert::guidance::GuidanceType::Json,
            $message,
            false,
            shape
        );
    }};
}

pub(crate) use sometimes_each;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn evaluates_each_shape_once() {
        let mut evaluations = 0;
        for expected in 1..=3 {
            self::sometimes_each!("Test shape expression evaluation", {
                evaluations += 1;
                json!({"observation": evaluations})
            });
            assert_eq!(evaluations, expected);
        }
    }
}
