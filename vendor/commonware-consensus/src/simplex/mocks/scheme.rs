//! Mock implementation of the [`Scheme`] trait for `simplex` tests.

use crate::simplex::{scheme::Namespace, types::Subject};
use commonware_cryptography::impl_certificate_mock;

impl_certificate_mock!(Subject<'a, D>, Namespace);
