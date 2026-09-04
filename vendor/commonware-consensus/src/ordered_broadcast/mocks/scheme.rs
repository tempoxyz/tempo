//! Mock implementation of the [`Scheme`] trait for `ordered_broadcast` tests.

use crate::ordered_broadcast::types::{AckNamespace, AckSubject};
use commonware_cryptography::impl_certificate_mock;

impl_certificate_mock!(AckSubject<'a, P, D>, AckNamespace);
