//! Mock implementation of the [`Scheme`] trait for `aggregation` tests.

use crate::aggregation::types::{Item, Namespace};
use commonware_cryptography::impl_certificate_mock;
use commonware_utils::N3f1;

impl_certificate_mock!(&'a Item<D>, Namespace, N3f1);
