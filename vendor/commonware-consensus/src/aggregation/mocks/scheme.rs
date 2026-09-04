//! Mock implementation of the [`Scheme`] trait for `aggregation` tests.

use crate::aggregation::types::{Item, Namespace};
use commonware_cryptography::impl_certificate_mock;

impl_certificate_mock!(&'a Item<D>, Namespace);
