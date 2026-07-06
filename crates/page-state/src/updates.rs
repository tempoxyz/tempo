use crate::{
    page::{Page, PageIndex},
    smt::{NodePath, PageTreeNode},
};
use alloy_primitives::{Address, B256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountPageUpdates {
    pub new_root: B256,
    pub pages: BTreeMap<PageIndex, Option<Page>>,
    pub nodes: BTreeMap<NodePath, Option<PageTreeNode>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PageStateUpdates {
    pub accounts: BTreeMap<Address, AccountPageUpdates>,
}

impl PageStateUpdates {
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
}
