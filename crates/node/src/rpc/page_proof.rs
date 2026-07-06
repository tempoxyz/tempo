use alloy_primitives::{Address, B256, U256};
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObject};
use serde::{Deserialize, Serialize};
use tempo_page_state::{Page, PageIndex, PageStateManager, PageTreeNode};

/// Response for `tempo_getPageProof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageProofResponse {
    pub address: Address,
    pub page_index: U256,
    pub page_root: B256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<Vec<PageWord>>,
    pub path_nodes: Vec<PageProofNode>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageWord {
    pub offset: u8,
    pub value: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum PageProofNode {
    Branch { left: B256, right: B256 },
    Leaf { page_index: U256, page_hash: B256 },
}

#[rpc(server, namespace = "tempo")]
pub trait TempoPageStateApi {
    /// Returns a page-tree proof for a page account page.
    #[method(name = "getPageProof")]
    async fn get_page_proof(
        &self,
        address: Address,
        page_index: U256,
        block_hash: Option<B256>,
    ) -> RpcResult<PageProofResponse>;
}

/// Implementation of `tempo_getPageProof`.
#[derive(Debug, Clone)]
pub struct TempoPageStateRpc {
    manager: PageStateManager,
}

impl TempoPageStateRpc {
    pub fn new(manager: PageStateManager) -> Self {
        Self { manager }
    }
}

#[async_trait::async_trait]
impl TempoPageStateApiServer for TempoPageStateRpc {
    async fn get_page_proof(
        &self,
        address: Address,
        page_index: U256,
        block_hash: Option<B256>,
    ) -> RpcResult<PageProofResponse> {
        let index = PageIndex::new(page_index);
        let anchor = block_hash.unwrap_or_default();
        let (page_root, proof) = self
            .manager
            .prove_page(anchor, address, index)
            .map_err(internal_err)?;
        let verified = proof.verify(page_root, address, index);

        Ok(PageProofResponse {
            address,
            page_index,
            page_root,
            page: proof.page.as_ref().map(page_words),
            path_nodes: proof.path_nodes.iter().map(proof_node).collect(),
            verified,
        })
    }
}

fn page_words(page: &Page) -> Vec<PageWord> {
    page.words()
        .iter()
        .map(|(&offset, &value)| PageWord { offset, value })
        .collect()
}

fn proof_node(node: &PageTreeNode) -> PageProofNode {
    match node {
        PageTreeNode::Branch { left, right } => PageProofNode::Branch {
            left: *left,
            right: *right,
        },
        PageTreeNode::Leaf { index, page_hash } => PageProofNode::Leaf {
            page_index: index.into_inner(),
            page_hash: *page_hash,
        },
    }
}

fn internal_err(err: impl ToString) -> ErrorObject<'static> {
    ErrorObject::owned(-32000, err.to_string(), None::<()>)
}
