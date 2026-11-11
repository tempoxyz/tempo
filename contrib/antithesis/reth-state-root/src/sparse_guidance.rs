//! JSON exploration guidance from the instrumented sparse-trie dependency.
//!
//! The Docker-only hook passes primitive values across this boundary, so the pinned
//! dependency needs no additional Cargo dependencies or changes to the production build.

use antithesis_sdk::serde_json::json;

/// Receives one dirty branch at sparse-trie RLP encoding time.
///
/// `revealed_mask` includes arena-backed children, and `leaf_mask` includes the revealed
/// children whose node (or lower-subtrie root) is a leaf. All masks use nibble positions.
#[unsafe(no_mangle)]
pub extern "C" fn antithesis_sparse_branch_shape(
    branch_path_len: usize,
    is_root: bool,
    state_mask: u16,
    revealed_mask: u16,
    leaf_mask: u16,
) {
    antithesis_sdk::guidance_helper!(
        GuidanceType::Json,
        "Sparse trie branch shape",
        false,
        json!({
            "branch_path_len": branch_path_len,
            "is_root": is_root,
            "state_mask": state_mask,
            "revealed_mask": revealed_mask,
            "leaf_mask": leaf_mask,
        })
    );
}
