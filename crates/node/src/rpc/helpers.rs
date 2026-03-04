use reth_node_core::rpc::result::internal_rpc_err;

/// Resolves pagination limit, default 10, max 100.
pub fn resolve_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(10).min(100)
}

/// Parses a cursor string of the form "block_number:index".
pub fn parse_cursor(cursor: &str) -> Result<(u64, usize), jsonrpsee::types::ErrorObject<'static>> {
    let parts: Vec<&str> = cursor.split(':').collect();
    if parts.len() != 2 {
        return Err(internal_rpc_err(
            "invalid cursor format, expected 'block_number:index'",
        ));
    }
    let block_number = parts[0]
        .parse::<u64>()
        .map_err(|_| internal_rpc_err("invalid cursor: bad block_number"))?;
    let index = parts[1]
        .parse::<usize>()
        .map_err(|_| internal_rpc_err("invalid cursor: bad index"))?;
    Ok((block_number, index))
}
