use reth_network_peers::{NodeRecord, parse_nodes};

pub(crate) static ANDANTINO_BOOTNODES: [&str; 4] = [
    "enode://386269ddd50fd95143ad8f33f60ff67c7bd17da1adb46aed19eba5c6ae5326316643595e3aa99784f41b7d861fedde78594b1f764e56a4659917b916c1c3e321@148.113.193.123:30004",
    "enode://11103c936d2c21be1a2da3ca81f4daa3b5ad508e1a04e63198eaebf7b0783b2f805b2ea3997e4745e51881a0f6a49e0d8d2c3c85088c3a4a8a8f3ae0a086cc7d@148.113.225.199:30006",
    "enode://b189a89051ac5c11010d21cac7fabe0c2a3723721f38625631bdd120e88d15a0a748760bc1e4d4a8cd808edf502d4ec6acf677e49592f9ab7d193d094049963b@148.113.193.121:30008",
    "enode://022e06bfe3763851901baa2aae1cf94e276e4faa889d700422db3a88d075072d15868caa103d077ddd1d96f6fca266b1ded8dc9a41e2a612dcd77edc6dd5bae8@40.160.32.193:30010",
];

pub(crate) fn andantino_nodes() -> Vec<NodeRecord> {
    parse_nodes(ANDANTINO_BOOTNODES)
}
