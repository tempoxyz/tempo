use poseidon::poseidon2::Poseidon2;

// Domain tags (ASCII packed into a field) keep leaves, nodes and commitments disjoint.
global DOMAIN_LEAF: Field = 0x74656d706f3a6d656d6265723a7631; // "tempo:member:v1"
global DOMAIN_NODE: Field = 0x74656d706f3a6e6f64653a7631; // "tempo:node:v1"
global DOMAIN_POLICY: Field = 0x74656d706f3a706f6c6963793a7631; // "tempo:policy:v1"

/// 32 big-endian bytes -> (hi, lo) 128-bit field limbs. Never reduces mod p.
pub fn bytes_to_limbs(b: [u8; 32]) -> (Field, Field) {
    let mut hi: Field = 0;
    let mut lo: Field = 0;
    for i in 0..16 {
        hi = hi * 256 + b[i] as Field;
        lo = lo * 256 + b[16 + i] as Field;
    }
    (hi, lo)
}

pub fn digest_bytes(hi: u128, lo: u128) -> [u8; 32] {
    let h: [u8; 16] = (hi as Field).to_be_bytes();
    let l: [u8; 16] = (lo as Field).to_be_bytes();
    let mut out = [0; 32];
    for i in 0..16 {
        out[i] = h[i];
        out[16 + i] = l[i];
    }
    out
}

pub fn member_leaf(kind: u8, weight: u32, pk_x: [u8; 32], pk_y: [u8; 32], rp_id_hash: [u8; 32]) -> Field {
    let (xh, xl) = bytes_to_limbs(pk_x);
    let (yh, yl) = bytes_to_limbs(pk_y);
    let (rh, rl) = bytes_to_limbs(rp_id_hash);
    Poseidon2::hash([DOMAIN_LEAF, kind as Field, weight as Field, xh, xl, yh, yl, rh, rl], 9)
}

pub fn node(l: Field, r: Field) -> Field {
    Poseidon2::hash([DOMAIN_NODE, l, r], 3)
}

pub fn merkle_root<let D: u32>(leaf: Field, index: u32, path: [Field; D]) -> Field {
    let mut cur = leaf;
    for i in 0..D {
        let bit = (index >> i) & 1;
        cur = if bit == 1 { node(path[i], cur) } else { node(cur, path[i]) };
    }
    cur
}

pub fn policy_commitment(roster_root: Field, threshold: u32, salt: Field) -> Field {
    Poseidon2::hash([DOMAIN_POLICY, roster_root, threshold as Field, salt], 4)
}

// Unused roster slots hold this leaf so the tree shape never leaks the roster size.
pub global EMPTY_LEAF: Field = 0;

/// Test/tooling helper: full tree over a fixed-size leaf array.
pub fn build_tree<let N: u32, let D: u32>(leaves: [Field; N]) -> (Field, [[Field; D]; N]) {
    let mut paths = [[0; D]; N];
    let mut level = leaves;
    let mut width = N;
    for d in 0..D {
        for j in 0..N {
            let pos = j >> d;
            paths[j][d] = level[pos ^ 1];
        }
        let mut next = level;
        for k in 0..N {
            if k < width / 2 {
                next[k] = node(level[2 * k], level[2 * k + 1]);
            }
        }
        level = next;
        width = width / 2;
    }
    (level[0], paths)
}
