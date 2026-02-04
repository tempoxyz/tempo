use alloy_primitives::{Address, B256, Bytes, U256, hex};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use tempo_chainspec::hardfork::ALL_TEMPO_HARDFORKS;
use tempo_primitives::TempoTxType;

/// A test vector for precompile differential testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVector {
    /// Optional template to extend
    #[serde(default)]
    pub extends: Option<String>,
    /// Unique name for this vector (derived from file path, not in JSON)
    #[serde(skip)]
    pub name: String,
    /// Description of what this vector tests
    #[serde(default)]
    pub description: String,
    /// Initial state before execution
    #[serde(default)]
    pub prestate: Prestate,
    /// Block context for execution
    #[serde(default)]
    pub block: BlockContext,
    /// Transactions to execute
    #[serde(default)]
    pub transactions: Vec<Transaction>,
    /// What to check after execution
    #[serde(default)]
    pub checks: Checks,
    /// If true, this vector will be compared against the baseline (main branch) to detect
    /// regressions. If false, the vector only validates it passes on the current branch.
    /// Required for all vectors (but optional in templates that are extended).
    #[serde(default)]
    pub check_regression: Option<bool>,
}

impl TestVector {
    /// Returns all hardforks to run this vector on.
    pub fn target_hardforks(&self) -> Vec<&'static str> {
        ALL_TEMPO_HARDFORKS.iter().map(|h| h.name()).collect()
    }
}

/// Initial state (accounts, storage, code)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Prestate {
    #[serde(default)]
    pub accounts: BTreeMap<Address, AccountState>,
    #[serde(default)]
    pub storage: BTreeMap<Address, BTreeMap<U256, U256>>,
    #[serde(default)]
    pub code: BTreeMap<Address, Bytes>,
    /// Precompile state to seed
    #[serde(default)]
    pub precompiles: Vec<PrecompileState>,
}

/// Account state (nonce only - balances are set via precompiles)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountState {
    #[serde(default)]
    pub nonce: u64,
}

/// Block context for execution
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockContext {
    #[serde(default)]
    pub number: u64,
    #[serde(default)]
    pub timestamp: u64,
    #[serde(default)]
    pub timestamp_millis_part: u16,
    #[serde(default, with = "u256_dec_or_hex")]
    pub basefee: U256,
    #[serde(default)]
    pub gas_limit: u64,
    #[serde(default)]
    pub coinbase: Address,
    #[serde(default)]
    pub prevrandao: B256,
}

/// Transaction to execute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction type
    #[serde(default = "default_tx_type", with = "tx_type_serde")]
    pub tx_type: TempoTxType,
    /// Sender address
    pub from: Address,
    /// Recipient address (None for contract creation)
    /// For "tempo" tx type, this is ignored in favor of `calls`
    #[serde(default)]
    pub to: Option<Address>,
    /// Value to transfer (for non-tempo txs)
    #[serde(default, with = "u256_dec_or_hex")]
    pub value: U256,
    /// Input data (for non-tempo txs)
    #[serde(default)]
    pub input: Bytes,
    /// Gas limit
    pub gas_limit: u64,
    /// Max fee per gas (EIP-1559 style)
    #[serde(default, with = "u256_dec_or_hex")]
    pub max_fee_per_gas: U256,
    /// Max priority fee per gas (EIP-1559 style)
    #[serde(default, with = "u256_dec_or_hex")]
    pub max_priority_fee_per_gas: U256,
    /// Nonce (if None, defaults to 0)
    #[serde(default)]
    pub nonce: Option<u64>,

    // === Tempo transaction (AA) specific fields ===
    /// Calls for Tempo transactions (multi-call support)
    /// If non-empty, this is treated as a Tempo AA transaction
    #[serde(default)]
    pub calls: Vec<Call>,
    /// Nonce key for 2D nonce system (Tempo AA)
    #[serde(default, with = "u256_dec_or_hex")]
    pub nonce_key: U256,
    /// Fee token address (Tempo AA)
    #[serde(default)]
    pub fee_token: Option<Address>,
    /// Valid before timestamp (Tempo AA)
    #[serde(default)]
    pub valid_before: Option<u64>,
    /// Valid after timestamp (Tempo AA)
    #[serde(default)]
    pub valid_after: Option<u64>,

    /// Expected outcome for this transaction (same across all hardforks)
    /// Use this OR `outcomes`, not both.
    #[serde(default)]
    pub outcome: Option<TxOutcome>,

    /// Expected outcomes per hardfork (when behavior differs across hardforks)
    /// Use this OR `outcome`, not both.
    #[serde(default)]
    pub outcomes: Vec<HardforkOutcome>,
}

/// Expected outcome for specific hardforks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardforkOutcome {
    /// Which hardforks this outcome applies to
    pub hardforks: Vec<String>,
    /// The expected outcome for these hardforks
    pub outcome: TxOutcome,
}

impl Transaction {
    /// Get the expected outcome for a specific hardfork.
    /// Returns None if no outcome is defined for this hardfork.
    pub fn outcome_for_hardfork(&self, hardfork: &str) -> Option<&TxOutcome> {
        // If single outcome is defined, use it for all hardforks
        if let Some(ref outcome) = self.outcome {
            return Some(outcome);
        }

        // Otherwise, look up in hardfork-specific outcomes
        self.outcomes
            .iter()
            .find(|ho| ho.hardforks.iter().any(|h| h == hardfork))
            .map(|ho| &ho.outcome)
    }
}

/// Expected outcome for a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutcome {
    /// Expected success (true) or revert (false)
    pub success: bool,
    /// Custom error - either a signature (e.g., "TokenAlreadyExists(address)")
    /// or a raw 4-byte selector starting with "0x" (e.g., "0x12345678")
    /// Only valid when success is false
    #[serde(default)]
    pub error: Option<String>,
    /// For Error(string) reverts - assert decoded message contains this
    /// Only valid when success is false
    #[serde(default)]
    pub revert_contains: Option<String>,
}

impl TxOutcome {
    /// Validate the outcome configuration.
    /// - When success=true, error and revert_contains must be None
    /// - When success=false, at least one of error or revert_contains must be Some
    pub fn validate(&self) -> Result<(), String> {
        if self.success {
            if self.error.is_some() {
                return Err("outcome has success=true but 'error' is set".to_string());
            }
            if self.revert_contains.is_some() {
                return Err("outcome has success=true but 'revert_contains' is set".to_string());
            }
        } else if self.error.is_none() && self.revert_contains.is_none() {
            return Err(
                "outcome has success=false but neither 'error' nor 'revert_contains' is set"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Compute the 4-byte selector for a custom error.
    /// If error starts with "0x" and is 10 chars, treat as raw selector.
    /// Otherwise, derive selector from signature via keccak256.
    pub fn error_selector(&self) -> Option<[u8; 4]> {
        self.error.as_ref().and_then(|err| {
            // Check if it's a raw selector (0x + 8 hex chars = 10 chars)
            if err.starts_with("0x") && err.len() == 10 {
                let hex_str = &err[2..];
                if let Ok(bytes) = hex::decode(hex_str)
                    && bytes.len() == 4 {
                        return Some([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    }
                return None;
            }
            // Treat as signature, compute selector
            let hash = alloy_primitives::keccak256(err.as_bytes());
            Some([hash[0], hash[1], hash[2], hash[3]])
        })
    }
}

/// A call within a Tempo transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Call {
    /// Call target (None for contract creation)
    #[serde(default)]
    pub to: Option<Address>,
    /// Value to transfer
    #[serde(default, with = "u256_dec_or_hex")]
    pub value: U256,
    /// Input data
    #[serde(default)]
    pub input: Bytes,
}

/// Precompile state configuration for prestate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecompileState {
    /// Precompile contract name (e.g., "TIP20Token")
    pub name: String,
    /// Contract address
    pub address: Address,
    /// Field values to seed
    pub fields: serde_json::Value,
}

/// Precompile fields to check after execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecompileCheck {
    /// Precompile contract name (e.g., "TIP20Token")
    pub name: String,
    /// Contract address
    pub address: Address,
    /// Fields to read
    pub fields: Vec<FieldSpec>,
}

/// Specification for a field to check
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldSpec {
    /// Simple field: "total_supply"
    Simple(String),
    /// Mapping field with keys
    WithKeys { field: String, keys: Vec<FieldKey> },
}

/// Key specification for mapping fields
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldKey {
    /// Single key for simple mappings: "0x1111..."
    Single(String),
    /// Tuple of keys for nested mappings: ["0x1111...", "0x2222..."]
    Tuple(Vec<String>),
}

/// What to check after execution
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Checks {
    /// Precompile fields to check
    #[serde(default)]
    pub precompiles: Vec<PrecompileCheck>,
    /// Storage slots to read per address (raw, escape hatch)
    #[serde(default)]
    pub storage: BTreeMap<Address, Vec<U256>>,
    /// Addresses to read nonces from
    #[serde(default)]
    pub nonces: Vec<Address>,
}

fn default_tx_type() -> TempoTxType {
    TempoTxType::Eip1559
}

/// Custom serde module for TempoTxType that accepts both string and numeric formats
mod tx_type_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use tempo_primitives::TempoTxType;

    pub(super) fn serialize<S>(value: &TempoTxType, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as lowercase string for human readability
        let s = match value {
            TempoTxType::Legacy => "legacy",
            TempoTxType::Eip2930 => "eip2930",
            TempoTxType::Eip1559 => "eip1559",
            TempoTxType::Eip7702 => "eip7702",
            TempoTxType::AA => "tempo",
        };
        serializer.serialize_str(s)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<TempoTxType, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        // Accept both string and numeric formats
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum TxTypeValue {
            String(String),
            Number(u8),
        }

        match TxTypeValue::deserialize(deserializer)? {
            TxTypeValue::String(s) => match s.to_lowercase().as_str() {
                "legacy" | "0" => Ok(TempoTxType::Legacy),
                "eip2930" | "1" => Ok(TempoTxType::Eip2930),
                "eip1559" | "2" => Ok(TempoTxType::Eip1559),
                "eip7702" | "4" => Ok(TempoTxType::Eip7702),
                "tempo" | "aa" | "118" | "0x76" => Ok(TempoTxType::AA),
                other => Err(D::Error::custom(format!(
                    "unknown transaction type: '{other}'. Expected: legacy, eip2930, eip1559, eip7702, tempo"
                ))),
            },
            TxTypeValue::Number(n) => match n {
                0 => Ok(TempoTxType::Legacy),
                1 => Ok(TempoTxType::Eip2930),
                2 => Ok(TempoTxType::Eip1559),
                4 => Ok(TempoTxType::Eip7702),
                118 => Ok(TempoTxType::AA),
                other => Err(D::Error::custom(format!(
                    "unknown transaction type id: {other}. Expected: 0, 1, 2, 4, or 118"
                ))),
            },
        }
    }
}

/// Helper module for U256 that accepts both decimal strings and hex
mod u256_dec_or_hex {
    use alloy_primitives::U256;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{value:#x}"))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.starts_with("0x") || s.starts_with("0X") {
            U256::from_str_radix(&s[2..], 16).map_err(serde::de::Error::custom)
        } else {
            U256::from_str_radix(&s, 10).map_err(serde::de::Error::custom)
        }
    }
}

impl TestVector {
    /// Load a vector from a JSON file
    pub fn from_file(path: impl AsRef<Path>) -> eyre::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let vector: Self = serde_json::from_str(&content)?;
        Ok(vector)
    }

    /// Load a vector from a JSON file, resolving any template inheritance.
    ///
    /// If the vector has an `extends` field, the template is loaded first
    /// and the vector's fields are merged on top.
    ///
    /// The `base_dir` is used to derive the vector name from the relative path.
    pub fn load_with_inheritance(
        path: impl AsRef<Path>,
        base_dir: impl AsRef<Path>,
    ) -> eyre::Result<Self> {
        let path = path.as_ref();
        let mut vector = Self::load_raw(path)?;

        // Derive name from path relative to base_dir
        // e.g., "tip20_factory/create_token.json" -> "tip20_factory::create_token"
        vector.name = Self::derive_name(path, base_dir.as_ref());

        // Validate that check_regression is set (required for all non-template vectors)
        if vector.check_regression.is_none() {
            return Err(eyre::eyre!(
                "check_regression is required for vector '{}' - set to true (regression test) or false (new feature)",
                vector.name
            ));
        }

        // Validate all transaction outcomes
        for (i, tx) in vector.transactions.iter().enumerate() {
            // Must have either outcome or outcomes, not both or neither
            if tx.outcome.is_some() && !tx.outcomes.is_empty() {
                return Err(eyre::eyre!(
                    "vector '{}' tx {}: cannot have both 'outcome' and 'outcomes'",
                    vector.name, i
                ));
            }
            if tx.outcome.is_none() && tx.outcomes.is_empty() {
                return Err(eyre::eyre!(
                    "vector '{}' tx {}: must have 'outcome' or 'outcomes'",
                    vector.name, i
                ));
            }

            // Validate single outcome
            if let Some(ref outcome) = tx.outcome
                && let Err(e) = outcome.validate() {
                    return Err(eyre::eyre!("vector '{}' tx {}: {}", vector.name, i, e));
                }

            // Validate hardfork-specific outcomes
            if !tx.outcomes.is_empty() {
                // Collect all hardforks covered by outcomes
                let mut covered: HashSet<&str> = HashSet::new();
                for ho in &tx.outcomes {
                    if let Err(e) = ho.outcome.validate() {
                        return Err(eyre::eyre!(
                            "vector '{}' tx {} (hardforks {:?}): {}",
                            vector.name, i, ho.hardforks, e
                        ));
                    }
                    for hf in &ho.hardforks {
                        covered.insert(hf.as_str());
                    }
                }

                // Check all hardforks are covered
                let all_hardforks: Vec<&str> =
                    ALL_TEMPO_HARDFORKS.iter().map(|h| h.name()).collect();
                let missing: Vec<_> = all_hardforks
                    .iter()
                    .filter(|hf| !covered.contains(*hf))
                    .collect();
                if !missing.is_empty() {
                    return Err(eyre::eyre!(
                        "vector '{}' tx {}: 'outcomes' must cover all hardforks, missing: {:?}",
                        vector.name, i, missing
                    ));
                }
            }
        }

        Ok(vector)
    }

    /// Derive vector name from file path relative to base directory.
    /// e.g., "tip20_factory/create_token.json" -> "tip20_factory::create_token"
    fn derive_name(path: &Path, base_dir: &Path) -> String {
        let relative = path.strip_prefix(base_dir).unwrap_or(path);
        let without_ext = relative.with_extension("");
        without_ext
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("::")
    }

    /// Load a vector without validation (used for templates).
    fn load_raw(path: impl AsRef<Path>) -> eyre::Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        let mut vector: Self = serde_json::from_str(&content)?;

        if let Some(template_path) = &vector.extends {
            // Resolve relative path from the vector's directory
            let base_dir = path.parent().unwrap_or(Path::new("."));
            let template_full_path = base_dir.join(template_path);

            // Load template recursively (templates can extend other templates)
            let template = Self::load_raw(&template_full_path)?;

            // Merge: vector overrides template
            vector = merge_vectors(template, vector);
        }

        Ok(vector)
    }

    /// Load all vectors from a directory (recursively)
    pub fn from_directory(path: impl AsRef<Path>) -> eyre::Result<Vec<Self>> {
        let base_dir = path.as_ref();
        let mut vectors = Vec::new();
        Self::load_recursive(base_dir, base_dir, &mut vectors)?;
        vectors.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(vectors)
    }

    fn load_recursive(
        dir: &Path,
        base_dir: &Path,
        vectors: &mut Vec<Self>,
    ) -> eyre::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                Self::load_recursive(&path, base_dir, vectors)?;
            } else if path.extension().is_some_and(|e| e == "json") {
                // Skip setup files (starting with "setup") - they're only for inheritance
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !file_name.starts_with("setup") {
                    match Self::load_with_inheritance(&path, base_dir) {
                        Ok(vector) => vectors.push(vector),
                        Err(e) => {
                            eprintln!("Warning: Failed to load {path:?}: {e}");
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Merge two BTreeMaps: child values override parent values.
fn merge_btreemaps<K: Ord, V>(mut parent: BTreeMap<K, V>, child: BTreeMap<K, V>) -> BTreeMap<K, V> {
    for (k, v) in child {
        parent.insert(k, v);
    }
    parent
}

/// Merge nested storage maps: child values override parent values.
fn merge_storage(
    mut parent: BTreeMap<Address, BTreeMap<U256, U256>>,
    child: BTreeMap<Address, BTreeMap<U256, U256>>,
) -> BTreeMap<Address, BTreeMap<U256, U256>> {
    for (addr, child_slots) in child {
        let entry = parent.entry(addr).or_default();
        for (slot, value) in child_slots {
            entry.insert(slot, value);
        }
    }
    parent
}

/// Merge two vectors: child overrides parent.
/// - Simple fields (name, description, hardfork): child wins if set
/// - prestate.accounts: merge maps (child wins on conflict)
/// - prestate.storage: merge maps (child wins on conflict)
/// - prestate.code: merge maps (child wins on conflict)
/// - prestate.precompiles: concatenate (child's come after parent's)
/// - block: child wins entirely if any field is set
/// - transactions: concatenate (parent's first, then child's)
/// - checks: merge (child extends parent)
fn merge_vectors(parent: TestVector, child: TestVector) -> TestVector {
    // Merge prestate
    let prestate = Prestate {
        accounts: merge_btreemaps(parent.prestate.accounts, child.prestate.accounts),
        storage: merge_storage(parent.prestate.storage, child.prestate.storage),
        code: merge_btreemaps(parent.prestate.code, child.prestate.code),
        precompiles: {
            let mut precompiles = parent.prestate.precompiles;
            precompiles.extend(child.prestate.precompiles);
            precompiles
        },
    };

    // Merge checks
    let checks = Checks {
        precompiles: {
            let mut precompiles = parent.checks.precompiles;
            precompiles.extend(child.checks.precompiles);
            precompiles
        },
        storage: merge_btreemaps(parent.checks.storage, child.checks.storage),
        nonces: {
            // Concatenate and deduplicate
            let mut nonces = parent.checks.nonces;
            for addr in child.checks.nonces {
                if !nonces.contains(&addr) {
                    nonces.push(addr);
                }
            }
            nonces
        },
    };

    // Merge block context: if child has defaults, use parent
    let block =
        if child.block.gas_limit == 0 && child.block.number == 0 && child.block.timestamp == 0 {
            parent.block
        } else {
            BlockContext {
                number: if child.block.number != 0 {
                    child.block.number
                } else {
                    parent.block.number
                },
                timestamp: if child.block.timestamp != 0 {
                    child.block.timestamp
                } else {
                    parent.block.timestamp
                },
                timestamp_millis_part: if child.block.timestamp_millis_part != 0 {
                    child.block.timestamp_millis_part
                } else {
                    parent.block.timestamp_millis_part
                },
                basefee: if child.block.basefee != U256::ZERO {
                    child.block.basefee
                } else {
                    parent.block.basefee
                },
                gas_limit: if child.block.gas_limit != 0 {
                    child.block.gas_limit
                } else {
                    parent.block.gas_limit
                },
                coinbase: if child.block.coinbase != Address::ZERO {
                    child.block.coinbase
                } else {
                    parent.block.coinbase
                },
                prevrandao: if child.block.prevrandao != B256::ZERO {
                    child.block.prevrandao
                } else {
                    parent.block.prevrandao
                },
            }
        };

    TestVector {
        extends: None, // Clear extends after merging
        name: child.name,
        description: if child.description.is_empty() {
            parent.description
        } else {
            child.description
        },
        prestate,
        block,
        transactions: {
            let mut transactions = parent.transactions;
            transactions.extend(child.transactions);
            transactions
        },
        checks,
        check_regression: child.check_regression, // Must be set by child, not inherited
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_directory_empty() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let vectors_dir = manifest_dir.join("vectors");

        // Empty directory should return empty vec, not error
        let vectors = TestVector::from_directory(&vectors_dir).expect("Failed to load vectors");
        // Vectors should be sorted by name
        for i in 1..vectors.len() {
            assert!(vectors[i - 1].name <= vectors[i].name);
        }
    }

    #[test]
    fn test_u256_decimal_parsing() {
        let json = r#"{
            "name": "test",
            "hardfork": "T0",
            "prestate": {
                "accounts": {
                    "0x1111111111111111111111111111111111111111": {
                        "nonce": 5
                    }
                }
            },
            "block": {
                "number": 1,
                "timestamp": 1,
                "basefee": "1000000000",
                "gas_limit": 30000000
            },
            "transactions": [],
            "checks": {}
        }"#;

        let vector: TestVector = serde_json::from_str(json).expect("Failed to parse");
        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let account = vector.prestate.accounts.get(&addr).unwrap();
        assert_eq!(account.nonce, 5);
        // basefee parsed as decimal
        assert_eq!(vector.block.basefee, U256::from(1000000000u64));
    }

    #[test]
    fn test_u256_hex_parsing() {
        let json = r#"{
            "name": "test",
            "hardfork": "T0",
            "prestate": {
                "accounts": {
                    "0x1111111111111111111111111111111111111111": {
                        "nonce": 0
                    }
                }
            },
            "block": {
                "number": 1,
                "timestamp": 1,
                "basefee": "0x3b9aca00",
                "gas_limit": 30000000
            },
            "transactions": [],
            "checks": {}
        }"#;

        let vector: TestVector = serde_json::from_str(json).expect("Failed to parse");
        // basefee parsed as hex
        assert_eq!(vector.block.basefee, U256::from(1000000000u64));
    }

    #[test]
    fn test_tx_type_string_parsing() {
        use tempo_primitives::TempoTxType;

        // Test lowercase string format
        let json = r#"{
            "name": "test",
            "hardfork": "T0",
            "prestate": {},
            "block": { "number": 1, "timestamp": 1, "gas_limit": 30000000 },
            "transactions": [
                { "tx_type": "legacy", "from": "0x1111111111111111111111111111111111111111", "gas_limit": 21000, "outcome": { "success": true } },
                { "tx_type": "eip1559", "from": "0x1111111111111111111111111111111111111111", "gas_limit": 21000, "outcome": { "success": true } },
                { "tx_type": "tempo", "from": "0x1111111111111111111111111111111111111111", "gas_limit": 21000, "outcome": { "success": true } },
                { "tx_type": "aa", "from": "0x1111111111111111111111111111111111111111", "gas_limit": 21000, "outcome": { "success": true } }
            ],
            "checks": {}
        }"#;

        let vector: TestVector = serde_json::from_str(json).expect("Failed to parse");
        assert_eq!(vector.transactions[0].tx_type, TempoTxType::Legacy);
        assert_eq!(vector.transactions[1].tx_type, TempoTxType::Eip1559);
        assert_eq!(vector.transactions[2].tx_type, TempoTxType::AA);
        assert_eq!(vector.transactions[3].tx_type, TempoTxType::AA); // "aa" alias
    }

    #[test]
    fn test_tx_type_numeric_parsing() {
        use tempo_primitives::TempoTxType;

        // Test numeric format
        let json = r#"{
            "name": "test",
            "hardfork": "T0",
            "prestate": {},
            "block": { "number": 1, "timestamp": 1, "gas_limit": 30000000 },
            "transactions": [
                { "tx_type": 0, "from": "0x1111111111111111111111111111111111111111", "gas_limit": 21000, "outcome": { "success": true } },
                { "tx_type": 2, "from": "0x1111111111111111111111111111111111111111", "gas_limit": 21000, "outcome": { "success": true } },
                { "tx_type": 118, "from": "0x1111111111111111111111111111111111111111", "gas_limit": 21000, "outcome": { "success": true } }
            ],
            "checks": {}
        }"#;

        let vector: TestVector = serde_json::from_str(json).expect("Failed to parse");
        assert_eq!(vector.transactions[0].tx_type, TempoTxType::Legacy);
        assert_eq!(vector.transactions[1].tx_type, TempoTxType::Eip1559);
        assert_eq!(vector.transactions[2].tx_type, TempoTxType::AA);
    }

    #[test]
    fn test_tx_type_default() {
        use tempo_primitives::TempoTxType;

        // Test that default is eip1559
        let json = r#"{
            "name": "test",
            "hardfork": "T0",
            "prestate": {},
            "block": { "number": 1, "timestamp": 1, "gas_limit": 30000000 },
            "transactions": [
                { "from": "0x1111111111111111111111111111111111111111", "gas_limit": 21000, "outcome": { "success": true } }
            ],
            "checks": {}
        }"#;

        let vector: TestVector = serde_json::from_str(json).expect("Failed to parse");
        assert_eq!(vector.transactions[0].tx_type, TempoTxType::Eip1559);
    }

    #[test]
    fn test_tx_type_serialization() {
        use tempo_primitives::TempoTxType;

        let tx = Transaction {
            tx_type: TempoTxType::AA,
            from: "0x1111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            to: None,
            value: U256::ZERO,
            input: Bytes::new(),
            gas_limit: 21000,
            max_fee_per_gas: U256::ZERO,
            max_priority_fee_per_gas: U256::ZERO,
            nonce: None,
            calls: vec![],
            nonce_key: U256::ZERO,
            fee_token: None,
            valid_before: None,
            valid_after: None,
            outcome: Some(TxOutcome {
                success: true,
                error: None,
                revert_contains: None,
            }),
            outcomes: vec![],
        };

        let json = serde_json::to_string(&tx).expect("Failed to serialize");
        // Should serialize as "tempo", not numeric
        assert!(json.contains(r#""tx_type":"tempo""#));
    }

    #[test]
    fn test_merge_btreemaps() {
        let mut parent = BTreeMap::new();
        parent.insert("a".to_string(), 1);
        parent.insert("b".to_string(), 2);

        let mut child = BTreeMap::new();
        child.insert("b".to_string(), 3); // Override
        child.insert("c".to_string(), 4); // New

        let merged = super::merge_btreemaps(parent, child);
        assert_eq!(merged.get("a"), Some(&1)); // Parent preserved
        assert_eq!(merged.get("b"), Some(&3)); // Child overrides
        assert_eq!(merged.get("c"), Some(&4)); // Child added
    }

    #[test]
    fn test_merge_vectors_accounts() {
        let addr1: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let addr2: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();

        let mut parent_accounts = BTreeMap::new();
        parent_accounts.insert(addr1, AccountState { nonce: 5 });

        let mut child_accounts = BTreeMap::new();
        child_accounts.insert(addr2, AccountState { nonce: 10 });

        let parent = TestVector {
            extends: None,
            name: "parent".to_string(),
            description: "Parent description".to_string(),
            
            prestate: Prestate {
                accounts: parent_accounts,
                ..Default::default()
            },
            block: BlockContext {
                number: 1,
                timestamp: 1,
                timestamp_millis_part: 0,
                basefee: U256::ZERO,
                gas_limit: 30000000,
                coinbase: Address::ZERO,
                prevrandao: B256::ZERO,
            },
            transactions: vec![],
            checks: Checks::default(),
            check_regression: Some(false),
        };

        let child = TestVector {
            extends: Some("parent.json".to_string()),
            name: "child".to_string(),
            description: "".to_string(), // Empty, should inherit
            
            prestate: Prestate {
                accounts: child_accounts,
                ..Default::default()
            },
            block: BlockContext {
                number: 2,
                timestamp: 2,
                timestamp_millis_part: 0,
                basefee: U256::ZERO,
                gas_limit: 30000000,
                coinbase: Address::ZERO,
                prevrandao: B256::ZERO,
            },
            transactions: vec![],
            checks: Checks::default(),
            check_regression: Some(false),
        };

        let merged = super::merge_vectors(parent, child);

        assert_eq!(merged.name, "child");
        assert_eq!(merged.description, "Parent description"); // Inherited
        assert!(merged.extends.is_none()); // Cleared after merge
        assert_eq!(merged.prestate.accounts.len(), 2); // Both accounts merged
        assert_eq!(merged.prestate.accounts.get(&addr1).unwrap().nonce, 5);
        assert_eq!(merged.prestate.accounts.get(&addr2).unwrap().nonce, 10);
    }

    #[test]
    fn test_merge_vectors_precompiles_concatenation() {
        let parent = TestVector {
            extends: None,
            name: "parent".to_string(),
            description: "".to_string(),
            
            prestate: Prestate {
                precompiles: vec![PrecompileState {
                    name: "Token1".to_string(),
                    address: "0x1111111111111111111111111111111111111111"
                        .parse()
                        .unwrap(),
                    fields: serde_json::json!({}),
                }],
                ..Default::default()
            },
            block: BlockContext {
                number: 1,
                timestamp: 1,
                timestamp_millis_part: 0,
                basefee: U256::ZERO,
                gas_limit: 30000000,
                coinbase: Address::ZERO,
                prevrandao: B256::ZERO,
            },
            transactions: vec![],
            checks: Checks::default(),
            check_regression: Some(false),
        };

        let child = TestVector {
            extends: Some("parent.json".to_string()),
            name: "child".to_string(),
            description: "".to_string(),
            
            prestate: Prestate {
                precompiles: vec![PrecompileState {
                    name: "Token2".to_string(),
                    address: "0x2222222222222222222222222222222222222222"
                        .parse()
                        .unwrap(),
                    fields: serde_json::json!({}),
                }],
                ..Default::default()
            },
            block: BlockContext {
                number: 1,
                timestamp: 1,
                timestamp_millis_part: 0,
                basefee: U256::ZERO,
                gas_limit: 30000000,
                coinbase: Address::ZERO,
                prevrandao: B256::ZERO,
            },
            transactions: vec![],
            checks: Checks::default(),
            check_regression: Some(false),
        };

        let merged = super::merge_vectors(parent, child);

        // Precompiles should be concatenated: parent first, then child
        assert_eq!(merged.prestate.precompiles.len(), 2);
        assert_eq!(merged.prestate.precompiles[0].name, "Token1");
        assert_eq!(merged.prestate.precompiles[1].name, "Token2");
    }

    #[test]
    fn test_merge_vectors_nonces_dedup() {
        let addr1: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let addr2: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();

        let parent = TestVector {
            extends: None,
            name: "parent".to_string(),
            description: "".to_string(),
            
            prestate: Prestate::default(),
            block: BlockContext {
                number: 1,
                timestamp: 1,
                timestamp_millis_part: 0,
                basefee: U256::ZERO,
                gas_limit: 30000000,
                coinbase: Address::ZERO,
                prevrandao: B256::ZERO,
            },
            transactions: vec![],
            checks: Checks {
                nonces: vec![addr1, addr2],
                ..Default::default()
            },
            check_regression: Some(false),
        };

        let child = TestVector {
            extends: Some("parent.json".to_string()),
            name: "child".to_string(),
            description: "".to_string(),
            
            prestate: Prestate::default(),
            block: BlockContext {
                number: 1,
                timestamp: 1,
                timestamp_millis_part: 0,
                basefee: U256::ZERO,
                gas_limit: 30000000,
                coinbase: Address::ZERO,
                prevrandao: B256::ZERO,
            },
            transactions: vec![],
            checks: Checks {
                nonces: vec![addr1], // Duplicate
                ..Default::default()
            },
            check_regression: Some(false),
        };

        let merged = super::merge_vectors(parent, child);

        // Should deduplicate: addr1, addr2 (no duplicate addr1)
        assert_eq!(merged.checks.nonces.len(), 2);
        assert!(merged.checks.nonces.contains(&addr1));
        assert!(merged.checks.nonces.contains(&addr2));
    }

    #[test]
    fn test_merge_storage_nested() {
        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let slot1 = U256::from(1);
        let slot2 = U256::from(2);

        let mut parent_storage = BTreeMap::new();
        let mut parent_slots = BTreeMap::new();
        parent_slots.insert(slot1, U256::from(100));
        parent_storage.insert(addr, parent_slots);

        let mut child_storage = BTreeMap::new();
        let mut child_slots = BTreeMap::new();
        child_slots.insert(slot1, U256::from(200)); // Override
        child_slots.insert(slot2, U256::from(300)); // New
        child_storage.insert(addr, child_slots);

        let merged = super::merge_storage(parent_storage, child_storage);

        let slots = merged.get(&addr).unwrap();
        assert_eq!(slots.get(&slot1), Some(&U256::from(200))); // Child overrides
        assert_eq!(slots.get(&slot2), Some(&U256::from(300))); // Child added
    }

    #[test]
    fn test_merge_vectors_transactions_concatenate() {
        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();

        let parent_tx = Transaction {
            tx_type: tempo_primitives::TempoTxType::Eip1559,
            from: addr,
            to: None,
            value: U256::from(100),
            input: Bytes::new(),
            gas_limit: 21000,
            max_fee_per_gas: U256::ZERO,
            max_priority_fee_per_gas: U256::ZERO,
            nonce: Some(0),
            calls: vec![],
            nonce_key: U256::ZERO,
            fee_token: None,
            valid_before: None,
            valid_after: None,
            outcome: Some(TxOutcome {
                success: true,
                error: None,
                revert_contains: None,
            }),
            outcomes: vec![],
        };

        let child_tx = Transaction {
            tx_type: tempo_primitives::TempoTxType::Eip1559,
            from: addr,
            to: None,
            value: U256::from(200),
            input: Bytes::new(),
            gas_limit: 21000,
            max_fee_per_gas: U256::ZERO,
            max_priority_fee_per_gas: U256::ZERO,
            nonce: Some(1),
            calls: vec![],
            nonce_key: U256::ZERO,
            fee_token: None,
            valid_before: None,
            valid_after: None,
            outcome: Some(TxOutcome {
                success: true,
                error: None,
                revert_contains: None,
            }),
            outcomes: vec![],
        };

        let parent = TestVector {
            extends: None,
            name: "parent".to_string(),
            description: "".to_string(),
            
            prestate: Prestate::default(),
            block: BlockContext {
                number: 1,
                timestamp: 1,
                timestamp_millis_part: 0,
                basefee: U256::ZERO,
                gas_limit: 30000000,
                coinbase: Address::ZERO,
                prevrandao: B256::ZERO,
            },
            transactions: vec![parent_tx],
            checks: Checks::default(),
            check_regression: Some(false),
        };

        let child = TestVector {
            extends: Some("parent.json".to_string()),
            name: "child".to_string(),
            description: "".to_string(),
            
            prestate: Prestate::default(),
            block: BlockContext {
                number: 1,
                timestamp: 1,
                timestamp_millis_part: 0,
                basefee: U256::ZERO,
                gas_limit: 30000000,
                coinbase: Address::ZERO,
                prevrandao: B256::ZERO,
            },
            transactions: vec![child_tx],
            checks: Checks::default(),
            check_regression: Some(false),
        };

        let merged = super::merge_vectors(parent, child);

        // Transactions should be concatenated: parent first, then child
        assert_eq!(merged.transactions.len(), 2);
        assert_eq!(merged.transactions[0].value, U256::from(100)); // Parent's tx
        assert_eq!(merged.transactions[1].value, U256::from(200)); // Child's tx
    }
}
