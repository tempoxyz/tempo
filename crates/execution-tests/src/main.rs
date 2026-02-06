use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use clap::{Parser, Subcommand};
use eyre::{Result, bail};
use tempo_execution_tests::{
    PostExecutionState, VectorDatabase, VectorExecutor, fingerprint::Fingerprint,
    validate_tx_outcomes, vector::TestVector,
};

/// Differential testing framework for the Tempo execution layer.
///
/// This tool executes test vectors against the EVM, generates fingerprints
/// of the results, and compares fingerprints across different implementations
/// or versions to detect behavioral changes.
///
/// # Examples
///
/// Run all vectors in a directory:
/// ```sh
/// tempo-execution-tests run --dir ./vectors
/// ```
///
/// Run a single vector and save fingerprints:
/// ```sh
/// tempo-execution-tests run --vector ./vectors/tip20_transfer.json --output fingerprints.json
/// ```
///
/// Compare two fingerprint files:
/// ```sh
/// tempo-execution-tests compare baseline.json current.json --strict
/// ```
///
/// List available test vectors:
/// ```sh
/// tempo-execution-tests list --dir ./vectors
/// ```
#[derive(Parser)]
#[command(name = "tempo-execution-tests")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute test vectors and output fingerprints.
    ///
    /// Runs the specified test vectors against the precompile implementations
    /// and generates fingerprints that can be used for differential testing.
    ///
    /// Defaults to ./vectors if neither --vector nor --dir is specified.
    #[command(visible_alias = "r")]
    Run {
        /// Path to a single vector JSON file.
        #[arg(short = 'f', long, value_name = "PATH")]
        vector: Option<PathBuf>,

        /// Path to a directory of vectors (scanned recursively).
        /// Defaults to ./vectors if neither --vector nor --dir is specified.
        #[arg(short, long, value_name = "PATH")]
        dir: Option<PathBuf>,

        /// Output file for fingerprints JSON.
        ///
        /// If not specified, output is written to stdout.
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,

        /// Verbosity: -v for failed JSON, -vv for all JSON
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbosity: u8,
    },

    /// Compare two fingerprint files.
    ///
    /// Compares a baseline fingerprint file against a current one and reports
    /// any differences found. Useful for detecting behavioral changes between
    /// implementations or versions.
    #[command(visible_alias = "c")]
    Compare {
        /// Path to baseline fingerprints JSON.
        #[arg(value_name = "BASELINE")]
        baseline: PathBuf,

        /// Path to current fingerprints JSON.
        #[arg(value_name = "CURRENT")]
        current: PathBuf,

        /// Fail on any difference (exit code 1).
        ///
        /// When set, the command will exit with code 1 if any differences
        /// are found between the baseline and current fingerprints.
        #[arg(long)]
        strict: bool,
    },

    /// List available test vectors.
    ///
    /// Scans the specified directory for test vector files and displays
    /// information about each one.
    #[command(visible_alias = "l")]
    List {
        /// Directory to scan for test vectors.
        #[arg(short, long, value_name = "PATH", default_value = "./vectors")]
        dir: PathBuf,
    },

    /// Run a single vector and output its fingerprint as JSON.
    ///
    /// This command is primarily used internally by the `diff` command to
    /// invoke the baseline binary for individual vectors.
    RunSingle {
        /// Path to the vector JSON file.
        #[arg(value_name = "PATH")]
        vector: PathBuf,
    },

    /// Compare current implementation against a baseline binary.
    ///
    /// Runs all vectors with `check_regression: true` on both the current binary
    /// and the baseline binary, then compares fingerprints to detect regressions.
    #[command(visible_alias = "d")]
    Diff {
        /// Path to the baseline tempo-execution-tests binary (built from main).
        #[arg(long, value_name = "PATH")]
        baseline_binary: PathBuf,

        /// Directory containing test vectors.
        #[arg(short, long, value_name = "PATH")]
        dir: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            vector,
            dir,
            output,
            verbosity,
        } => {
            run_command(vector, dir, output, verbosity)?;
        }
        Commands::Compare {
            baseline,
            current,
            strict,
        } => {
            compare_command(baseline, current, strict)?;
        }
        Commands::List { dir } => {
            list_command(dir)?;
        }
        Commands::RunSingle { vector } => {
            run_single_command(vector)?;
        }
        Commands::Diff {
            baseline_binary,
            dir,
        } => {
            diff_command(baseline_binary, dir)?;
        }
    }

    Ok(())
}

fn run_command(
    vector: Option<PathBuf>,
    dir: Option<PathBuf>,
    output: Option<PathBuf>,
    verbosity: u8,
) -> Result<()> {
    let dir = if vector.is_none() && dir.is_none() {
        Some(PathBuf::from("./vectors"))
    } else {
        dir
    };

    let mut vectors = Vec::new();

    if let Some(path) = vector {
        let base_dir = path.parent().unwrap_or(Path::new("."));
        vectors.push(TestVector::load_with_inheritance(&path, base_dir)?);
    }

    if let Some(path) = dir {
        vectors.extend(TestVector::from_directory(&path)?);
    }

    let mut passed: BTreeMap<String, Fingerprint> = BTreeMap::new();
    let mut failed: BTreeMap<String, Fingerprint> = BTreeMap::new();
    let mut errors: Vec<(String, eyre::Report)> = Vec::new();
    let executor = VectorExecutor::with_test_chainspec();

    for vector in &vectors {
        for hardfork in vector.target_hardforks() {
            let test_name = format!("{}::{}", hardfork, vector.name);
            match execute_vector(&executor, vector, hardfork) {
                Ok(result) => {
                    if result.validation_errors.is_empty() {
                        passed.insert(test_name, result.fingerprint);
                    } else {
                        failed.insert(test_name, result.fingerprint);
                    }
                }
                Err(e) => {
                    errors.push((test_name, e));
                }
            }
        }
    }

    // Output format based on verbosity:
    // 0 (default): list pass/fail
    // 1 (-v): list pass, then each failed test with JSON
    // 2+ (-vv): each test with JSON
    let mut result = String::new();

    match verbosity {
        0 => {
            for name in passed.keys() {
                result.push_str(&format!("✓ {name}\n"));
            }
            for name in failed.keys() {
                result.push_str(&format!("✗ {name}\n"));
            }
            for (name, err) in &errors {
                result.push_str(&format!("✗ {name}: {err}\n"));
            }
        }
        1 => {
            for name in passed.keys() {
                result.push_str(&format!("✓ {name}\n"));
            }
            for (name, fp) in &failed {
                result.push_str(&format!("\n✗ {name}\n"));
                result.push_str(&serde_json::to_string_pretty(&fp)?);
                result.push('\n');
            }
            for (name, err) in &errors {
                result.push_str(&format!("\n✗ {name}: {err}\n"));
            }
        }
        _ => {
            for (name, fp) in &passed {
                result.push_str(&format!("\n✓ {name}\n"));
                result.push_str(&serde_json::to_string_pretty(&fp)?);
                result.push('\n');
            }
            for (name, fp) in &failed {
                result.push_str(&format!("\n✗ {name}\n"));
                result.push_str(&serde_json::to_string_pretty(&fp)?);
                result.push('\n');
            }
            for (name, err) in &errors {
                result.push_str(&format!("\n✗ {name}: {err}\n"));
            }
        }
    }

    // Always append summary
    result.push_str(&format!(
        "\n{} passed, {} failed\n",
        passed.len(),
        failed.len() + errors.len()
    ));

    if let Some(path) = output {
        let mut file = std::fs::File::create(&path)?;
        file.write_all(result.as_bytes())?;
    } else {
        print!("{result}");
    }

    // Exit with code 1 if any tests failed or errored
    if !failed.is_empty() || !errors.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

/// Result of executing a vector - includes fingerprint and any validation errors
struct VectorResult {
    fingerprint: Fingerprint,
    validation_errors: Vec<String>,
}

fn execute_vector(
    executor: &VectorExecutor,
    vector: &TestVector,
    hardfork: &str,
) -> Result<VectorResult> {
    let mut db = VectorDatabase::from_prestate(&vector.prestate)?;
    let result = executor.execute(vector, &mut db)?;

    // Validate transaction outcomes
    let validation_errors =
        validate_tx_outcomes(&result.tx_results, &vector.transactions, hardfork);

    let test_name = format!("{}::{}", hardfork, vector.name);
    let post_state = PostExecutionState::capture(&db.db, &vector.checks)?;
    let fingerprint = Fingerprint::from_execution(
        &test_name,
        hardfork,
        vector.block.number,
        result.tx_results,
        post_state,
    );
    Ok(VectorResult {
        fingerprint,
        validation_errors,
    })
}

fn compare_command(baseline: PathBuf, current: PathBuf, strict: bool) -> Result<()> {
    let baseline_fingerprints: BTreeMap<String, Fingerprint> =
        serde_json::from_str(&std::fs::read_to_string(&baseline)?)?;
    let current_fingerprints: BTreeMap<String, Fingerprint> =
        serde_json::from_str(&std::fs::read_to_string(&current)?)?;

    let mut ok_count = 0;
    let mut changed_count = 0;
    let mut missing_count = 0;
    let mut new_count = 0;

    let total = baseline_fingerprints.len().max(current_fingerprints.len());
    println!("Comparing {total} vectors...\n");

    for (name, baseline_fp) in &baseline_fingerprints {
        if let Some(current_fp) = current_fingerprints.get(name) {
            let baseline_hash = baseline_fp.hash();
            let current_hash = current_fp.hash();
            if baseline_hash == current_hash {
                println!("  {name:<20} OK");
                ok_count += 1;
            } else {
                println!("  {name:<20} CHANGED");
                println!("    baseline: {baseline_hash:#x}");
                println!("    current:  {current_hash:#x}");
                changed_count += 1;
            }
        } else {
            println!("  {name:<20} MISSING");
            missing_count += 1;
        }
    }

    for name in current_fingerprints.keys() {
        if !baseline_fingerprints.contains_key(name) {
            println!("  {name:<20} NEW");
            new_count += 1;
        }
    }

    println!(
        "\nSummary: {ok_count} ok, {changed_count} changed, {missing_count} missing, {new_count} new"
    );

    if strict && (changed_count > 0 || missing_count > 0 || new_count > 0) {
        std::process::exit(1);
    }

    Ok(())
}

fn list_command(dir: PathBuf) -> Result<()> {
    if !dir.exists() {
        bail!("Directory does not exist: {:?}", dir);
    }

    let vectors = TestVector::from_directory(&dir)?;

    println!("Found {} test vectors in {:?}:\n", vectors.len(), dir);

    for vector in &vectors {
        if vector.description.is_empty() {
            println!("  {}", vector.name);
        } else {
            println!("  {}", vector.name);
            println!("    {}", vector.description);
        }
    }

    println!("\nTotal: {} vectors", vectors.len());

    Ok(())
}

fn run_single_command(vector_path: PathBuf) -> Result<()> {
    let base_dir = vector_path.parent().unwrap_or(Path::new("."));
    let vector = TestVector::load_with_inheritance(&vector_path, base_dir)?;
    let executor = VectorExecutor::with_test_chainspec();
    // For run-single, use the first target hardfork
    let hardfork = vector.target_hardforks().first().copied().unwrap_or("T1");
    let result = execute_vector(&executor, &vector, hardfork)?;
    let json = serde_json::to_string(&result.fingerprint)?;
    println!("{json}");
    Ok(())
}

fn diff_command(baseline_binary: PathBuf, dir: PathBuf) -> Result<()> {
    if !baseline_binary.exists() {
        bail!("Baseline binary does not exist: {:?}", baseline_binary);
    }
    if !dir.exists() {
        bail!("Directory does not exist: {:?}", dir);
    }

    let vectors = TestVector::from_directory(&dir)?;
    let executor = VectorExecutor::with_test_chainspec();

    let mut current_fingerprints: BTreeMap<String, Fingerprint> = BTreeMap::new();
    let mut vector_paths: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut execution_errors: Vec<(String, String)> = Vec::new();

    // Count total test runs (vectors × hardforks)
    let total_runs: usize = vectors.iter().map(|v| v.target_hardforks().len()).sum();
    eprintln!("Running {total_runs} test runs on current binary...");

    for vector in &vectors {
        let vector_path = find_vector_path(&dir, &vector.name)?;
        vector_paths.insert(vector.name.clone(), vector_path);

        for hardfork in vector.target_hardforks() {
            let test_name = format!("{}::{}", hardfork, vector.name);
            match execute_vector(&executor, vector, hardfork) {
                Ok(result) => {
                    current_fingerprints.insert(test_name, result.fingerprint);
                }
                Err(e) => {
                    execution_errors.push((test_name, e.to_string()));
                }
            }
        }
    }

    let baseline_vectors: Vec<_> = vectors
        .iter()
        .filter(|v| v.check_regression.unwrap_or(false))
        .collect();

    let baseline_runs: usize = baseline_vectors
        .iter()
        .map(|v| v.target_hardforks().len())
        .sum();
    eprintln!("Comparing {baseline_runs} test runs with check_regression=true against baseline...");

    let mut matched = 0;
    let mut new_passed = 0;
    let mut regressions: Vec<(String, String, String)> = Vec::new();

    for vector in &baseline_vectors {
        let vector_path = vector_paths.get(&vector.name).unwrap();

        for hardfork in vector.target_hardforks() {
            let test_name = format!("{}::{}", hardfork, vector.name);

            let current_fp = match current_fingerprints.get(&test_name) {
                Some(fp) => fp,
                None => {
                    continue;
                }
            };

            let baseline_output = Command::new(&baseline_binary)
                .arg("run-single")
                .arg(vector_path)
                .output();

            match baseline_output {
                Ok(output) => {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        match serde_json::from_str::<Fingerprint>(&stdout) {
                            Ok(baseline_fp) => {
                                let current_hash = current_fp.hash();
                                let baseline_hash = baseline_fp.hash();
                                if current_hash == baseline_hash {
                                    matched += 1;
                                } else {
                                    regressions.push((
                                        test_name.clone(),
                                        format!("{baseline_hash:#x}"),
                                        format!("{current_hash:#x}"),
                                    ));
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "  Warning: failed to parse baseline fingerprint for {test_name}: {e}"
                                );
                            }
                        }
                    } else {
                        new_passed += 1;
                    }
                }
                Err(e) => {
                    eprintln!("  Warning: failed to run baseline for {test_name}: {e}");
                }
            }
        }
    }

    println!("\n=== Diff Summary ===");
    println!("{matched} vectors matched baseline");
    println!("{new_passed} new vectors passed (not in baseline or baseline failed)");
    println!("{} regressions detected", regressions.len());

    if !regressions.is_empty() {
        println!("\nRegressions:");
        for (name, baseline_hash, current_hash) in &regressions {
            println!("  {name}");
            println!("    baseline: {baseline_hash}");
            println!("    current:  {current_hash}");
        }
    }

    if !execution_errors.is_empty() {
        println!("\nExecution errors on current binary:");
        for (name, err) in &execution_errors {
            println!("  {name}: {err}");
        }
    }

    if !regressions.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

fn find_vector_path(dir: &PathBuf, vector_name: &str) -> Result<PathBuf> {
    fn search_dir(dir: &PathBuf, vector_name: &str) -> Result<Option<PathBuf>> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if let Some(found) = search_dir(&path, vector_name)? {
                    return Ok(Some(found));
                }
            } else if path.extension().is_some_and(|ext| ext == "json")
                && let Ok(content) = std::fs::read_to_string(&path)
                && let Ok(v) = serde_json::from_str::<serde_json::Value>(&content)
                && v.get("name").and_then(|n| n.as_str()) == Some(vector_name)
            {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    search_dir(dir, vector_name)?
        .ok_or_else(|| eyre::eyre!("Could not find vector file for '{}'", vector_name))
}
