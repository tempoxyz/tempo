use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use clap::{Parser, Subcommand, ValueEnum};
use eyre::{Result, bail};
use precompile_tests::{
    PostExecutionState, VectorDatabase, VectorExecutor, fingerprint::Fingerprint,
    vector::TestVector,
};

/// Differential testing framework for Tempo precompiles.
///
/// This tool executes test vectors against precompiles, generates fingerprints
/// of the results, and compares fingerprints across different implementations
/// or versions to detect behavioral changes.
///
/// # Examples
///
/// Run all vectors in a directory:
/// ```sh
/// precompile-tests run --dir ./vectors
/// ```
///
/// Run a single vector and save fingerprints:
/// ```sh
/// precompile-tests run --vector ./vectors/tip20_transfer.json --output fingerprints.json
/// ```
///
/// Compare two fingerprint files:
/// ```sh
/// precompile-tests compare baseline.json current.json --strict
/// ```
///
/// List available test vectors:
/// ```sh
/// precompile-tests list --dir ./vectors
/// ```
#[derive(Parser)]
#[command(name = "precompile-tests")]
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
    /// At least one of --vector or --dir must be specified.
    #[command(visible_alias = "r")]
    Run {
        /// Path to a single vector JSON file.
        #[arg(short, long, value_name = "PATH")]
        vector: Option<PathBuf>,

        /// Path to a directory of vectors (scanned recursively).
        #[arg(short, long, value_name = "PATH")]
        dir: Option<PathBuf>,

        /// Output file for fingerprints JSON.
        ///
        /// If not specified, output is written to stdout.
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,

        /// Output format for the results.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
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
        /// Path to the baseline precompile-tests binary (built from main).
        #[arg(long, value_name = "PATH")]
        baseline_binary: PathBuf,

        /// Directory containing test vectors.
        #[arg(short, long, value_name = "PATH")]
        dir: PathBuf,
    },
}

/// Output format for fingerprint results.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Full JSON output with all fingerprint details.
    Json,
    /// Only output the fingerprint hashes.
    Hashes,
    /// Human-readable summary.
    Summary,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            vector,
            dir,
            output,
            format,
        } => {
            run_command(vector, dir, output, format)?;
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
    format: OutputFormat,
) -> Result<()> {
    if vector.is_none() && dir.is_none() {
        bail!("At least one of --vector or --dir must be provided");
    }

    let mut vectors = Vec::new();

    if let Some(path) = vector {
        vectors.push(TestVector::load_with_inheritance(&path)?);
    }

    if let Some(path) = dir {
        vectors.extend(TestVector::from_directory(&path)?);
    }

    let mut fingerprints = BTreeMap::new();
    let mut errors = Vec::new();
    let executor = VectorExecutor::with_test_chainspec();

    for vector in &vectors {
        eprintln!("Running: {}...", vector.name);

        match execute_vector(&executor, vector) {
            Ok(fingerprint) => {
                fingerprints.insert(vector.name.clone(), fingerprint);
            }
            Err(e) => {
                eprintln!("  ✗ Error: {e}");
                errors.push((vector.name.clone(), e));
            }
        }
    }

    let output_str = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&fingerprints)?,
        OutputFormat::Hashes => {
            let hashes: BTreeMap<String, String> = fingerprints
                .iter()
                .map(|(name, fp)| (name.clone(), format!("{:#x}", fp.hash())))
                .collect();
            serde_json::to_string_pretty(&hashes)?
        }
        OutputFormat::Summary => {
            let mut summary = String::new();
            for (name, fp) in &fingerprints {
                summary.push_str(&format!("✓ {} ({:#x})\n", name, fp.hash()));
            }
            for (name, err) in &errors {
                summary.push_str(&format!("✗ {name}: {err}\n"));
            }
            summary
        }
    };

    if let Some(path) = output {
        let mut file = std::fs::File::create(&path)?;
        file.write_all(output_str.as_bytes())?;
    } else {
        print!("{output_str}");
    }

    Ok(())
}

fn execute_vector(executor: &VectorExecutor, vector: &TestVector) -> Result<Fingerprint> {
    let mut db = VectorDatabase::from_prestate(&vector.prestate)?;
    let result = executor.execute(vector, &mut db)?;
    let post_state = PostExecutionState::capture(&db.db, &vector.checks)?;
    let fingerprint = Fingerprint::from_execution(
        &vector.name,
        &vector.hardfork,
        vector.block.number,
        result.tx_results,
        post_state,
    );
    Ok(fingerprint)
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
            println!("  {} ({})", vector.name, vector.hardfork);
        } else {
            println!("  {} ({})", vector.name, vector.hardfork);
            println!("    {}", vector.description);
        }
    }

    println!("\nTotal: {} vectors", vectors.len());

    Ok(())
}

fn run_single_command(vector_path: PathBuf) -> Result<()> {
    let vector = TestVector::load_with_inheritance(&vector_path)?;
    let executor = VectorExecutor::with_test_chainspec();
    let fingerprint = execute_vector(&executor, &vector)?;
    let json = serde_json::to_string(&fingerprint)?;
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

    eprintln!("Running {} vectors on current binary...", vectors.len());
    for vector in &vectors {
        let vector_path = find_vector_path(&dir, &vector.name)?;
        vector_paths.insert(vector.name.clone(), vector_path);

        match execute_vector(&executor, vector) {
            Ok(fingerprint) => {
                current_fingerprints.insert(vector.name.clone(), fingerprint);
            }
            Err(e) => {
                execution_errors.push((vector.name.clone(), e.to_string()));
            }
        }
    }

    let baseline_vectors: Vec<_> = vectors
        .iter()
        .filter(|v| v.check_regression.unwrap_or(false))
        .collect();

    eprintln!(
        "Comparing {} vectors with check_regression=true against baseline...",
        baseline_vectors.len()
    );

    let mut matched = 0;
    let mut new_passed = 0;
    let mut regressions: Vec<(String, String, String)> = Vec::new();

    for vector in &baseline_vectors {
        let vector_path = vector_paths.get(&vector.name).unwrap();

        let current_fp = match current_fingerprints.get(&vector.name) {
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
                                    vector.name.clone(),
                                    format!("{baseline_hash:#x}"),
                                    format!("{current_hash:#x}"),
                                ));
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "  Warning: failed to parse baseline fingerprint for {}: {}",
                                vector.name, e
                            );
                        }
                    }
                } else {
                    new_passed += 1;
                }
            }
            Err(e) => {
                eprintln!(
                    "  Warning: failed to run baseline for {}: {}",
                    vector.name, e
                );
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
                        && v.get("name").and_then(|n| n.as_str()) == Some(vector_name) {
                            return Ok(Some(path));
                        }
        }
        Ok(None)
    }

    search_dir(dir, vector_name)?
        .ok_or_else(|| eyre::eyre!("Could not find vector file for '{}'", vector_name))
}
