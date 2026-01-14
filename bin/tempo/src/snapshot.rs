use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

use clap::Subcommand;
use eyre::{Context, bail};
use indicatif::{ProgressBar, ProgressStyle};
use reth_db::{Database, mdbx::DatabaseArguments, open_db_read_only};
use tar::{Archive, Builder};
use walkdir::WalkDir;

#[derive(Debug, clap::Args)]
pub(crate) struct SnapshotCommand {
    #[command(subcommand)]
    command: SnapshotSubcommand,
}

impl SnapshotCommand {
    pub(crate) fn run(self) -> eyre::Result<()> {
        match self.command {
            SnapshotSubcommand::Create(args) => args.run(),
            SnapshotSubcommand::Extract(args) => args.run(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum SnapshotSubcommand {
    /// Create a snapshot archive from node data.
    Create(SnapshotCreate),
    /// Extract a snapshot archive to restore node data.
    Extract(SnapshotExtract),
}

#[derive(Debug, clap::Args)]
struct SnapshotCreate {
    /// Path to the data directory containing db and static_files.
    #[arg(long, value_name = "PATH")]
    datadir: PathBuf,

    /// Chain ID to include in the snapshot filename.
    #[arg(long, value_name = "ID")]
    chain_id: u64,

    /// Output path for the snapshot archive. If not specified, uses
    /// snapshot-<block>-archive-<chain_id>.tar.lz4 in the current directory.
    #[arg(long, short, value_name = "FILE")]
    output: Option<PathBuf>,
}

impl SnapshotCreate {
    fn run(self) -> eyre::Result<()> {
        let Self {
            datadir,
            chain_id,
            output,
        } = self;

        let db_path = datadir.join("db");
        let static_files_path = datadir.join("static_files");

        // Verify directories exist
        if !db_path.exists() {
            bail!("database directory does not exist: {}", db_path.display());
        }
        if !static_files_path.exists() {
            bail!(
                "static_files directory does not exist: {}",
                static_files_path.display()
            );
        }

        // Try to open database read-only to check if it's in use and get block number
        println!("Opening database to read block number...");
        let block_number = read_block_number_from_db(&db_path)?;
        println!("Latest block number: {block_number}");

        // Determine output path
        let output_path = output.unwrap_or_else(|| {
            PathBuf::from(format!(
                "snapshot-{block_number}-archive-{chain_id}.tar.lz4"
            ))
        });

        if output_path.exists() {
            bail!(
                "output file already exists: {}. Remove it first or specify a different path.",
                output_path.display()
            );
        }

        println!("Creating snapshot archive: {}", output_path.display());

        // Count total files for progress bar
        let total_files = count_files(&db_path)? + count_files(&static_files_path)?;
        let progress = ProgressBar::new(total_files);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
                .expect("valid template")
                .progress_chars("#>-"),
        );

        // Create the archive
        let file = File::create(&output_path)
            .wrap_err_with(|| format!("failed to create output file: {}", output_path.display()))?;
        let encoder = lz4::EncoderBuilder::new()
            .level(0) // default compression
            .build(BufWriter::new(file))
            .wrap_err("failed to create lz4 encoder")?;

        let mut archive = Builder::new(encoder);

        // Add db directory
        add_directory_to_archive(&mut archive, &db_path, "db", &progress)?;

        // Add static_files directory
        add_directory_to_archive(&mut archive, &static_files_path, "static_files", &progress)?;

        // Finalize the archive
        let encoder = archive
            .into_inner()
            .wrap_err("failed to finalize tar archive")?;
        let (mut writer, result) = encoder.finish();
        result.wrap_err("failed to finalize lz4 compression")?;
        writer.flush().wrap_err("failed to flush output")?;

        progress.finish_with_message("done");

        let file_size = fs::metadata(&output_path)?.len();
        println!(
            "Snapshot created successfully: {} ({} bytes)",
            output_path.display(),
            file_size
        );

        Ok(())
    }
}

#[derive(Debug, clap::Args)]
struct SnapshotExtract {
    /// Path to the snapshot archive to extract.
    #[arg(value_name = "ARCHIVE")]
    archive: PathBuf,

    /// Path to the data directory where db and static_files will be extracted.
    #[arg(long, value_name = "PATH")]
    datadir: PathBuf,
}

impl SnapshotExtract {
    fn run(self) -> eyre::Result<()> {
        let Self { archive, datadir } = self;

        if !archive.exists() {
            bail!("archive file does not exist: {}", archive.display());
        }

        let db_path = datadir.join("db");
        let static_files_path = datadir.join("static_files");

        // Safety check: refuse to overwrite existing directories
        if db_path.exists() {
            bail!(
                "database directory already exists: {}. Remove it first to prevent data loss.",
                db_path.display()
            );
        }
        if static_files_path.exists() {
            bail!(
                "static_files directory already exists: {}. Remove it first to prevent data loss.",
                static_files_path.display()
            );
        }

        // Create parent directory if needed
        if !datadir.exists() {
            fs::create_dir_all(&datadir)
                .wrap_err_with(|| format!("failed to create datadir: {}", datadir.display()))?;
        }

        println!(
            "Extracting snapshot archive: {} -> {}",
            archive.display(),
            datadir.display()
        );

        // Open and decompress the archive
        let file = File::open(&archive)
            .wrap_err_with(|| format!("failed to open archive: {}", archive.display()))?;
        let decoder =
            lz4::Decoder::new(BufReader::new(file)).wrap_err("failed to create lz4 decoder")?;

        let mut archive = Archive::new(decoder);

        // Get entries count for progress (we'll estimate based on archive metadata)
        let progress = ProgressBar::new_spinner();
        progress.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .expect("valid template"),
        );

        let mut file_count = 0u64;
        let mut total_bytes = 0u64;

        for entry in archive
            .entries()
            .wrap_err("failed to read archive entries")?
        {
            let mut entry = entry.wrap_err("failed to read archive entry")?;
            let path = entry
                .path()
                .wrap_err("failed to get entry path")?
                .into_owned();
            let dest_path = datadir.join(&path);

            progress.set_message(format!("extracting: {}", path.display()));

            // Ensure parent directory exists
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).wrap_err_with(|| {
                    format!("failed to create directory: {}", parent.display())
                })?;
            }

            let entry_size = entry.size();
            entry
                .unpack(&dest_path)
                .wrap_err_with(|| format!("failed to extract: {}", path.display()))?;

            file_count += 1;
            total_bytes += entry_size;
        }

        progress.finish_with_message(format!(
            "extracted {file_count} files ({total_bytes} bytes)"
        ));

        println!("Snapshot extracted successfully to: {}", datadir.display());

        Ok(())
    }
}

/// Read the latest block number from the database.
fn read_block_number_from_db(db_path: &Path) -> eyre::Result<u64> {
    use reth_db::{cursor::DbCursorRO, tables, transaction::DbTx};

    // Try to open database in read-only mode
    let database = open_db_read_only(db_path, DatabaseArguments::default()).wrap_err(
        "failed to open database. Is the node running? Stop the node before creating a snapshot.",
    )?;

    let provider = database
        .tx()
        .wrap_err("failed to create database transaction")?;

    // Try CanonicalHeaders first (primary source)
    let mut cursor = provider
        .cursor_read::<tables::CanonicalHeaders>()
        .wrap_err("failed to create cursor for CanonicalHeaders")?;

    if let Some((block_number, _)) = cursor
        .last()
        .wrap_err("failed to read last canonical header")?
    {
        return Ok(block_number);
    }

    // Fallback: try HeaderNumbers table (maps hash -> number)
    let mut cursor = provider
        .cursor_read::<tables::HeaderNumbers>()
        .wrap_err("failed to create cursor for HeaderNumbers")?;

    if let Some((_, block_number)) = cursor
        .last()
        .wrap_err("failed to read last header number")?
    {
        return Ok(block_number);
    }

    // If neither table has data, it's likely a fresh database with only genesis in static files
    // In this case, return 0 (genesis block)
    Ok(0)
}

/// Count the number of files in a directory recursively.
fn count_files(path: &Path) -> eyre::Result<u64> {
    let mut count = 0;
    for entry in WalkDir::new(path) {
        let entry = entry.wrap_err("failed to read directory entry")?;
        if entry.file_type().is_file() {
            count += 1;
        }
    }
    Ok(count)
}

/// Add a directory to the tar archive with progress updates.
fn add_directory_to_archive<W: Write>(
    archive: &mut Builder<W>,
    src_path: &Path,
    archive_name: &str,
    progress: &ProgressBar,
) -> eyre::Result<()> {
    for entry in WalkDir::new(src_path) {
        let entry = entry.wrap_err("failed to read directory entry")?;
        let path = entry.path();
        let relative_path = path
            .strip_prefix(src_path)
            .wrap_err("failed to compute relative path")?;

        let archive_path = PathBuf::from(archive_name).join(relative_path);

        if entry.file_type().is_file() {
            let mut file = File::open(path)
                .wrap_err_with(|| format!("failed to open file: {}", path.display()))?;
            archive
                .append_file(&archive_path, &mut file)
                .wrap_err_with(|| format!("failed to add file to archive: {}", path.display()))?;
            progress.inc(1);
        } else if entry.file_type().is_dir() && path != src_path {
            archive.append_dir(&archive_path, path).wrap_err_with(|| {
                format!("failed to add directory to archive: {}", path.display())
            })?;
        }
    }
    Ok(())
}
