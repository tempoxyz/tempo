//! Explicit launcher for experimental per-hardfork bundles.
//! This does not replace `tempo` or automatically route node execution.

use clap::{Parser, Subcommand};
use std::{
    ffi::OsString,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tempo_hardfork::TempoHardfork;
use tempo_multiversion::{Bundle, pack};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Print the canonical executable names expected by the packer.
    Forks,
    /// Append one native executable per hardfork to this launcher.
    Pack {
        /// Directory containing tempo-genesis, tempo-t0, tempo-t1, etc.
        #[arg(long)]
        input_dir: PathBuf,
        /// Destination must not already exist.
        #[arg(long)]
        output: PathBuf,
    },
    /// List the hardforks in a bundle after verifying every checksum.
    Inspect {
        /// Defaults to this executable.
        #[arg(long)]
        bundle: Option<PathBuf>,
    },
    /// Extract a verified executable without overwriting an existing file.
    Extract {
        hardfork: TempoHardfork,
        #[arg(long)]
        bundle: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Execute an explicitly selected hardfork (Linux only).
    ///
    /// No database inspection or automatic protocol selection is performed.
    Run {
        hardfork: TempoHardfork,
        #[arg(long)]
        bundle: Option<PathBuf>,
        #[arg(last = true)]
        args: Vec<OsString>,
    },
}

fn main() -> io::Result<()> {
    match Args::parse().action {
        Action::Forks => {
            for fork in TempoHardfork::VARIANTS {
                println!("{}", executable_name(*fork));
            }
            Ok(())
        }
        Action::Pack { input_dir, output } => pack_command(&input_dir, &output),
        Action::Inspect { bundle } => {
            let mut bundle = open_bundle(bundle)?;
            bundle.verify()?;
            for entry in bundle.entries() {
                let checksum: String = entry
                    .sha256
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                println!("{}\t{}\t{checksum}", entry.hardfork, entry.length);
            }
            Ok(())
        }
        Action::Extract {
            hardfork,
            bundle,
            output,
        } => {
            let mut bundle = open_bundle(bundle)?;
            publish(&output, |file| bundle.copy_executable(hardfork, file))
        }
        Action::Run {
            hardfork,
            bundle,
            args,
        } => run(open_bundle(bundle)?, hardfork, args),
    }
}

fn executable_name(fork: TempoHardfork) -> String {
    format!("tempo-{}", fork.to_string().to_ascii_lowercase())
}

fn open_bundle(path: Option<PathBuf>) -> io::Result<Bundle<File>> {
    Bundle::open(File::open(path.map_or_else(std::env::current_exe, Ok)?)?)
}

fn pack_command(input_dir: &Path, output: &Path) -> io::Result<()> {
    let mut launcher = File::open(std::env::current_exe()?)?;
    // A bundle cannot be used as a launcher: that would recursively embed previous packs.
    // Check only the fixed footer magic; a corrupt bundle must not be repacked either.
    if has_bundle_footer(&mut launcher)? {
        return Err(io::Error::other(
            "pack with the unbundled tempo-multiversion launcher",
        ));
    }
    launcher.rewind()?;
    let target = native_target(&mut launcher)?;
    let mut executables = Vec::new();
    for fork in TempoHardfork::VARIANTS {
        let path = input_dir.join(executable_name(*fork));
        let mut file = File::open(&path)
            .map_err(|err| io::Error::new(err.kind(), format!("{}: {err}", path.display())))?;
        if has_bundle_footer(&mut file)? {
            return Err(io::Error::other(format!(
                "{}: extract individual executables before packing; nested bundles are not allowed",
                path.display()
            )));
        }
        if native_target(&mut file)? != target {
            return Err(io::Error::other(format!(
                "{}: executable target differs from launcher",
                path.display()
            )));
        }
        executables.push((*fork, file));
    }
    publish(output, |file| {
        pack(&mut launcher, &mut executables, &mut *file)?;
        file.rewind()?;
        Bundle::open(file)?.verify()
    })
}

fn has_bundle_footer(file: &mut File) -> io::Result<bool> {
    if file.metadata()?.len() < 56 {
        return Ok(false);
    }
    file.seek(SeekFrom::End(-56))?;
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    file.rewind()?;
    Ok(&magic == b"TEMPMV01")
}

/// Use the ELF machine or Mach-O CPU fields to reject scripts and mixed architectures.
/// The release builder still owns ABI, linkage, fork semantics, and provenance validation.
fn native_target(file: &mut File) -> io::Result<[u8; 8]> {
    let mut header = [0; 20];
    file.rewind()?;
    file.read_exact(&mut header)?;
    file.rewind()?;
    if &header[..4] == b"\x7fELF" && header[4] == 2 && header[5] == 1 {
        Ok([
            b'E', b'L', b'F', header[4], header[5], header[7], header[18], header[19],
        ])
    } else if header[..4] == [0xcf, 0xfa, 0xed, 0xfe] {
        Ok(header[..8].try_into().unwrap())
    } else {
        Err(io::Error::other(
            "expected a little-endian 64-bit ELF or Mach-O executable",
        ))
    }
}

fn publish(output: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    write(staged.as_file_mut())?;
    staged.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        staged
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))?;
    }
    staged.as_file().sync_all()?;
    staged.persist_noclobber(output).map_err(|err| err.error)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn run(mut bundle: Bundle<File>, fork: TempoHardfork, args: Vec<OsString>) -> io::Result<()> {
    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
    use std::os::{fd::AsRawFd as _, unix::process::CommandExt as _};

    let mut executable = File::from(memfd_create(
        "tempo-hardfork",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?);
    bundle.copy_executable(fork, &mut executable)?;
    // Seal the exact bytes that were verified, then replace this process. This preserves
    // PID, signals, standard IO, exit status, and argument bytes without a supervising shell.
    fcntl_add_seals(
        &executable,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )?;
    Err(
        std::process::Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()))
            .args(args)
            .exec(),
    )
}

#[cfg(not(target_os = "linux"))]
fn run(_bundle: Bundle<File>, _fork: TempoHardfork, _args: Vec<OsString>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "in-memory launch is Linux-only; extract the selected executable explicitly",
    ))
}
