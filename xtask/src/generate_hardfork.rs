use std::{fs, path::Path};

use eyre::{Context as _, ensure};
use serde::Serialize;

const HARDFORK_SOURCE: &str = "crates/hardfork/src/lib.rs";
const CHAINSPEC_SOURCE: &str = "crates/chainspec/src/spec.rs";
const GENESIS_ARGS_SOURCE: &str = "xtask/src/genesis_args.rs";
const FOUNDRY_CONFIG: &str = "tips/verify/foundry.toml";
const BENCH_WORKFLOW: &str = ".github/workflows/bench.yml";
const DEV_GENESIS: &str = "crates/chainspec/src/genesis/dev.json";
const TEST_GENESIS: &str = "crates/node/tests/assets/test-genesis.json";
const SNAPSHOT_DIR: &str = "crates/evm/src/snapshots";
const FUTURE_TIMESTAMP: u64 = 4_102_444_800;

#[derive(Debug, Serialize)]
struct HardforkLane {
    hardfork: String,
    #[serde(rename = "genesisArgs")]
    genesis_args: String,
}

#[derive(Debug, Serialize)]
struct HardforkMetadata {
    current: String,
    next: String,
    ordered: Vec<String>,
    hardforks: Vec<HardforkLane>,
}

/// Add mechanical plumbing for a new Tempo hardfork.
///
/// This command intentionally does not modify feature gates, TIPs, runtime code, or genesis
/// allocations owned by a specific upgrade. Those changes remain reviewable in the feature PRs
/// that follow the generated plumbing PR.
#[derive(clap::Args, Debug)]
pub(crate) struct AddHardfork {
    /// New hardfork identifier, for example `T11` or `T1A`.
    #[arg(long, value_name = "HARDFORK")]
    hardfork: String,
    /// Emit machine-readable transition metadata instead of a summary.
    #[arg(long)]
    json: bool,
}

impl AddHardfork {
    pub(crate) fn run(self) -> eyre::Result<()> {
        let metadata = add_hardfork(Path::new("."), &self.hardfork)?;
        if self.json {
            println!("{}", serde_json::to_string(&metadata)?);
        } else {
            println!(
                "Added {} plumbing; rotated Foundry profiles -> {}/{}",
                metadata.next, metadata.current, metadata.next
            );
        }
        Ok(())
    }
}

fn add_hardfork(root: &Path, hardfork: &str) -> eyre::Result<HardforkMetadata> {
    validate_name(hardfork)?;

    let hardfork_path = root.join(HARDFORK_SOURCE);
    let hardfork_source = read(&hardfork_path)?;
    let variants = parse_variants(&hardfork_source)?;
    ensure!(
        !variants.iter().any(|variant| variant == hardfork),
        "hardfork `{hardfork}` already exists"
    );

    let previous = variants
        .last()
        .expect("TempoHardfork always has at least Genesis");
    let current = variants
        .get(variants.len().saturating_sub(2))
        .expect("TempoHardfork always has a current hardfork");

    let metadata = build_metadata(&variants, current, previous, hardfork);

    let foundry_path = root.join(FOUNDRY_CONFIG);
    let foundry = read(&foundry_path)?;
    ensure_profile_pair(&foundry, current, previous)?;

    write(
        &hardfork_path,
        &append_hardfork_source(&hardfork_source, previous, hardfork)?,
    )?;

    let chainspec_path = root.join(CHAINSPEC_SOURCE);
    let chainspec = read(&chainspec_path)?;
    write(
        &chainspec_path,
        &append_genesis_info_field(&chainspec, previous, hardfork)?,
    )?;

    let genesis_args_path = root.join(GENESIS_ARGS_SOURCE);
    let genesis_args = read(&genesis_args_path)?;
    write(
        &genesis_args_path,
        &append_genesis_arg(&genesis_args, previous, hardfork)?,
    )?;

    write(
        &foundry_path,
        &rotate_profiles(&foundry, previous, hardfork)?,
    )?;

    let bench_path = root.join(BENCH_WORKFLOW);
    let bench = read(&bench_path)?;
    write(
        &bench_path,
        &append_bench_hardfork(&bench, &variants, previous, hardfork)?,
    )?;

    for path in [DEV_GENESIS, TEST_GENESIS] {
        let path = root.join(path);
        let genesis = read(&path)?;
        write(&path, &append_genesis_time(&genesis, previous, hardfork)?)?;
    }

    copy_snapshot(root, previous, hardfork)?;

    Ok(metadata)
}

fn build_metadata(
    variants: &[String],
    current: &str,
    next_current: &str,
    next: &str,
) -> HardforkMetadata {
    let start = variants
        .iter()
        .position(|variant| variant == current)
        .expect("current hardfork must be in the variants");
    let mut ordered = variants[start..].to_vec();
    ordered.push(next.to_owned());

    let current_args = build_genesis_args(&ordered, Some(next));
    let next_args = build_genesis_args(&ordered, None);

    HardforkMetadata {
        current: next_current.to_owned(),
        next: next.to_owned(),
        ordered,
        hardforks: vec![
            HardforkLane {
                hardfork: next_current.to_owned(),
                genesis_args: current_args,
            },
            HardforkLane {
                hardfork: next.to_owned(),
                genesis_args: next_args,
            },
        ],
    }
}

fn build_genesis_args(ordered: &[String], future_hardfork: Option<&str>) -> String {
    ordered
        .iter()
        .map(|hardfork| {
            let timestamp = if future_hardfork == Some(hardfork.as_str()) {
                FUTURE_TIMESTAMP
            } else {
                0
            };
            format!("--{}-time={timestamp}", hardfork.to_ascii_lowercase())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_name(hardfork: &str) -> eyre::Result<()> {
    ensure!(
        !hardfork.is_empty()
            && hardfork.starts_with("T")
            && hardfork.chars().skip(1).all(|c| c.is_ascii_alphanumeric()),
        "invalid hardfork `{hardfork}`; expected an identifier such as T11 or T1A"
    );
    Ok(())
}

fn parse_variants(source: &str) -> eyre::Result<Vec<String>> {
    let enum_start = source
        .find("TempoHardfork {")
        .ok_or_else(|| eyre::eyre!("could not find TempoHardfork definition"))?
        + "TempoHardfork {".len();
    let enum_end = source[enum_start..]
        .find("\n    }\n);")
        .map(|offset| enum_start + offset)
        .ok_or_else(|| eyre::eyre!("could not find end of TempoHardfork definition"))?;

    let variants = source[enum_start..enum_end]
        .lines()
        .filter_map(|line| {
            let candidate = line.trim().strip_suffix(',')?;
            (candidate.chars().next()?.is_ascii_uppercase()
                && candidate.chars().all(|c| c.is_ascii_alphanumeric()))
            .then(|| candidate.to_string())
        })
        .collect::<Vec<_>>();

    ensure!(
        !variants.is_empty(),
        "TempoHardfork definition has no variants"
    );
    Ok(variants)
}

fn append_hardfork_source(source: &str, previous: &str, hardfork: &str) -> eyre::Result<String> {
    let marker = format!("        {previous},\n");
    let docs = format!(
        "        /// {hardfork} hardfork.\n        ///\n        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/{}>.\n        {hardfork},\n",
        hardfork.to_ascii_lowercase()
    );
    let mut output = insert_once(source, &marker, &format!("{marker}{docs}"))?;

    let match_marker = format!("            Self::{previous} => None,\n");
    let match_replacement = format!("{match_marker}            Self::{hardfork} => None,\n");
    let count = output.matches(&match_marker).count();
    ensure!(
        count == 4,
        "expected four activation matches for {previous}, found {count}"
    );
    output = output.replace(&match_marker, &match_replacement);
    Ok(output)
}

fn append_genesis_info_field(source: &str, previous: &str, hardfork: &str) -> eyre::Result<String> {
    let previous_field = format!(
        "    /// Activation timestamp for {previous} hardfork.\n    #[serde(skip_serializing_if = \"Option::is_none\")]\n    {}_time: Option<u64>,\n",
        previous.to_ascii_lowercase()
    );
    let new_field = format!(
        "{previous_field}    /// Activation timestamp for {hardfork} hardfork.\n    #[serde(skip_serializing_if = \"Option::is_none\")]\n    {}_time: Option<u64>,\n",
        hardfork.to_ascii_lowercase()
    );
    let source = insert_once(source, &previous_field, &new_field)?;
    let previous_assert = format!(
        "            assert!(!cs.is_{}_active_at_timestamp(u64::MAX));\n",
        previous.to_ascii_lowercase()
    );
    let new_assert = format!(
        "{previous_assert}            assert!(!cs.is_{}_active_at_timestamp(u64::MAX));\n",
        hardfork.to_ascii_lowercase()
    );
    let count = source.matches(&previous_assert).count();
    ensure!(
        count == 2,
        "expected two future activation assertions for {previous}, found {count}"
    );
    Ok(source.replace(&previous_assert, &new_assert))
}

fn append_genesis_arg(source: &str, previous: &str, hardfork: &str) -> eyre::Result<String> {
    let previous_arg = format!(
        "    /// {previous} hardfork activation time.\n    #[arg(long, default_value = \"0\")]\n    {}_time: u64,\n",
        previous.to_ascii_lowercase()
    );
    let new_arg = format!(
        "{previous_arg}\n    /// {hardfork} hardfork activation time.\n    #[arg(long, default_value = \"0\")]\n    {}_time: u64,\n",
        hardfork.to_ascii_lowercase()
    );
    let mut output = insert_once(source, &previous_arg, &new_arg)?;

    let previous_insert = format!(
        "        chain_config\n            .extra_fields\n            .insert_value(\"{}Time\".to_string(), self.{}_time)?;\n",
        previous.to_ascii_lowercase(),
        previous.to_ascii_lowercase()
    );
    let new_insert = format!(
        "{previous_insert}        chain_config\n            .extra_fields\n            .insert_value(\"{}Time\".to_string(), self.{}_time)?;\n",
        hardfork.to_ascii_lowercase(),
        hardfork.to_ascii_lowercase()
    );
    output = insert_once(&output, &previous_insert, &new_insert)?;
    Ok(output)
}

fn ensure_profile_pair(source: &str, current: &str, previous: &str) -> eyre::Result<()> {
    ensure!(
        profile_hardfork(source, "default")?.as_deref() == Some(current),
        "default profile must use current hardfork {current}"
    );
    ensure!(
        profile_hardfork(source, "next")?.as_deref() == Some(previous),
        "next profile must use latest hardfork {previous}"
    );
    Ok(())
}

fn profile_hardfork(source: &str, profile: &str) -> eyre::Result<Option<String>> {
    let header = format!("[profile.{profile}]");
    let start = source
        .find(&header)
        .ok_or_else(|| eyre::eyre!("missing {header} section"))?;
    let end = source[start + header.len()..]
        .find("\n[")
        .map(|offset| start + header.len() + offset)
        .unwrap_or(source.len());
    Ok(source[start..end].lines().find_map(|line| {
        let value = line.trim().strip_prefix("hardfork = \"tempo:")?;
        Some(value.strip_suffix('"')?.to_string())
    }))
}

fn rotate_profiles(source: &str, previous: &str, hardfork: &str) -> eyre::Result<String> {
    let source = replace_profile_hardfork(source, "default", previous)?;
    replace_profile_hardfork(&source, "next", hardfork)
}

fn replace_profile_hardfork(source: &str, profile: &str, hardfork: &str) -> eyre::Result<String> {
    let header = format!("[profile.{profile}]");
    let start = source
        .find(&header)
        .ok_or_else(|| eyre::eyre!("missing {header} section"))?;
    let end = source[start + header.len()..]
        .find("\n[")
        .map(|offset| start + header.len() + offset)
        .unwrap_or(source.len());
    let section = &source[start..end];
    let old_line = section
        .lines()
        .find(|line| line.trim().starts_with("hardfork ="))
        .ok_or_else(|| eyre::eyre!("missing hardfork in {header}"))?;
    let new_line = format!("hardfork = \"tempo:{hardfork}\"");
    let line_start = start + section.find(old_line).unwrap();
    let line_end = line_start + old_line.len();
    let mut output = source.to_string();
    output.replace_range(line_start..line_end, &new_line);
    Ok(output)
}

fn append_bench_hardfork(
    source: &str,
    variants: &[String],
    previous: &str,
    hardfork: &str,
) -> eyre::Result<String> {
    let marker = format!("'{previous}'");
    let replacement = format!("'{previous}', '{hardfork}'");
    let count = source.matches(&marker).count();
    ensure!(
        count == 1,
        "expected one benchmark hardfork allowlist entry"
    );
    let mut output = source.replacen(&marker, &replacement, 1);
    let usage_values = variants
        .iter()
        .skip(1)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("|");

    for prefix in ["baseline-hardfork=", "feature-hardfork="] {
        let mut search_from = 0;
        let mut replacements = 0;
        while let Some(relative_start) = output[search_from..].find(prefix) {
            let start = search_from + relative_start;
            let values_start = start + prefix.len();
            let end = values_start
                + output[values_start..]
                    .find(']')
                    .ok_or_else(|| eyre::eyre!("unterminated benchmark usage range"))?;
            output.replace_range(values_start..end, &usage_values);
            search_from = values_start + usage_values.len();
            replacements += 1;
        }
        ensure!(
            replacements == 2,
            "expected two benchmark usage ranges for {prefix}, found {replacements}"
        );
    }

    Ok(output)
}

fn append_genesis_time(source: &str, previous: &str, hardfork: &str) -> eyre::Result<String> {
    let marker = format!("    \"{}Time\": 0,\n", previous.to_ascii_lowercase());
    let insertion = format!(
        "{marker}    \"{}Time\": 0,\n",
        hardfork.to_ascii_lowercase()
    );
    insert_once(source, &marker, &insertion)
}

fn copy_snapshot(root: &Path, previous: &str, hardfork: &str) -> eyre::Result<()> {
    let dir = root.join(SNAPSHOT_DIR);
    let previous_name =
        format!("tempo_evm__evm__tests__tip20_full_evm_storage_actions_{previous}.snap");
    let hardfork_name =
        format!("tempo_evm__evm__tests__tip20_full_evm_storage_actions_{hardfork}.snap");
    let source = dir.join(previous_name);
    let target = dir.join(hardfork_name);
    ensure!(
        source.exists(),
        "missing source snapshot `{}`",
        source.display()
    );
    ensure!(
        !target.exists(),
        "snapshot `{}` already exists",
        target.display()
    );
    fs::copy(&source, &target)
        .wrap_err_with(|| format!("failed copying snapshot to `{}`", target.display()))?;
    Ok(())
}

fn insert_once(source: &str, marker: &str, replacement: &str) -> eyre::Result<String> {
    let count = source.matches(marker).count();
    ensure!(
        count == 1,
        "expected one occurrence of generator marker, found {count}"
    );
    Ok(source.replacen(marker, replacement, 1))
}

fn read(path: &Path) -> eyre::Result<String> {
    fs::read_to_string(path).wrap_err_with(|| format!("failed reading `{}`", path.display()))
}

fn write(path: &Path, contents: &str) -> eyre::Result<()> {
    fs::write(path, contents).wrap_err_with(|| format!("failed writing `{}`", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hardfork_variants_without_comments() {
        let source = "TempoHardfork {\n        Genesis,\n        /// T0\n        T0,\n    }\n);";
        assert_eq!(
            parse_variants(source).unwrap(),
            vec!["Genesis".to_owned(), "T0".to_owned()]
        );
    }

    #[test]
    fn rotates_only_selected_profiles() {
        let source = "[profile.default]\nhardfork = \"tempo:T9\"\n\n[profile.next]\nhardfork = \"tempo:T10\"\n";
        let rotated = rotate_profiles(source, "T10", "T11").unwrap();
        assert!(rotated.contains("[profile.default]\nhardfork = \"tempo:T10\""));
        assert!(rotated.contains("[profile.next]\nhardfork = \"tempo:T11\""));
    }

    #[test]
    fn builds_machine_readable_transition_metadata() {
        let variants = ["Genesis", "T8", "T9", "T10"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let metadata = build_metadata(&variants, "T9", "T10", "T11");

        assert_eq!(metadata.current, "T10");
        assert_eq!(metadata.next, "T11");
        assert_eq!(
            metadata.ordered,
            vec!["T9".to_owned(), "T10".to_owned(), "T11".to_owned()]
        );
        assert_eq!(metadata.hardforks[0].hardfork, "T10");
        assert_eq!(
            metadata.hardforks[0].genesis_args,
            "--t9-time=0 --t10-time=0 --t11-time=4102444800"
        );
        assert_eq!(metadata.hardforks[1].hardfork, "T11");
        assert_eq!(
            metadata.hardforks[1].genesis_args,
            "--t9-time=0 --t10-time=0 --t11-time=0"
        );
        assert_eq!(
            serde_json::to_string(&metadata).unwrap(),
            r#"{"current":"T10","next":"T11","ordered":["T9","T10","T11"],"hardforks":[{"hardfork":"T10","genesisArgs":"--t9-time=0 --t10-time=0 --t11-time=4102444800"},{"hardfork":"T11","genesisArgs":"--t9-time=0 --t10-time=0 --t11-time=0"}]}"#
        );
    }

    #[test]
    fn appends_all_activation_match_arms() {
        let source = "        T10,\n    }\n);\n\n".to_owned()
            + "            Self::T10 => None,\n"
            + "            Self::T10 => None,\n"
            + "            Self::T10 => None,\n"
            + "            Self::T10 => None,\n";
        let updated = append_hardfork_source(&source, "T10", "T11").unwrap();
        assert_eq!(updated.matches("Self::T11 => None").count(), 4);
        assert!(updated.contains("        T11,\n"));
    }

    #[test]
    fn updates_benchmark_allowlist_and_usage() {
        let variants = ["Genesis", "T9", "T10", "T11"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let source = concat!(
            "const hardforkValues = new Set(['T9', 'T10']);\n",
            "[baseline-hardfork=T0|T8] [feature-hardfork=T0|T8]\n",
            "[baseline-hardfork=T0|T8] [feature-hardfork=T0|T8]\n",
        );
        let updated = append_bench_hardfork(source, &variants, "T10", "T11").unwrap();
        assert!(updated.contains("['T9', 'T10', 'T11']"));
        assert_eq!(updated.matches("T9|T10|T11").count(), 4);
    }
}
