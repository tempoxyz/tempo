use std::io;

use core_affinity::CoreId;
use rlimit::Resource;

use crate::config;

/// Increase the file descriptor limit to the given minimum.
///
/// Panics if the hard limit is too low, otherwise tries to increase.
pub fn increase_nofile_limit(min_limit: u64) -> io::Result<u64> {
    let (soft, hard) = Resource::NOFILE.get()?;
    println!("[*] At startup, file descriptor limit:      soft = {soft}, hard = {hard}");

    if hard < min_limit {
        panic!("[!] File descriptor hard limit is too low. Please increase it to at least {min_limit}.");
    }

    if soft != hard {
        Resource::NOFILE.set(hard, hard)?; // Just max things out to give us plenty of overhead.
        let (soft, hard) = Resource::NOFILE.get()?;
        println!("[+] After increasing file descriptor limit: soft = {soft}, hard = {hard}");
    }

    Ok(soft)
}

/// Pin the current thread to the given core ID if enabled.
///
/// Panics if the thread fails to pin.
pub fn maybe_pin_thread(core_id: CoreId) {
    if !config::get().workers.thread_pinning {
        return;
    }

    if !core_affinity::set_for_current(core_id) {
        panic!("[!] Failed to pin thread to core {}. Try disabling thread_pinning in your config.", core_id.id);
    }
}

/// Format a sorted list of numbers into a range string (e.g., "1-3, 5, 7-9")
pub fn format_ranges(nums: &[usize]) -> String {
    if nums.is_empty() {
        return String::new();
    }

    let mut ranges = Vec::new();
    let mut i = 0;

    while i < nums.len() {
        let start = nums[i];
        let mut end = start;

        // Find end of consecutive sequence
        while i + 1 < nums.len() && nums[i + 1] == nums[i] + 1 {
            i += 1;
            end = nums[i];
        }

        // Format this range
        if start == end {
            ranges.push(start.to_string());
        } else {
            ranges.push(format!("{start}-{end}"));
        }

        i += 1;
    }

    ranges.join(", ")
}

/// Merge two TOML values, with `overlay` taking precedence over `base`.
pub fn merge_toml_values(base: toml::Value, overlay: toml::Value) -> toml::Value {
    match (base, overlay) {
        (toml::Value::Table(mut base_table), toml::Value::Table(overlay_table)) => {
            for (key, overlay_value) in overlay_table {
                match base_table.get(&key) {
                    Some(base_value) if base_value.is_table() && overlay_value.is_table() => {
                        // Recursively merge nested tables
                        base_table.insert(key, merge_toml_values(base_value.clone(), overlay_value));
                    }
                    _ => {
                        // Replace the value
                        base_table.insert(key, overlay_value);
                    }
                }
            }
            toml::Value::Table(base_table)
        }
        (_, overlay) => overlay, // For non-table values, overlay completely replaces base.
    }
}
