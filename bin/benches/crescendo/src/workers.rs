use std::collections::HashMap;

use core_affinity::CoreId;

mod network;
mod tx_gen;

pub use network::network_worker;
pub use tx_gen::tx_gen_worker;

use crate::utils::format_ranges;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum WorkerType {
    TxGen,
    Network,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum DesireType {
    Exact(u64),
    Percentage(f64),
}

/// Given a desired breakdown of workers, translate this into actual numbers of workers to spawn.
///
/// Assumes that thread pinning is desired and thus maps each worker to a core, but this can be
/// ignored if desired, of course. Each worker type will be assigned at least one core.
///
/// TODO: The first worker for each type is assigned a core at the end of the core list. This is
/// not ideal, as it means workers are not placed in contiguous ranges of cores, which is gross
/// for monitoring performance but also could also slightly hurt cache locality. Should refactor
/// to ensure each worker type is assigned a contiguous range of cores no matter what.
///
/// TODO: This also doesn't do error handling well as far as I can tell, I think there can be silent
/// allocation failures.
pub fn assign_workers(
    mut core_ids: Vec<CoreId>,
    assignments: Vec<(WorkerType, DesireType)>,
    log_core_ranges: bool, // Enable to log the range of cores each worker should be pinned to.
) -> (Vec<(core_affinity::CoreId, WorkerType)>, HashMap<WorkerType, u64>) {
    let mut result = Vec::new();
    let mut worker_counts: HashMap<WorkerType, u64> = HashMap::new();
    let mut worker_cores: HashMap<WorkerType, Vec<CoreId>> = HashMap::new();

    let total_starting_cores = core_ids.len();
    let mut remaining_cores = total_starting_cores;

    // First pass: handle exact assignments
    let mut percentage_assignments = Vec::new();
    for (worker_type, desire_type) in assignments {
        match desire_type {
            DesireType::Exact(count) => {
                let cores_to_assign = (count as usize).min(remaining_cores);
                for _ in 0..cores_to_assign {
                    if let Some(core_id) = core_ids.pop() {
                        result.push((core_id, worker_type));
                        *worker_counts.entry(worker_type).or_insert(0) += 1;
                        worker_cores.entry(worker_type).or_default().push(core_id);
                        remaining_cores -= 1;
                    }
                }
            }
            DesireType::Percentage(percentage) => {
                percentage_assignments.push((worker_type, percentage));
            }
        }
    }

    // Second pass: ensure each percentage worker gets at least one core
    for (worker_type, _) in &percentage_assignments {
        if remaining_cores > 0 && !worker_counts.contains_key(worker_type) {
            if let Some(core_id) = core_ids.pop() {
                result.push((core_id, *worker_type));
                *worker_counts.entry(*worker_type).or_insert(0) += 1;
                worker_cores.entry(*worker_type).or_default().push(core_id);
                remaining_cores -= 1;
            }
        }
    }

    for (worker_type, percentage) in percentage_assignments {
        let cores_for_type = (remaining_cores as f64 * percentage).floor() as usize;

        for _ in 0..cores_for_type {
            if let Some(core_id) = core_ids.pop() {
                result.push((core_id, worker_type));
                *worker_counts.entry(worker_type).or_insert(0) += 1;
                worker_cores.entry(worker_type).or_default().push(core_id);
            }
        }
    }

    println!("[+] Spawning {total_starting_cores} workers:");
    for (worker_type, count) in worker_counts.clone() {
        if log_core_ranges {
            if let Some(cores) = worker_cores.get(&worker_type) {
                let mut core_ids: Vec<usize> = cores.iter().map(|c| c.id).collect();
                core_ids.sort();

                let core_str = match core_ids.as_slice() {
                    [single] => format!("core {single}"),
                    ids => format!("cores {}", format_ranges(ids)),
                };
                println!("- {worker_type:?}: {count} ({core_str})");
            }
        } else {
            println!("- {worker_type:?}: {count}");
        }
    }

    (result, worker_counts)
}
