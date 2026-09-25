import csv, json
from pathlib import Path
root = Path(__file__).resolve().parent
runs = json.loads((root / "results.json").read_text())["runs"]
with (root / "summary.csv").open("w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["case", "slots_per_transaction", "measurement_seconds", "canonical_transactions", "canonical_slots_per_second", "whole_wall_ns_per_slot", "builder_durable_slots_per_second", "follower_durable_slots_per_second", "builder_backpressure_fraction", "follower_backpressure_fraction", "builder_durable_completion_seconds_after_load", "follower_durable_completion_seconds_after_load"])
    for r in runs:
        writer.writerow([r["scenario"], r["accesses_per_transaction"], r["canonical"]["duration_seconds"], r["canonical"]["transactions"], r["slots"]["slots_per_second"], r["slots"]["amortized_wall_ns_per_slot"], r["durability"]["a"]["slots"]["slots_per_second"], r["durability"]["b"]["slots"]["slots_per_second"], r["builder"]["backpressure"]["active_fraction"], r["follower"]["backpressure"]["active_fraction"], r["postload_durability"]["nodes"]["a"]["seconds_after_load_end"], r["postload_durability"]["nodes"]["b"]["seconds_after_load_end"]])
with (root / "time-slices.csv").open("w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["case", "load_seconds_from", "load_seconds_to", "canonical_blocks", "canonical_transactions", "canonical_slots_per_second", "whole_wall_ns_per_slot"])
    for r in runs:
        for s in r["trend"]:
            writer.writerow([r["scenario"], s["from_seconds"], s["to_seconds"], s["canonical"]["blocks"], s["canonical"]["transactions"], s["slots"]["slots_per_second"], s["slots"]["amortized_wall_ns_per_slot"]])
print("Wrote summary.csv and time-slices.csv")
