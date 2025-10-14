# Python Analysis Tools

This directory contains Python scripts and libraries for analyzing tempo benchmark logs.

## Directory Structure

```
python_analysis/
├── lib/                    # Shared library code
│   ├── __init__.py
│   └── log_analysis.py    # Core log analysis functions
├── scripts/               # Executable scripts
│   ├── analyze_logs.py    # Standalone log analysis script
│   └── reth_bench_compare.py  # Full benchmark pipeline
└── logs/                  # Log files and output
    ├── debug_main.log
    ├── debug_feature.log
    ├── metrics_main.json
    └── metrics_feature.json
```

## Scripts

### analyze_logs.py

Standalone script for analyzing tempo benchmark logs without running the full benchmark pipeline.

**Usage:**
```bash
cd scripts

# Analyze a single log file
python3 analyze_logs.py ../logs/debug_main.log

# Compare two log files
python3 analyze_logs.py ../logs/debug_main.log ../logs/debug_feature.log

# Save metrics to JSON
python3 analyze_logs.py ../logs/debug_main.log --save ../logs/output.json
```

**Features:**
- Detects steady-state block range based on transaction count and gas usage
- Extracts timing metrics: Build Payload, Execution, Builder Finish, State Root Task, Payload Delivery Lag, Block Added to Chain
- Computes statistics: mean, median, min, max, standard deviation
- Compares two logs and shows absolute and percentage differences

### reth_bench_compare.py

Full benchmark pipeline that builds tempo, runs benchmarks, and analyzes logs.

**Usage:**
```bash
cd scripts

# Run full benchmark comparison
python3 reth_bench_compare.py

# The script will:
# 1. Build tempo with feature and main commits
# 2. Run benchmarks for each version
# 3. Analyze logs with detailed block decision tracking
# 4. Compare results and save to JSON
```

**Features:**
- Builds tempo from specified commits
- Runs tempo node and benchmark tests
- Enhanced log parsing with block decision tracking for debugging
- Detailed reporting of which blocks were included/excluded and why

## Library

### lib/log_analysis.py

Core log analysis functions shared by all scripts.

**Key Functions:**
- `strip_ansi_codes(text)` - Remove ANSI escape codes
- `parse_timestamp(line)` - Extract timestamp from log line
- `parse_time_to_ms(time_str)` - Parse time strings to milliseconds
- `find_block_range(log_file)` - Detect steady-state block range
- `parse_log_file(log_file, block_range)` - Extract timing metrics
- `compute_statistics(times)` - Compute mean, median, min, max, std_dev
- `build_summary(log_file, block_range, metrics)` - Build metrics summary
- `analyze_log(log_file, label)` - Analyze a single log file

## Metrics

The analysis extracts these timing metrics from logs:

1. **Build Payload Time** - Total time to build a payload (from "Built payload" log)
2. **Execution Time** - Execution phase duration (from `execution_elapsed` field)
3. **Payload Finalization** - Builder finish phase duration captured by `builder_finish_elapsed` (includes inline state root when applicable)
4. **State Root Task** - Explicit state root task duration (from "State root task finished" log)
5. **Payload Delivery Lag** - Time between "Built payload" and "Received block from consensus engine"
6. **Block Added to Canonical Chain** - Total time to add block to chain (from "Block added" log)

## Block Filtering

The analysis automatically detects steady-state blocks based on:
- Transaction count > 1 (excludes warmup blocks with 0-1 tx)
- Gas usage > 1000 gas (excludes minimal blocks)
- Excludes block #1 (genesis block)

The detected block range is printed at the start of analysis.

## Output Format

Metrics are saved to JSON files with this structure:

```json
{
  "label": "main",
  "log_file": "debug_main.log",
  "block_range": [21842, 21852],
  "metrics": {
    "Build Payload Time": {
      "count": 11,
      "mean": 427.556,
      "median": 419.122,
      "min": 32.809,
      "max": 771.622,
      "std_dev": 192.807
    },
    ...
  }
}
```

All timing values are in milliseconds.
