# Excluded: generator preset parse failure

Both nodes restored cold and passed priming and near-cap bytecode calibration.
The generator rejected a malformed fee-token address in history_code_max.yml
before sending any transactions (sent=0). There is no measured load in this
attempt. The original failed manifest and logs are retained unchanged.

The preset address was corrected to the existing public benchmark fee token;
address assertions and real offline generation cover both near-cap presets.
The bytecode workload is rerun from fresh cold restores in v4. No measured
SLOAD input changed: the bytecode preset is not used by the SLOAD workload.
