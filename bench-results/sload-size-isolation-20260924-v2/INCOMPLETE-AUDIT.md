# Load complete, required audit incomplete

The first 4096-read/prewarming-on load completed with its intended binary,
fixture, cold-start policy and 20 GiB/no-swap limits. Post-load auditing failed
because no three non-first transaction samples existed: all candidate blocks
contained a single workload transaction. No completed four-way comparison was
produced, and this attempt is excluded from the final verified results.

The corrected runner explicitly allows first-transaction cold-read samples for
the large-SLOAD diagnostic control only, records their sampling policy, and
retains the small case's 90% history-coverage gate. Replacement runs start from
fresh fixture restores under `../sload-size-isolation-20260924-v3`.
