#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["matplotlib==3.10.8"]
# ///
"""Validate and plot executed receipt gas, never debug-build wall-clock performance.

uv run scripts/plot-tip-1086-tree.py --root-log /tmp/tree.log --baseline-log /tmp/baseline.log
Omit log flags to reproduce plots/report from committed CSVs.
"""
import argparse
import csv
import io
import itertools
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / "docs/benchmarks"
CAP = 12_000_000_000
CURVES = ["Secp", "P256", "WebAuthn"]
POLICIES = ["Unlimited", "Lifetime cap", "Periodic cap", "2 caps + 2 targets"]
ACTIVE = [1, 2, 4, 8, 16, 64, 256]

def fee(gas):
    return (int(gas) * CAP + 10**12 - 1) // 10**12

def save(name, rows):
    with (OUT / name).open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

def read(name):
    with (OUT / name).open(newline="") as stream:
        return list(csv.DictReader(stream))

def extract(log, prefix):
    lines = []
    for line in Path(log).read_text().splitlines():
        if prefix in line:
            lines.append(line.split(prefix, 1)[1])
    return list(csv.DictReader(io.StringIO("\n".join(lines))))

def main():
    args = argparse.ArgumentParser()
    args.add_argument("--root-log")
    args.add_argument("--baseline-log")
    opts = args.parse_args()
    if opts.root_log:
        for prefix, name in [("TREE_COST,", "tip-1086-tree.csv"),
                             ("TREE_EDGE,", "tip-1086-tree-edges.csv"),
                             ("TREE_FAILURE,", "tip-1086-tree-failures.csv")]:
            save(name, extract(opts.root_log, prefix))
    if opts.baseline_log:
        lines = Path(opts.baseline_log).read_text().splitlines()
        assert any("BASELINE_BASEFEE,12000000000" in line for line in lines)
        header = "mode,parent,delegate,sponsored,policy,phase,authorization_bytes,gas,keychain_words_created,execution_us"
        rows = [line for line in lines if line.startswith(("stored,", "carried,")) and len(line.split(",")) == 10]
        save("tip-1086-tree-baseline.csv", list(csv.DictReader(io.StringIO(header + "\n" + "\n".join(rows)))))
    rows = read("tip-1086-tree.csv")
    edges = read("tip-1086-tree-edges.csv")
    failures = read("tip-1086-tree-failures.csv")
    baseline = read("tip-1086-tree-baseline.csv")
    keys = ["parent", "delegate", "sponsored", "policy", "active", "fresh", "phase"]
    matrix = {tuple(r[k] for k in keys): r for r in rows}
    expected = set(itertools.product(CURVES, [f"{c}-{n}" for c in CURVES for n in ["false", "true"]],
                   ["false", "true"], map(str, range(4)), map(str, ACTIVE), ["false"], map(str, range(3))))
    expected |= {k[:4] + ("1", "true", k[-1]) for k in expected}
    assert len(rows) == len(matrix) == 3456 and set(matrix) == expected
    assert all(int(r["micro_pathusd"]) == fee(r["gas"]) for r in rows + failures)
    assert len(edges) == 32 and len(failures) == 18 and len(baseline) == 1728
    assert sum(r["status"] == "rejected-size" for r in edges) == 4
    assert all((int(r["gas"]) > 0) == (r["status"] == "success") for r in edges)
    bk = ["mode", "parent", "delegate", "sponsored", "policy", "phase"]
    bm = {tuple(r[k] for k in bk): r for r in baseline}
    assert len(bm) == 1728

    def root(p, phase, active=1, sponsored=False, delegate="Secp-false", parent="Secp", fresh=False):
        return int(matrix[(parent, delegate, str(sponsored).lower(), str(p), str(active), str(fresh).lower(), str(phase))]["gas"])

    def old(mode, p, phase, sponsored=False):
        return int(bm[(mode, "Secp-true", "Secp-false", str(sponsored).lower(), str(p), str(phase))]["gas"])

    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    fig, axes = plt.subplots(2, 2, figsize=(13, 8))
    for p, ax in enumerate(axes.flat):
        for i, (name, color) in enumerate([("stored", "#667085"), ("carried", "#bc7930"), ("root", "#087f8c")]):
            values = [fee(root(p, phase) if name == "root" else old(name, p, phase)) / 1e6 for phase in range(3)]
            ax.bar([x + (i-1)*.24 for x in range(3)], values, width=.23, color=color, label={"stored":"Stored", "carried":"V1 carried", "root":"V2 root (1 active)"}[name])
        ax.axhline(.001, ls="--", c="#a33131", label="$0.001 signing reference")
        ax.set_title(POLICIES[p]); ax.set_xticks(range(3), ["First", "Repeat", "Later/rollover"])
        ax.set_ylabel("Full transaction fee ($)"); ax.grid(axis="y", alpha=.15)
    axes[0,0].legend(fontsize=8)
    fig.suptitle("Executed fees at Tempo's 12 cap: one configurable secp owner, primitive secp delegate\nSelf-paid transfer; registered parent; zero per-policy persistent writes in V2", fontsize=13)
    fig.text(.02,.01,"Receipt gas, zero priority fee, microUSD rounding. Signing-service reference excludes its chain fees; not equivalent total service cost.", fontsize=9)
    fig.tight_layout(rect=[0,.035,1,.93]); fig.savefig(OUT/"tip-1086-tree-costs.png", dpi=170)

    fig2, axes = plt.subplots(1, 2, figsize=(13,6))
    for p in range(4):
        for sponsored, style in [(False,"-"),(True,"--")]:
            for ax, phase in zip(axes,[0,1]):
                ax.plot(ACTIVE, [fee(root(p,phase,n,sponsored))/1e6 for n in ACTIVE], style,
                        marker="o", label=f"{POLICIES[p]}, {'sponsored' if sponsored else 'self-paid'}")
    for ax,title in zip(axes,["First use","Repeat use"]):
        ax.set_xscale("log",base=2); ax.set_xticks(ACTIVE,[str(n) for n in ACTIVE]); ax.set_xlabel("Active policies after installation")
        ax.set_ylabel("Full fee ($)"); ax.axhline(.001,ls=":",c="#a33131",label="$0.001 signing-only reference"); ax.set_title(title); ax.grid(alpha=.15)
    fig2.legend(*axes[0].get_legend_handles_labels(),loc="lower center",ncol=3,fontsize=8)
    fig2.suptitle("Measured proof-size tradeoff at the cap — configurable secp parent / primitive secp delegate")
    fig2.tight_layout(rect=[0,.16,1,.95]); fig2.savefig(OUT/"tip-1086-tree-scaling.png", dpi=170)
    with PdfPages(OUT/"tip-1086-tree-plots.pdf") as pdf:
        pdf.savefig(fig); pdf.savefig(fig2)

    text = ["# Executed V2 account-root benchmark results", "", "Executed on the implementation committed with these artifacts; see git history for the exact code revision.",
            "Stack: configurable-account activation (`joshie/configurable-activation`) → carried V1 → V2 root.", "",
            "3,456 V2 matrix receipts, 28 successful edge receipts plus four oversized-certificate rejections,",
            "18 failed-batch receipts, and a freshly executed 1,728-row stored/V1 baseline. Every V2 execution",
            "asserts no persistent AccountKeychain writes and checks the receipt-reconstructed tree against R.", "",
            "## Representative costs", "", "Configurable 1-owner secp256k1 parent, primitive secp256k1 delegate; one active policy; registered parent; self-paid.", "",
            "| Policy | Stored first | V1 first | V2 first | V2 repeat | V2 later |", "|---|---:|---:|---:|---:|---:|"]
    for p in range(4):
        values = [old("stored",p,0),old("carried",p,0),root(p,0),root(p,1),root(p,2)]
        text.append("| " + POLICIES[p] + " | " + " | ".join(f"{g:,} gas / ${fee(g)/1e6:.6f}" for g in values) + " |")
    text += ["", f"Lifetime-cap first-use gas falls {100*(1-root(1,0)/old('carried',1,0)):.2f}% versus V1, but reuse costs {root(1,1)-old('carried',1,1):,} more gas.",
             "Unlimited V1 has no counter allocation to remove and is cheaper than V2 here. Constant account state is not universally the lowest fee."]
    text += ["", "## Active policies and sponsorship", "", "Lifetime-cap policy, same actors. Fresh=true means an unregistered configuration on an already funded account;",
             "the new-accounts edge separately starts both native account records at nonce zero with empty extensions.", "",
             "| Active | Self first | Self repeat | Sponsored first | Sponsored repeat |", "|---:|---:|---:|---:|---:|"]
    for n in ACTIVE:
        text.append(f"| {n} | " + " | ".join(f"${fee(root(1,phase,n,s))/1e6:.6f}" for s,phase in [(False,0),(False,1),(True,0),(True,1)]) + " |")
    below = sum(int(r["micro_pathusd"]) < 1000 for r in rows)
    text += ["", f"{below:,}/{len(rows):,} matrix receipts are strictly below the $0.001 reference; **not all cases are cheaper**.",
             "Large quorums, broad policies, multiple calls, fresh configuration and deeper proofs remain explicit costs.",
             "Root commitment removes per-policy counter allocation, not transaction execution, signatures, proof publication, or mutable-root updates.", "",
             "[Privy's pricing](https://www.privy.io/pricing), checked 2026-09-11, advertises enterprise signatures as low as $0.001.",
             "That is a signature-service-only reference, not a universal price floor: free allowances, custody, issuance signatures,",
             "relay operation and vendor-backed transaction chain fees differ. No total-service-cost or throughput claim is made.", "",
             "## Measurement scope", "", "Root and main baseline matrix run with basefee=maxFeePerGas=12,000,000,000 attodollars/gas, zero priority fee.",
             "Fees use ceil(gas*price/10^12) microUSD. `bytes` is the complete carried authorization, not the whole transaction.",
             "Policies: 0 unlimited; 1 lifetime cap; 2 periodic cap; 3 two capped tokens plus two target scopes.",
             "Phases: 0 installation+transfer; 1 repeat; 2 later transfer (rollover only for policy 2). Prior unrelated leaves are seeded",
             "fixture state, not free installations. Matrix parents are native 1-owner accounts; all three parent and delegate curves",
             "are crossed with primitive/native delegates, both payer modes, all policies and 1/2/4/8/16/64/256 active leaves.",
             "Unused token limits remain in the committed usage vector; only the transferred/fee token changes.",
             "The 32 edge rows cover maximum-size WebAuthn, 8-owner secp and maximum-WebAuthn quorums, 32 tokens, 32 calls, 120 recipients, new accounts, and late first period.",
             "Eight-owner maximum-WebAuthn carried certificates exceed 4KB and are rejected, not assigned an imaginary successful gas cost.",
             "Failure cases perform a successful first transfer then scope/revert/out-of-gas failure, at 1/4/256 active leaves and both payer modes.", "",
             "Baseline `execution_us` is debug-build diagnostic timing only; it is not a calibrated performance benchmark.",
             "V2 meter constants are draft candidates; production calibration, independent security review, reorg integration,",
             "a deployed witness service and automatic client proof refresh remain outside this local implementation/receipt validation.", "",
             "## Validation", "", "Affected library suites: 159 tempo-alloy, 1,019 tempo-precompiles, 283 tempo-primitives and 243 tempo-revm tests passed (1,704 total).",
             "Root matrix/lifecycle run: eight tests passed including both ignored receipt generators. Fresh baseline: three receipt generators passed.",
             "Nightly fmt check and clippy for the four affected libraries passed; existing unrelated clippy warnings remain.",
             "The precompile suite requires `--features test-utils`; without it, existing ABI-conformance test imports are unavailable.", "",
             "## Reproduce", "", "```sh", "CARGO_PROFILE_DEV_DEBUG=0 cargo test -p tempo-revm --lib account_tree --locked -j 4 -- --include-ignored --nocapture > /tmp/tree.log 2>&1",
             "CARGO_PROFILE_DEV_DEBUG=0 cargo test -p tempo-revm --lib carried_cost_ --locked -j 4 -- --ignored --nocapture --test-threads=1 > /tmp/baseline.log 2>&1",
             "uv run scripts/plot-tip-1086-tree.py --root-log /tmp/tree.log --baseline-log /tmp/baseline.log", "```", "",
             "[Implementation and wire rules](tip-1086-tree-implementation.md) · [matrix](tip-1086-tree.csv) · [baseline](tip-1086-tree-baseline.csv)",
             "· [edges](tip-1086-tree-edges.csv) · [failures](tip-1086-tree-failures.csv) · [plots](tip-1086-tree-plots.pdf)"]
    (OUT/"tip-1086-tree-results.md").write_text("\n".join(text)+"\n")
    print(f"Validated {len(rows)} matrix + {len(edges)} edge + {len(failures)} failure + {len(baseline)} baseline rows; {below} root receipts < $0.001")

if __name__ == "__main__":
    main()
