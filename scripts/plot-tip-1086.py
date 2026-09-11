#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["matplotlib==3.10.8"]
# ///
"""Plot committed TIP-1086 receipts; never use debug timings as performance data.

Run: uv run scripts/plot-tip-1086.py
Use --input-dir with CSVs from another execution, or --output-dir for scratch output.
"""

import argparse
import csv
from itertools import product
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.ticker import FuncFormatter

PRICE = 600_000_000  # attodollars / gas, the fixture price, not a live quote
SIGNATURE_MICRO = 1_000  # advertised Privy enterprise reference, not every plan
POLICIES = ["Unlimited", "Lifetime cap", "Periodic cap", "2 caps + 2 targets"]
ACTORS = [
    f"{curve}-{native}"
    for curve in ["Secp", "P256", "WebAuthn"]
    for native in ["false", "true"]
]
STORED, CARRIED, VENDOR = "#667085", "#087f8c", "#bd441b"


def fee_micro(gas):
    """Round each transaction up to one token micro-unit, as the protocol does."""
    return (gas * PRICE + 10**12 - 1) // 10**12


def strict_break_even(stored_first, carried_first, stored_repeat, carried_repeat):
    saving = stored_first - carried_first
    premium = carried_repeat - stored_repeat
    if saving < 0:
        return 1
    if premium <= 0:
        return None
    return saving // premium + 2


def read_csv(path):
    with path.open(newline="") as source:
        return list(csv.DictReader(source))


def write_csv(path, rows):
    with path.open("w", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def load_data(directory):
    rows = read_csv(directory / "tip-1086.csv")
    keys = ("mode", "parent", "delegate", "sponsored", "policy", "phase")
    matrix = {tuple(row[key] for key in keys): row for row in rows}
    expected = set(
        product(
            ["stored", "carried"],
            ACTORS,
            ACTORS,
            ["false", "true"],
            map(str, range(4)),
            map(str, range(3)),
        )
    )
    assert len(rows) == len(matrix) == 1728 and set(matrix) == expected
    assert all(int(row["gas"]) > 0 for row in rows)
    edges = read_csv(directory / "tip-1086-edges.csv")
    assert len(edges) == 32
    assert len({(r["edge"], r["mode"], r["sponsored"]) for r in edges}) == 32
    assert all((int(r["gas"]) > 0) == (r["status"] == "success") for r in edges)
    failures = read_csv(directory / "tip-1086-failures.csv")
    assert len(failures) == 24
    assert (
        len(
            {
                (r["failure"], r["mode"], r["configurable"], r["sponsored"])
                for r in failures
            }
        )
        == 24
    )
    assert all(int(r["gas"]) > 0 for r in failures)
    return matrix, rows, edges, failures


def gas(matrix, mode, policy, phase, native="false", sponsored="false"):
    return int(
        matrix[
            (
                mode,
                f"Secp-{native}",
                f"Secp-{native}",
                sponsored,
                str(policy),
                str(phase),
            )
        ]["gas"]
    )


def comparisons(matrix):
    result = []
    for parent, delegate, sponsored, policy in product(
        ACTORS, ACTORS, ["false", "true"], range(4)
    ):
        values = [
            int(
                matrix[(mode, parent, delegate, sponsored, str(policy), str(phase))][
                    "gas"
                ]
            )
            for mode, phase in [
                ("stored", 0),
                ("carried", 0),
                ("stored", 1),
                ("carried", 1),
            ]
        ]
        sf, cf, sr, cr = values
        rounded = list(map(fee_micro, values))
        # Periodic rows have different anchors and a first-nonzero-window write.
        # Do not extrapolate their repeat sample to a lifetime crossover.
        gas_break = strict_break_even(*values) if policy != 2 else None
        fee_break = strict_break_even(*rounded) if policy != 2 else None
        for costs, crossing in [(values, gas_break), (rounded, fee_break)]:
            if crossing is not None:
                s_first, c_first, s_repeat, c_repeat = costs
                assert (
                    s_first + (crossing - 1) * s_repeat
                    < c_first + (crossing - 1) * c_repeat
                )
                if crossing > 1:
                    assert (
                        s_first + (crossing - 2) * s_repeat
                        >= c_first + (crossing - 2) * c_repeat
                    )
        no_crossing = "window-dependent" if policy == 2 else "none-under-repeat-model"
        result.append(
            {
                "parent": parent,
                "delegate": delegate,
                "sponsored": sponsored,
                "policy": policy,
                "stored_first_gas": sf,
                "carried_first_gas": cf,
                "stored_repeat_gas": sr,
                "carried_repeat_gas": cr,
                "stored_later_gas": int(
                    matrix[("stored", parent, delegate, sponsored, str(policy), "2")][
                        "gas"
                    ]
                ),
                "carried_later_gas": int(
                    matrix[("carried", parent, delegate, sponsored, str(policy), "2")][
                        "gas"
                    ]
                ),
                "first_saving_percent": f"{100 * (sf - cf) / sf:.4f}",
                "stored_cheaper_from_use_gas": gas_break or no_crossing,
                "stored_cheaper_from_use_rounded_fee": fee_break or no_crossing,
                "carried_first_micro_pathusd": rounded[1],
                "carried_repeat_micro_pathusd": rounded[3],
                "first_fee_headroom_to_1000_micro": SIGNATURE_MICRO - rounded[1],
            }
        )
    return result


def dollar_axis(axis):
    axis.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"${value:,.5f}"))
    axis.grid(axis="y", alpha=0.18)
    axis.set_axisbelow(True)


def footer(fig):
    fig.text(
        0.04,
        0.015,
        "Fixture price: 600,000,000 attodollars/gas; per-transaction micro-unit rounding. "
        "pathUSD treated as $1.\n"
        "Privy: advertised $0.001/signature reference, excludes chain fees; free tier/contract terms differ. "
        "No relay, custody, or production-throughput measurement.",
        fontsize=8,
        color="#475467",
    )


def overview(matrix, rows):
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(
        "TIP-1086: first use, reuse, and the signing-cost target",
        fontsize=19,
        x=0.04,
        ha="left",
    )
    x = list(range(4))
    for axis, native, title in [
        (axes[0, 0], "false", "Primitive parent + delegate"),
        (axes[0, 1], "true", "Configurable parent + delegate (1 owner each)"),
    ]:
        for mode, offset, color in [
            ("stored", -0.18, STORED),
            ("carried", 0.18, CARRIED),
        ]:
            values = [
                fee_micro(gas(matrix, mode, policy, 0, native)) / 1e6 for policy in x
            ]
            bars = axis.bar(
                [i + offset for i in x],
                values,
                width=0.34,
                label=mode.title(),
                color=color,
            )
            axis.bar_label(
                bars, labels=[f"${v:.6f}" for v in values], fontsize=8, padding=3
            )
        axis.axhline(0.001, color=VENDOR, linestyle="--", label="Privy signature only")
        axis.set(
            title=f"First transaction · {title}",
            xticks=x,
            xticklabels=POLICIES,
            ylim=(0, 0.00195),
            ylabel="Chain fee at fixture price",
        )
        axis.tick_params(axis="x", labelsize=9)
        dollar_axis(axis)
    axes[0, 0].legend(fontsize=8, loc="upper left")

    axis = axes[1, 0]
    counts = list(range(1, 201))
    totals = {}
    for mode, color in [("stored", STORED), ("carried", CARRIED)]:
        first = fee_micro(gas(matrix, mode, 3, 0))
        repeat = fee_micro(gas(matrix, mode, 3, 1))
        totals[mode] = [(first + (n - 1) * repeat) / 1e6 for n in counts]
        axis.plot(counts, totals[mode], label=f"{mode.title()} chain fees", color=color)
    axis.plot(
        counts,
        [v + 0.001 for v in totals["carried"]],
        color=CARRIED,
        linestyle=":",
        label="Carried + one paid certificate signature",
    )
    axis.plot(
        counts,
        [n * 0.001 for n in counts],
        color=VENDOR,
        linestyle="--",
        label="Privy signature per transaction; chain fees extra",
    )
    axis.set(
        xscale="log",
        yscale="log",
        xlabel="Transactions using one grant",
        ylabel="Cumulative cost (log scale)",
        title="Two caps + two targets · primitive · sender pays",
    )
    axis.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"${value:g}"))
    axis.grid(alpha=0.18)
    axis.legend(fontsize=8)

    axis = axes[1, 1]
    for phase, label, color in [
        (0, "First use", CARRIED),
        (1, "Repeat", "#8254b0"),
        (2, "Later timestamp / periodic rollover", "#e7a33e"),
    ]:
        values = sorted(
            fee_micro(int(r["gas"])) / 1e6
            for r in rows
            if r["mode"] == "carried" and r["phase"] == str(phase)
        )
        axis.plot(range(1, len(values) + 1), values, label=label, color=color)
    axis.axhline(0.001, color=VENDOR, linestyle="--", label="Privy signature only")
    axis.set(
        xlabel="Scenario rank (sorted separately for each phase)",
        ylabel="Carried chain fee",
        ylim=(0, 0.0011),
        title="All 288 carried scenarios × 3 phases",
    )
    dollar_axis(axis)
    axis.legend(fontsize=8, loc="center left")
    fig.subplots_adjust(
        left=0.07, right=0.98, top=0.91, bottom=0.12, hspace=0.40, wspace=0.28
    )
    footer(fig)
    return fig


def boundary_plot(edges, failures):
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(
        "TIP-1086: setup, boundaries, and failed execution",
        fontsize=19,
        x=0.04,
        ha="left",
    )
    names = list(dict.fromkeys(r["edge"] for r in edges))
    for col, sponsored in enumerate(["false", "true"]):
        axis = axes[0, col]
        for mode, offset, color in [
            ("stored", -0.18, STORED),
            ("carried", 0.18, CARRIED),
        ]:
            data = [
                next(
                    r
                    for r in edges
                    if r["edge"] == edge
                    and r["mode"] == mode
                    and r["sponsored"] == sponsored
                )
                for edge in names
            ]
            values = [
                fee_micro(int(r["gas"])) / 1e6
                if r["status"] == "success"
                else float("nan")
                for r in data
            ]
            axis.barh(
                [i + offset for i in range(len(names))],
                values,
                height=0.34,
                label=mode.title(),
                color=color,
            )
            for i, row in enumerate(data):
                if row["status"] != "success":
                    axis.text(
                        0.00001,
                        i + offset,
                        "REJECTED: exceeds transaction gas cap",
                        fontsize=7,
                        va="center",
                        color=VENDOR,
                    )
        axis.set(
            yticks=range(len(names)),
            yticklabels=names,
            title="Sponsor pays" if sponsored == "true" else "Sender pays",
            xlabel="Chain fee at fixture price",
        )
        axis.invert_yaxis()
        axis.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f"${value:.4f}"))
        axis.tick_params(axis="y", labelsize=8)
        axis.grid(axis="x", alpha=0.18)
        axis.legend(fontsize=8, loc="lower right")
        axis = axes[1, col]
        categories = list(product(["scope", "revert", "out-of-gas"], ["false", "true"]))
        for mode, offset, color in [
            ("stored", -0.18, STORED),
            ("carried", 0.18, CARRIED),
        ]:
            values = [
                fee_micro(
                    int(
                        next(
                            r
                            for r in failures
                            if r["failure"] == failure
                            and r["configurable"] == native
                            and r["mode"] == mode
                            and r["sponsored"] == sponsored
                        )["gas"]
                    )
                )
                / 1e6
                for failure, native in categories
            ]
            axis.bar(
                [i + offset for i in range(len(categories))],
                values,
                width=0.34,
                color=color,
                label=mode.title(),
            )
        axis.set(
            xticks=range(len(categories)),
            xticklabels=[
                f"{failure}\n{'config.' if native == 'true' else 'primitive'}"
                for failure, native in categories
            ],
            title="Failed executions · initialized grant · 500,000 gas limit",
            ylabel="Charged chain fee",
        )
        axis.tick_params(axis="x", labelsize=8)
        dollar_axis(axis)
    fig.subplots_adjust(
        left=0.15, right=0.98, top=0.90, bottom=0.12, hspace=0.40, wspace=0.65
    )
    footer(fig)
    return fig


def write_report(path, matrix, rows, edges, table):
    carried = [int(r["gas"]) for r in rows if r["mode"] == "carried"]
    maximum = max(carried + [int(r["gas"]) for r in edges if r["mode"] == "carried"])
    sample = next(
        r
        for r in table
        if r["parent"] == r["delegate"] == "Secp-false"
        and r["sponsored"] == "false"
        and r["policy"] == 3
    )
    first_fee = sample["carried_first_micro_pathusd"]
    repeat_fee = sample["carried_repeat_micro_pathusd"]
    sponsor_repeat = gas(matrix, "carried", 3, 1, sponsored="true")
    batch_gas = int(
        next(
            r
            for r in edges
            if r["edge"] == "32-calls"
            and r["mode"] == "carried"
            and r["sponsored"] == "false"
        )["gas"]
    )
    lines = [
        "# TIP-1086 cost decisions",
        "",
        (
            "Generated by `uv run scripts/plot-tip-1086.py` from the committed receipt CSVs. "
            "This is a fee analysis of the draft, not a new execution or a throughput benchmark."
        ),
        "",
        "![First use and lifecycle](tip-1086-costs.png)",
        "",
        (
            "[Two-page chart PDF](tip-1086-plots.pdf) · [All 288 scenario comparisons](tip-1086-comparisons.csv) · "
            "[Receipt methodology](tip-1086.md)"
        ),
        "",
        "## Signing-cost target",
        "",
        (
            "[Privy pricing](https://www.privy.io/pricing), checked 2026-09-11, advertises enterprise pricing "
            "as low as $0.001/signature. Developer plans include 50,000 monthly signatures; the listed "
            "signature overage is $0.01, with other plan/base charges. The plotted $0.001 is a paid "
            "reference price, not a universal minimum or a quote for a particular customer."
        ),
        "",
        (
            f"All **{len(carried)} carried main-matrix receipts and 16 carried boundary receipts** have chain fees "
            f"below $0.001 at the fixture price, treating pathUSD as $1. The largest is **{maximum:,} gas / "
            f"{fee_micro(maximum) / 1e6:.6f} pathUSD**. Invalid transactions are not zero-cost alternatives."
        ),
        "",
        (
            "These are full chain fees compared with a signature-service fee alone. Privy-backed transactions "
            "also pay chain fees; carried grants still need a signing/retention system. Relay, custody, key "
            "management, free allowances, and contract pricing are not measured. This is not proof of lower "
            "total service cost or equivalent service guarantees."
        ),
        "",
        (
            "If Privy signs the certificate once, add that issuance charge upfront. For a primitive issuer "
            f"and one $0.001 issuance signature, the representative carried first use totals ${(1000 + first_fee) / 1e6:.6f}; "
            f"two uses total ${(1000 + first_fee + repeat_fee) / 1e6:.6f}, versus $0.002 for two paid vendor signatures before their chain fees. "
            "A quorum can require multiple paid issuance signatures. These examples assume subsequent "
            "delegate signatures incur no vendor fee; using a paid service for every delegate signature "
            "retains its per-transaction charge."
        ),
        "",
        "## Choose the mode before issuing the grant",
        "",
        (
            "First use is cheaper with carried mode in every paired main-matrix scenario. For repeated "
            "non-periodic use, upfront stored registration can amortize. The CSV reports exact crossover "
            "counts for gas and separately for per-transaction rounded fees; they need not be equal."
        ),
        "",
        (
            f"For primitive sender-paid two-cap/two-target grants, the gas crossover is use "
            f"**{sample['stored_cheaper_from_use_gas']}**, while the rounded-fee crossover is use "
            f"**{sample['stored_cheaper_from_use_rounded_fee']}** at this fixture price."
        ),
        "",
        "| Policy | Fee payer | Carried first (pathUSD) | Carried repeat (pathUSD) | Stored cheaper from use (gas / fee) |",
        "|---|---|---:|---:|---:|",
    ]
    for row in table:
        if row["parent"] != "Secp-false" or row["delegate"] != "Secp-false":
            continue
        cross = (
            "Window-dependent"
            if row["policy"] == 2
            else (
                f"{row['stored_cheaper_from_use_gas']} / {row['stored_cheaper_from_use_rounded_fee']}"
            )
        )
        lines.append(
            f"| {POLICIES[row['policy']]} | {'Sponsor' if row['sponsored'] == 'true' else 'Sender'} | "
            f"{row['carried_first_micro_pathusd'] / 1e6:.6f} | "
            f"{row['carried_repeat_micro_pathusd'] / 1e6:.6f} | {cross} |"
        )
    lines += [
        "",
        (
            "Mode selection is a planning comparison, not an automatic migration strategy. Switching an "
            "existing carried key to stored mode invalidates its certificates and creates a separate "
            "budget. Keep the required policy intact; removing limits or quorum owners is not a like-for-like optimization."
        ),
        "",
        (
            "Sponsorship changes both who pays and the budget-accounting path. In the scoped primitive "
            f"fixture it changes carried repeat gas from {sample['carried_repeat_gas']:,} to {sponsor_repeat:,}, but a sponsor still pays that fee "
            "and may charge separately. First use should be compared using the same fee payer and account setup."
        ),
        "",
        (
            f"The measured 32-call carried batch uses {batch_gas:,} gas total ({batch_gas / 32:,.1f} gas per transfer on average). "
            "That amortizes one certificate, signature, and initial counter over a batch; independent "
            "transactions have different atomicity and latency, and batch-size scaling has not been measured here."
        ),
        "",
        (
            "Do not extrapolate periodic repeats through rollover. The signed anchor and the first nonzero "
            "window write change the result; stored and carried window semantics also differ. An access "
            "list is not a saving in the measured case. The 120-recipient stored setup exceeds the gas "
            "cap and is shown as rejected, not as free."
        ),
        "",
        "## Setup and failure coverage",
        "",
        "![Boundary and failure receipts](tip-1086-boundaries.png)",
        "",
        (
            "The first page shows representative paired costs and all 864 carried main-matrix receipts. "
            "The second page plots all 32 boundary rows and 24 failed receipts. "
            "The comparison CSV preserves all 1,728 main-matrix gas values across every curve, "
            "configurable-role combination, policy, phase and fee payer."
        ),
        "",
        "## Limits and further optimization",
        "",
        (
            "The existing implementation's major saving is avoiding immutable policy writes, while "
            "retaining required spending counters. This report changes no consensus gas constants. "
            "Further CPU optimizations need a carried-grant workload in the end-to-end benchmark "
            "generator; its current keychain scenario does not exercise this wire variant. "
            "Production hardware calibration and full-node/relay measurements remain outstanding. "
            "The debug `execution_us` column is deliberately excluded from all plots and decisions."
        ),
        "",
    ]
    path.write_text("\n".join(lines))


def main():
    default = Path(__file__).resolve().parents[1] / "docs" / "benchmarks"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=default)
    parser.add_argument("--output-dir", type=Path, default=default)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    matrix, rows, edges, failures = load_data(args.input_dir)
    table = comparisons(matrix)
    assert len(table) == 288
    assert all(float(r["first_saving_percent"]) > 0 for r in table)
    write_csv(args.output_dir / "tip-1086-comparisons.csv", table)
    write_report(
        args.output_dir / "tip-1086-cost-decisions.md", matrix, rows, edges, table
    )
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )
    with PdfPages(
        args.output_dir / "tip-1086-plots.pdf",
        metadata={
            "Title": "TIP-1086 receipt-gas cost analysis",
            "CreationDate": None,
            "ModDate": None,
        },
    ) as pdf:
        for name, figure in [
            ("tip-1086-costs", overview(matrix, rows)),
            ("tip-1086-boundaries", boundary_plot(edges, failures)),
        ]:
            figure.savefig(args.output_dir / f"{name}.png", dpi=160)
            pdf.savefig(figure)
            plt.close(figure)
    print(
        f"Validated 1,728 matrix + 32 boundary + 24 failure rows; wrote plots and 288 comparisons to {args.output_dir}"
    )


if __name__ == "__main__":
    main()
