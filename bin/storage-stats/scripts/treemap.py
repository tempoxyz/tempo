#!/usr/bin/env python3
"""
Generate an interactive treemap visualization of Tempo state distribution.

Similar to Paradigm's "Distribution of Ethereum State" chart from:
https://github.com/paradigmxyz/how-to-raise-the-gas-limit

Usage:
    # Generate JSON from storage-stats CLI
    storage-stats --db /path/to/db --format json > state.json
    
    # Generate treemap
    python treemap.py state.json --output state_treemap.html
    
    # Or pipe directly
    storage-stats --db /path/to/db --format json | python treemap.py - --output state.html
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import plotly.graph_objects as go
except ImportError:
    print("Error: plotly is required. Install with: pip install plotly", file=sys.stderr)
    sys.exit(1)


# Color palette for categories (similar to Paradigm's style)
CATEGORY_COLORS = {
    "Tokens": "#3366CC",
    "Token Infrastructure": "#6699FF", 
    "DEX": "#DC3912",
    "Fee Infrastructure": "#FF9900",
    "Compliance": "#109618",
    "Account Abstraction": "#990099",
    "Consensus": "#0099C6",
    "Utilities": "#DD4477",
    "Other": "#66AA00",
}


def load_data(input_path: str) -> list:
    """Load JSON data from file or stdin."""
    if input_path == "-":
        data = json.load(sys.stdin)
    else:
        with open(input_path) as f:
            data = json.load(f)
    return data


def build_treemap_data(stats: list) -> dict:
    """
    Build hierarchical data structure for Plotly treemap.
    
    Input: List of AddressStats objects from storage-stats CLI
    Output: Dict with labels, parents, values, colors, and custom data
    """
    # Group by category
    categories = {}
    for item in stats:
        cat = item.get("category", "Other")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(item)
    
    # Calculate totals
    total_mb = sum(item.get("total_mb", 0) for item in stats)
    
    # Build hierarchical structure
    labels = ["Tempo State"]
    parents = [""]
    values = [total_mb]
    colors = ["#FFFFFF"]
    customdata = [f"Total: {total_mb:.2f} MB"]
    
    for cat_name, items in sorted(categories.items(), key=lambda x: -sum(i.get("total_mb", 0) for i in x[1])):
        cat_total = sum(item.get("total_mb", 0) for item in items)
        cat_slots = sum(item.get("storage_slots", 0) for item in items)
        cat_color = CATEGORY_COLORS.get(cat_name, "#999999")
        
        # Add category node
        labels.append(cat_name)
        parents.append("Tempo State")
        values.append(cat_total)
        colors.append(cat_color)
        customdata.append(f"{cat_total:.2f} MB | {cat_slots:,} slots")
        
        # Sort items by size and add top entries
        sorted_items = sorted(items, key=lambda x: -x.get("total_mb", 0))
        
        for item in sorted_items[:50]:  # Top 50 per category
            label = item.get("label", item.get("address", "Unknown")[:10])
            addr = item.get("address", "")
            mb = item.get("total_mb", 0)
            slots = item.get("storage_slots", 0)
            
            # Truncate long labels
            if len(label) > 20:
                label = label[:17] + "..."
            
            labels.append(label)
            parents.append(cat_name)
            values.append(mb)
            colors.append(cat_color)
            customdata.append(f"{addr}<br>{mb:.3f} MB | {slots:,} slots")
    
    return {
        "labels": labels,
        "parents": parents,
        "values": values,
        "colors": colors,
        "customdata": customdata,
    }


def create_treemap(data: dict, title: str = "Distribution of Tempo State") -> go.Figure:
    """Create Plotly treemap figure."""
    fig = go.Figure(go.Treemap(
        labels=data["labels"],
        parents=data["parents"],
        values=data["values"],
        marker=dict(
            colors=data["colors"],
            line=dict(width=1, color="white"),
        ),
        customdata=data["customdata"],
        hovertemplate="<b>%{label}</b><br>%{customdata}<extra></extra>",
        textposition="middle center",
        textfont=dict(size=14),
        pathbar=dict(visible=True),
        branchvalues="total",
    ))
    
    total_mb = data["values"][0]
    
    fig.update_layout(
        title=dict(
            text=f"{title}<br><sup>Total: {total_mb:.2f} MB</sup>",
            font=dict(size=24),
            x=0.5,
            xanchor="center",
        ),
        margin=dict(t=80, l=10, r=10, b=10),
        height=700,
        font=dict(family="Inter, sans-serif"),
    )
    
    return fig


def main():
    parser = argparse.ArgumentParser(
        description="Generate treemap visualization of Tempo state distribution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "input",
        help="JSON file from storage-stats CLI (use '-' for stdin)",
    )
    parser.add_argument(
        "--output", "-o",
        default="state_treemap.html",
        help="Output HTML file (default: state_treemap.html)",
    )
    parser.add_argument(
        "--title", "-t",
        default="Distribution of Tempo State",
        help="Chart title",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Open in browser after generating",
    )
    
    args = parser.parse_args()
    
    # Load data
    print(f"Loading data from {args.input}...", file=sys.stderr)
    stats = load_data(args.input)
    
    if not stats:
        print("Error: No data found in input", file=sys.stderr)
        sys.exit(1)
    
    print(f"Processing {len(stats)} entries...", file=sys.stderr)
    
    # Build treemap data
    treemap_data = build_treemap_data(stats)
    
    # Create figure
    fig = create_treemap(treemap_data, title=args.title)
    
    # Save to HTML
    output_path = Path(args.output)
    fig.write_html(
        str(output_path),
        include_plotlyjs=True,
        full_html=True,
        config={"displayModeBar": True, "responsive": True},
    )
    print(f"Saved treemap to {output_path}", file=sys.stderr)
    
    if args.show:
        fig.show()


if __name__ == "__main__":
    main()
