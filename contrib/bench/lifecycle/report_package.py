"""Standalone focused pages and bounded, lossless context exports."""
from collections import defaultdict
from html import escape
import json
import re
import shutil
from pathlib import Path

from perfetto import write_trace

CHUNK_INTERVALS = 10_000


def write_page(data, path, links):
    template = Path(__file__).with_name('viewer.html').read_text()
    encoded = json.dumps(data, separators=(',', ':')).replace('<', '\\u003c')
    navigation = '<p><a href="index.html">Capture summary</a> · ' + ' · '.join(
        f'<a href="{escape(file)}">{escape(label)}</a>' for file, label in links) + '</p>'
    path.write_text(template.replace('__LIFECYCLE_DATA__', encoded).replace('__NAVIGATION__', navigation))


def write_package(data, out, chunk_intervals=CHUNK_INTERVALS, full=False):
    """Keep original intervals intact; context chunks partition all source records.

    Chunk membership follows start order and is bounded by record count, not
    duration. Long intervals can overlap several chunks' start ranges, but are
    stored exactly once. The manifest records each chunk's full time extent.
    """
    if chunk_intervals < 1:
        raise ValueError('chunk_intervals must be positive')
    out.mkdir(parents=True, exist_ok=True)
    for old in out.iterdir():
        if re.fullmatch(r'(?:context-\d+\.(?:html|json)|(?:block|attempt)-\d+\.html|perfetto(?:-(?:block|attempt)-\d+|-p(?:50|90|99))?\.json)', old.name):
            old.unlink()
    # The complete lifecycle.json retains global diagnostics. Focused pages and
    # context chunks carry only their selected block data to avoid multiplying
    # the global read-readiness payload into every HTML/Perfetto artifact.
    base = {k: v for k, v in data.items() if k not in ('spans', 'transfers', 'blocks', 'prewarm', 'read_readiness')}
    # Every standalone page needs the histogram, not every block's worker rows.
    # Full block details remain in lifecycle.json and each focused block page.
    base['population_blocks'] = [
        {key: b[key] for key in ('id', 'duration', 'in_population')}
        for b in data['blocks']]
    base['packaged'] = True
    base['capture_attempt_details'] = data.get('attempt_details', [])
    base['percentile_blocks'] = {} if data['bad_capture'] else data['representatives']
    block_spans, attempt_spans = defaultdict(list), defaultdict(list)
    lookup = {}
    records = []
    for s in data['spans']:
        block_spans[s['block']].append(s)
        if s.get('attempt') is not None:
            attempt_spans[s['attempt']].append(s)
        if not s.get('count'):
            lookup[(s['node'], s['id'])] = s
        records.append((s['start'], 'span', s))
    records.extend((t['start'], 'transfer', t) for t in data.get('transfers', []))
    for b in data['blocks']:
        records.extend((m['ts'], 'marker', (b['id'], m)) for m in b['markers'])
    unbound = [a for a in data.get('attempt_details', []) if not a.get('block')]
    for a in unbound:
        records.extend((m['ts'], 'attempt_marker', (a['id'], m)) for m in a['markers'])
    records.sort(key=lambda r: r[0])
    chunks = []
    for offset in range(0, len(records), chunk_intervals):
        part = records[offset:offset + chunk_intervals]
        spans, transfers, markers, attempt_markers = [], [], defaultdict(list), defaultdict(list)
        for _, kind, record in part:
            if kind == 'span': spans.append(record)
            elif kind == 'transfer': transfers.append(record)
            elif kind == 'marker': markers[record[0]].append(record[1])
            else: attempt_markers[record[0]].append(record[1])
        start = part[0][0]
        end = max([part[-1][0], *(s['end'] for s in spans), *(t['end'] for t in transfers)])
        stem = f'context-{len(chunks) + 1:04d}'
        chunk = dict(base, spans=spans, transfers=transfers,
                     blocks=[dict(b, markers=markers[b['id']]) for b in data['blocks'] if b['id'] in markers] +
                            [dict(a, id=None, attempt=a['id'], markers=attempt_markers[a['id']]) for a in unbound if a['id'] in attempt_markers])
        export = write_trace(chunk, out / f'{stem}.json')
        # A synthetic selection is a time window, never a percentile sample/block.
        selection = dict(id=0, start=start, end=end, duration=end-start, complete=True,
                         in_population=False, markers=[m for ms in [*markers.values(), *attempt_markers.values()] for m in ms], execution_totals=[])
        page = dict(chunk, blocks=[selection], attempt_details=[], representatives={}, context_chunk=True)
        write_page(page, out / f'{stem}.html', [(f'{stem}.json', 'This context chunk in Perfetto')])
        chunks.append(dict(file=f'{stem}.json', page=f'{stem}.html', start=start, end=end,
                           records=len(part), spans=len(spans), transfers=len(transfers),
                           markers=sum(map(len, markers.values())) + sum(map(len, attempt_markers.values())), **{k:v for k,v in export.items() if k != 'file'}))

    def focused(spans, selected, attempt=False):
        # Retain causal ancestors even when they have no block association.
        result = list(spans)
        included = {(s['node'], s['id']) for s in result if not s.get('count')}
        for s in list(result):
            key = (s['node'], s['parent'])
            while key not in included and key in lookup:
                parent = lookup[key]
                included.add(key)
                result.append(parent)
                key = (parent['node'], parent['parent'])
        transfers = [t for t in data.get('transfers', [])
                     if t['start'] < selected['end'] and t['end'] > selected['start']]
        return dict(base, spans=result, transfers=transfers,
                    blocks=[] if attempt else [selected],
                    attempt_details=[selected] if attempt else [],
                    focus_attempt=selected['id'] if attempt else None,
                    focus_block=None if attempt else selected['id'],
                    representatives={} if attempt else {p:i for p,i in data['representatives'].items() if i == selected['id']})

    pages = []
    for selected, attempt in [(b, False) for b in data['blocks']] + [
            (a, True) for a in data.get('attempt_details', []) if not a.get('block')]:
        identifier = selected['id']
        stem = f'attempt-{identifier}' if attempt else f'block-{identifier}'
        view = focused(attempt_spans[identifier] if attempt else block_spans[identifier], selected, attempt)
        trace = f'perfetto-{stem}.json'
        # Attempts carry markers too, without assigning a fictional block identity.
        trace_view = view if not attempt else dict(view, blocks=[dict(selected, id=None, attempt=selected['id'])])
        write_trace(trace_view, out / trace)
        low = min([selected['start'], *(s['start'] for s in view['spans'])])
        high = max([selected['end'], *(s['end'] for s in view['spans'])])
        overlaps = [c for c in chunks if c['start'] <= high and c['end'] >= low]
        links = [(trace, 'Focused Perfetto'), *[(c['page'], f"Context {c['start']:.1f}–{c['end']:.1f} ms") for c in overlaps]]
        write_page(view, out / f'{stem}.html', links)
        pages.append(dict(file=f'{stem}.html', trace=trace, id=identifier, attempt=attempt,
                          spans=len(view['spans']), context=[c['file'] for c in overlaps]))
    percentiles = []
    for p in (50, 90, 99):
        path = out / f'perfetto-p{p}.json'
        selected = data['representatives'].get(str(p))
        if selected is not None and not data['bad_capture']:
            # Copy bytes instead of rebuilding/sorting the same selected block.
            shutil.copyfile(out / f'perfetto-block-{selected}.json', path)
            percentiles.append(dict(percentile=p, block=selected, trace=path.name, page=f'block-{selected}.html'))
        elif path.exists():
            path.unlink()
    if full:
        write_trace(dict(data, blocks=data['blocks'] + [dict(a, id=None, attempt=a['id']) for a in unbound]), out / 'perfetto.json')
    manifest = dict(schema=1, chunk_interval_limit=chunk_intervals, chunks=chunks, pages=pages,
                    percentiles=percentiles, full_trace='perfetto.json' if (out/'perfetto.json').exists() else None,
                    counts=dict(spans=len(data['spans']), transfers=len(data.get('transfers', [])),
                                markers=sum(len(b['markers']) for b in data['blocks']) + sum(len(a['markers']) for a in unbound)))
    (out/'manifest.json').write_text(json.dumps(manifest, separators=(',', ':')))
    write_index(data, manifest, out)
    return manifest


def write_index(data, manifest, out):
    def link(file, label): return f'<a href="{escape(file)}">{escape(label)}</a>'
    rows = []
    for b in data['blocks']:
        status = 'percentile population' if b.get('in_population') else 'warmup' if b.get('warmup') else 'outside population' if b['complete'] else 'incomplete'
        identifier = b["id"]
        timeline = link(f"block-{identifier}.html", f"Block {identifier}")
        trace = link(f"perfetto-block-{identifier}.json", "Perfetto")
        rows.append(f'<tr><td>{timeline}</td><td>{b["duration"]:.3f}</td><td>{status}</td><td>{trace}</td></tr>')
    prewarm_link = '<p>'+link('prewarm.html', 'Selected prewarming call CPU and Perfetto traces')+'</p>' if data.get('prewarm_cpu') == 'leaf_v1' else ''
    attempts = ''.join('<li>'+link(f'attempt-{a["id"]}.html', f'Attempt {a["id"]}: {a["status"]}')+'</li>' for a in data.get('attempt_details', []) if not a.get('block'))
    percentiles = ' · '.join(link(p['page'], f'p{p["percentile"]}: block {p["block"]}')+' ('+link(p['trace'], 'Perfetto')+')' for p in manifest['percentiles'])
    chunks = ''.join(f'<tr><td>{link(c["page"], c["page"])}</td><td>{c["start"]:.3f}–{c["end"]:.3f}</td><td>{c["records"]}</td><td>{link(c["file"], "Perfetto")}</td></tr>' for c in manifest['chunks'])
    optional = link(manifest['full_trace'], 'Optional full Perfetto (large)') if manifest['full_trace'] else 'Full Perfetto is optional: run perfetto.py lifecycle.json --out . --full.'
    health = 'Capture incomplete; percentile selection disabled.' if data['bad_capture'] else f'{data["eligible"]} complete blocks in percentile population.'
    html = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Block lifecycle capture</title><style>body{{font:16px system-ui;background:#0d1119;color:#dfe7f3;max-width:1200px;margin:32px auto;padding:16px}}a{{color:#6ce3cd}}p{{line-height:1.6}}table{{border-collapse:collapse;width:100%}}td,th{{padding:8px;text-align:left;border-bottom:1px solid #34465e}}</style><h1>Block lifecycle capture</h1><p>{escape(health)} {len(data['spans']):,} measured spans. All pages work offline after extracting the whole artifact.</p><p>{escape(data['definition'])}</p><p>{percentiles}</p>{prewarm_link}<h2>Individual blocks</h2><table><tr><th>Timeline</th><th>Duration (ms)</th><th>Population</th><th>Trace</th></tr>{''.join(rows)}</table><h2>Unassociated proposal attempts</h2><ul>{attempts}</ul><h2>Complete context capture</h2><p>These bounded chunks contain every span, matched frame transfer and block milestone exactly once, including unassociated work. Intervals retain their original timestamps and full duration; chunk time ranges may overlap. Temporal overlap does not establish block causality. Block pages link overlapping chunks.</p><table><tr><th>Timeline</th><th>Capture time (ms)</th><th>Records</th><th>Trace</th></tr>{chunks}</table><h2>Source data</h2><p>{link('lifecycle.json', 'Complete lifecycle data (large)')} · {link('manifest.json', 'Export manifest')} · {optional}</p><p>Raw captures and complete lifecycle data are preserved. Focused pages contain associated operations and causal ancestors; overlapping background work is available through context chunks.</p></html>'''
    (out/'index.html').write_text(html)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--full', action='store_true')
    args = parser.parse_args()
    data = json.loads(args.report.read_text())
    args.out.mkdir(parents=True, exist_ok=True)
    if args.report.resolve() != (args.out/'lifecycle.json').resolve():
        shutil.copyfile(args.report, args.out/'lifecycle.json')
        for source in args.report.parent.iterdir():
            if re.fullmatch(r'[a-z]\.jsonl|window\.json', source.name):
                shutil.copyfile(source, args.out/source.name)
    manifest = write_package(data, args.out, full=args.full)
    print(f"Packaged {len(manifest['pages'])} focused pages and {len(manifest['chunks'])} complete context chunks")
