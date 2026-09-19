#!/usr/bin/env python3
"""Shrink a samply profile (Firefox Profiler processed format) so it can be uploaded.

profiler.firefox.com rejects uploads above 150 MiB (MAX_BODY_LENGTH in
profiler-server's src/routes/publish.ts). Profiles recorded with tempo's
`--log.samply` are several times that: roughly 90% of the JSON is tracing-span
interval markers, most of them shorter than a millisecond, while the samples and
stack tables are comparatively small.

This script drops interval markers shorter than a duration threshold, leaves
everything else (samples, stacks, frames, funcs, strings, counters) untouched and
records what was dropped in `meta.extra` (visible in the profiler's "more info"
panel). If the gzipped result is still above --max-bytes it escalates through the
threshold list and finally drops all markers.

The uncompressed JSON of a 500 MiB profile is several GiB, so the document is only
materialized one thread at a time, the first threshold is applied as each thread is
decoded (only surviving markers stay in memory) and everything except the marker
tables is copied through as text. Both the current layout (preprocessedProfileVersion
>= 55 with tables in `profile.shared`) and older per-thread table layouts work, since
only the marker table columns are touched.

Usage:
  shrink-samply-profile.py [--max-bytes N] [--thresholds-ms 1,10,100]
                           [--gzip-level 6] [--force] INPUT.json.gz OUTPUT.json.gz

Exit codes: 0 output written and within --max-bytes, 3 output written but still
above --max-bytes even with all markers dropped, 1 error.
"""

import argparse
import gzip
import json
import os
import re
import sys
import time
from collections import Counter
from itertools import compress
from operator import not_

MIB = 1024 * 1024
DEFAULT_MAX_BYTES = 140 * MIB  # headroom below the profiler's 150 MiB limit
DEFAULT_THRESHOLDS_MS = "1,10,100"
PHASE_INTERVAL = 1  # MarkerPhase: 0 instant, 1 interval, 2 interval start, 3 interval end
READ_CHUNK = 64 * MIB
WRITE_CHUNK = 16 * MIB
# Stands in for a thread's marker table when the rest of the thread is serialized
# once up front; the filtered table is spliced in on every write pass.
MARKERS_PLACEHOLDER = "__tempo_shrink_samply_markers_placeholder_7f3c9d__"
NON_ASCII_RUN = re.compile(rb"[\x80-\xff]+")
TRAILING_NON_ASCII = re.compile(rb"[\x80-\xff]+\Z")
WHITESPACE = re.compile(r"[ \t\n\r]*")

_decoder = json.JSONDecoder()


class ProfileFormatError(Exception):
    pass


def log(msg):
    print("shrink-samply-profile: {}".format(msg), file=sys.stderr, flush=True)


def fmt_mib(n):
    return "{:.1f} MiB".format(n / MIB)


def fmt_ms(ms):
    return "{:g} ms".format(ms)


def compact(obj):
    return json.dumps(obj, separators=(",", ":"))


def _escape_run(match):
    return json.dumps(match.group(0).decode("utf-8"))[1:-1].encode("ascii")


def read_ascii_json(path):
    """Decompress `path` into an ASCII-only str.

    Non-ASCII characters are rewritten as \\uXXXX escapes (equivalent JSON) so the
    text costs one byte per character instead of two or four. Escaping happens per
    chunk to avoid another full-size copy of the text.
    """
    data = bytearray()
    carry = b""
    with gzip.open(path, "rb") as f:
        while True:
            chunk = f.read(READ_CHUNK)
            if not chunk:
                break
            if carry:
                chunk = carry + chunk
                carry = b""
            if not chunk.isascii():
                # A multi-byte UTF-8 sequence may be split across chunks; hold back a
                # trailing run of non-ASCII bytes so it is escaped whole.
                tail = TRAILING_NON_ASCII.search(chunk)
                if tail:
                    carry = chunk[tail.start() :]
                    chunk = chunk[: tail.start()]
                chunk = NON_ASCII_RUN.sub(_escape_run, chunk)
            data += chunk
    if carry:
        data += NON_ASCII_RUN.sub(_escape_run, carry)
    text = data.decode("ascii")
    del data
    return text


class Cursor:
    """Walks the top-level structure of a JSON text, decoding values with the
    stdlib decoder only where asked."""

    def __init__(self, text):
        self.text = text
        self.i = 0

    def skip_ws(self):
        self.i = WHITESPACE.match(self.text, self.i).end()

    def peek(self):
        self.skip_ws()
        return self.text[self.i] if self.i < len(self.text) else ""

    def expect(self, ch):
        if self.peek() != ch:
            raise ProfileFormatError(
                "expected {!r} at offset {}, found {!r}".format(ch, self.i, self.peek())
            )
        self.i += 1

    def value(self):
        """Decode the JSON value at the cursor and advance past it."""
        self.skip_ws()
        try:
            obj, end = _decoder.raw_decode(self.text, self.i)
        except json.JSONDecodeError as e:
            raise ProfileFormatError("invalid JSON at offset {}: {}".format(self.i, e.msg))
        self.i = end
        return obj

    def members(self):
        """Yield the keys of the object at the cursor. The caller must consume each
        value (with value() or a nested walk) before resuming the iteration."""
        self.expect("{")
        if self.peek() == "}":
            self.i += 1
            return
        while True:
            key = self.value()
            if not isinstance(key, str):
                raise ProfileFormatError("object key at offset {} is not a string".format(self.i))
            self.expect(":")
            yield key
            ch = self.peek()
            self.i += 1
            if ch == ",":
                continue
            if ch == "}":
                return
            raise ProfileFormatError("expected ',' or '}}' at offset {}".format(self.i - 1))

    def elements(self):
        """Yield once per element of the array at the cursor; same protocol as members()."""
        self.expect("[")
        if self.peek() == "]":
            self.i += 1
            return
        while True:
            yield
            ch = self.peek()
            self.i += 1
            if ch == ",":
                continue
            if ch == "]":
                return
            raise ProfileFormatError("expected ',' or ']' at offset {}".format(self.i - 1))


class ThreadPart:
    """One thread, serialized except for its marker table."""

    __slots__ = ("prefix", "suffix", "markers", "orig_len", "strings")

    def __init__(self, thread):
        self.markers = None
        self.orig_len = 0
        self.strings = None
        table = thread.get("markers")
        if isinstance(table, dict) and isinstance(table.get("length"), int):
            thread["markers"] = MARKERS_PLACEHOLDER
            self.markers = table
            self.orig_len = table["length"]
            # Older profile versions keep a string table per thread; current ones
            # share it in profile.shared.
            strings = thread.get("stringArray")
            self.strings = strings if isinstance(strings, list) else None
        dumped = compact(thread)
        if self.markers is None:
            self.prefix, self.suffix = dumped, None
            return
        marker = compact(MARKERS_PLACEHOLDER)
        prefix, sep, suffix = dumped.partition(marker)
        if not sep or marker in suffix:
            raise ProfileFormatError("could not locate the marker table in the serialized thread")
        self.prefix, self.suffix = prefix, suffix


class Profile:
    """The parsed document. `thread_hook` is called with each ThreadPart as soon as
    it is decoded, so the first filter pass can run before the next thread's marker
    table is materialized."""

    def __init__(self, text, thread_hook=None):
        self.text = text
        self.meta = None
        self.threads = []
        self.shared_strings = None
        # (key, kind, payload) in document order; kind is "meta", "threads" or "text"
        self.segments = []
        self._parse(thread_hook)

    def _parse(self, thread_hook):
        cur = Cursor(self.text)
        for key in cur.members():
            cur.skip_ws()
            start = cur.i
            if key == "meta":
                self.meta = cur.value()
                if not isinstance(self.meta, dict):
                    raise ProfileFormatError("profile.meta is not an object")
                self.segments.append((key, "meta", None))
            elif key == "threads":
                for _ in cur.elements():
                    thread = cur.value()
                    if not isinstance(thread, dict):
                        raise ProfileFormatError("profile.threads contains a non-object")
                    part = ThreadPart(thread)
                    del thread
                    if thread_hook is not None:
                        thread_hook(part)
                    self.threads.append(part)
                self.segments.append((key, "threads", None))
            elif key == "shared":
                # Only the string table is needed (to name dropped markers); the big
                # stack/frame/func tables are copied through as text.
                for skey in cur.members():
                    val = cur.value()
                    if skey == "stringArray" and isinstance(val, list):
                        self.shared_strings = val
                self.segments.append((key, "text", (start, cur.i)))
            else:
                cur.value()
                self.segments.append((key, "text", (start, cur.i)))
        cur.skip_ws()
        if cur.i != len(self.text):
            raise ProfileFormatError("trailing data after the profile object")
        if self.meta is None:
            raise ProfileFormatError("profile has no meta object")

    def total_markers(self):
        return sum(p.orig_len for p in self.threads)

    def marker_name(self, key):
        if isinstance(key, str):
            return key
        strings = self.shared_strings
        if strings is not None and isinstance(key, int) and 0 <= key < len(strings):
            return str(strings[key])
        return "<string #{}>".format(key)

    def write(self, path, extra_section, gzip_level):
        with gzip.open(path, "wb", compresslevel=gzip_level) as gz:

            def emit(s):
                gz.write(s.encode("ascii"))

            emit("{")
            for idx, (key, kind, payload) in enumerate(self.segments):
                if idx:
                    emit(",")
                emit(compact(key))
                emit(":")
                if kind == "meta":
                    meta = dict(self.meta)
                    extra = meta.get("extra")
                    extra = list(extra) if isinstance(extra, list) else []
                    extra.append(extra_section)
                    meta["extra"] = extra
                    emit(compact(meta))
                elif kind == "threads":
                    emit("[")
                    for tidx, part in enumerate(self.threads):
                        if tidx:
                            emit(",")
                        emit(part.prefix)
                        if part.suffix is not None:
                            emit(compact(part.markers))
                            emit(part.suffix)
                    emit("]")
                else:
                    start, end = payload
                    for pos in range(start, end, WRITE_CHUNK):
                        emit(self.text[pos : min(pos + WRITE_CHUNK, end)])
            emit("}")


def filter_markers(part, threshold_ms, dropped_names):
    """Drop interval markers shorter than threshold_ms (None drops every marker)
    from part.markers in place. Returns the number of markers dropped."""
    table = part.markers
    n = table["length"]
    if n == 0:
        return 0
    if threshold_ms is None:
        keep = [False] * n
    else:
        phase = table.get("phase")
        start = table.get("startTime")
        end = table.get("endTime")
        for name, col in (("phase", phase), ("startTime", start), ("endTime", end)):
            if not isinstance(col, list) or len(col) != n:
                raise ProfileFormatError(
                    "marker column {!r} is missing or does not match length {}".format(name, n)
                )
        keep = [
            p != PHASE_INTERVAL or s is None or e is None or (e - s) >= threshold_ms
            for p, s, e in zip(phase, start, end)
        ]
    dropped = n - sum(keep)
    if dropped == 0:
        return 0
    names = table.get("name")
    if isinstance(names, list) and len(names) == n:
        dropped_iter = compress(names, map(not_, keep))
        if part.strings is not None:
            strings = part.strings
            dropped_names.update(
                str(strings[i]) if isinstance(i, int) and 0 <= i < len(strings) else i
                for i in dropped_iter
            )
        else:
            dropped_names.update(dropped_iter)
    for key, col in table.items():
        if isinstance(col, list) and len(col) == n:
            table[key] = list(compress(col, keep))
    table["length"] = n - dropped
    return dropped


def describe_drop(threshold_ms):
    if threshold_ms is None:
        return "all markers"
    return "interval markers shorter than {}".format(fmt_ms(threshold_ms))


def extra_section(in_size, total, dropped, threshold_ms):
    return {
        "label": "Shrunk for upload",
        "entries": [
            {
                "label": "Reason",
                "format": "string",
                "value": (
                    "The recorded profile was {} gzipped; profiler.firefox.com rejects "
                    "uploads above 150 MiB.".format(fmt_mib(in_size))
                ),
            },
            {
                "label": "Dropped",
                "format": "string",
                "value": (
                    "{:,} of {:,} markers ({}). Samples, stacks and all other tables "
                    "are unchanged.".format(dropped, total, describe_drop(threshold_ms))
                ),
            },
            {"label": "Kept markers", "format": "integer", "value": total - dropped},
            {
                "label": "Tool",
                "format": "string",
                "value": "tempo contrib/bench/shrink-samply-profile.py",
            },
        ],
    }


def parse_thresholds(spec):
    if not spec.strip():
        return []
    values = []
    for item in spec.split(","):
        try:
            v = float(item)
        except ValueError:
            raise argparse.ArgumentTypeError("invalid threshold {!r}".format(item))
        if v <= 0 or (values and v <= values[-1]):
            raise argparse.ArgumentTypeError("thresholds must be positive and increasing")
        values.append(v)
    return values


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("input", help="samply profile (.json.gz)")
    ap.add_argument("output", help="where to write the shrunk profile (.json.gz)")
    ap.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help="target gzipped size in bytes (default: 140 MiB)",
    )
    ap.add_argument(
        "--thresholds-ms",
        type=parse_thresholds,
        default=DEFAULT_THRESHOLDS_MS,
        help="increasing interval-marker duration thresholds to try in turn; after the "
        "last one all markers are dropped (default: %(default)s)",
    )
    ap.add_argument(
        "--gzip-level", type=int, default=6, choices=range(1, 10), metavar="1-9",
        help="gzip compression level for the output (default: 6)",
    )
    ap.add_argument(
        "--force", action="store_true", help="shrink even if INPUT is already within --max-bytes"
    )
    args = ap.parse_args(argv)
    thresholds = (
        parse_thresholds(args.thresholds_ms)
        if isinstance(args.thresholds_ms, str)
        else args.thresholds_ms
    )

    in_size = os.path.getsize(args.input)
    if in_size <= args.max_bytes and not args.force:
        log(
            "{} is {}, within the {} limit; nothing to do".format(
                args.input, fmt_mib(in_size), fmt_mib(args.max_bytes)
            )
        )
        return 0

    t0 = time.monotonic()
    text = read_ascii_json(args.input)
    t1 = time.monotonic()
    log(
        "{}: {} gzipped, {} of JSON, decompressed in {:.0f}s".format(
            os.path.basename(args.input), fmt_mib(in_size), fmt_mib(len(text)), t1 - t0
        )
    )

    attempts = list(thresholds) + [None]
    dropped_names = Counter()
    state = {"dropped": 0}

    def first_pass(part):
        if part.markers is not None:
            state["dropped"] += filter_markers(part, attempts[0], dropped_names)

    profile = Profile(text, first_pass)
    total = profile.total_markers()
    t2 = time.monotonic()
    log(
        "parsed {} threads with {:,} markers in {:.0f}s".format(
            len(profile.threads), total, t2 - t1
        )
    )

    out_size = None
    for idx, threshold in enumerate(attempts):
        if idx > 0:
            for part in profile.threads:
                if part.markers is not None:
                    state["dropped"] += filter_markers(part, threshold, dropped_names)
        dropped = state["dropped"]
        profile.write(args.output, extra_section(in_size, total, dropped, threshold), args.gzip_level)
        out_size = os.path.getsize(args.output)
        log(
            "dropped {}: {:,} of {:,} markers removed, {:,} kept -> {} ({:.0f}s)".format(
                describe_drop(threshold),
                dropped,
                total,
                total - dropped,
                fmt_mib(out_size),
                time.monotonic() - t2,
            )
        )
        if out_size <= args.max_bytes:
            break
        if threshold is not None:
            log("still above {}; retrying with a higher threshold".format(fmt_mib(args.max_bytes)))

    if dropped_names:
        log("most frequently dropped marker names:")
        for key, count in dropped_names.most_common(10):
            log("  {:>12,}  {}".format(count, profile.marker_name(key)))

    if out_size > args.max_bytes:
        log(
            "error: {} is still {} even with all markers dropped; cannot fit within {}".format(
                args.output, fmt_mib(out_size), fmt_mib(args.max_bytes)
            )
        )
        return 3
    log("wrote {} ({}) in {:.0f}s".format(args.output, fmt_mib(out_size), time.monotonic() - t0))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ProfileFormatError, UnicodeDecodeError, EOFError, OSError) as e:
        log("error: {}".format(e))
        sys.exit(1)
