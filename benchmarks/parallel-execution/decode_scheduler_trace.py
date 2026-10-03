#!/usr/bin/env python3
"""Decode the bounded scheduler recorder's uncompressed, little-endian perf.data.

This is an offline structural decoder, not a proof of complete scheduler or block
coverage. It preserves tracepoint-reported numeric states without interpreting
those states. No perf Python bindings or external commands are used.

Layout references: Linux v6.8, commit e8f897f4afef0031fe618a8e94127a0934896aba,
include/uapi/linux/perf_event.h (sample/trailer/read layouts), tools/perf/util/
header.{h,c} (PERFILE2, attrs/IDs/features), tools/lib/perf/include/perf/event.h
(metadata), and tools/perf/util/evsel.c (sample order and raw padding).
https://github.com/torvalds/linux/tree/e8f897f4afef0031fe618a8e94127a0934896aba
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile

MAX_BYTES = 128 * 1024 * 1024
MAX_EVENTS = 2_000_000
SOURCE_COMMIT = "e8f897f4afef0031fe618a8e94127a0934896aba"
EVENTS = {"sched_switch", "sched_wakeup", "sched_wakeup_new"}
# PERF_SAMPLE bits; variable layouts such as callchains and sampled READ are not accepted.
IP, TID, TIME, ADDR, ID, CPU, PERIOD, STREAM, RAW, IDENTIFIER = (1 << n for n in (0, 1, 2, 3, 6, 7, 8, 9, 10, 16))
ALLOWED_SAMPLE = IP | TID | TIME | ADDR | ID | CPU | PERIOD | STREAM | RAW | IDENTIFIER
REQUIRED_SAMPLE = TID | TIME | CPU
RECORD_NAMES = {1: "MMAP", 2: "LOST", 3: "COMM", 4: "EXIT", 5: "THROTTLE", 6: "UNTHROTTLE", 7: "FORK", 8: "READ", 9: "SAMPLE", 10: "MMAP2", 13: "LOST_SAMPLES", 16: "NAMESPACES", 17: "KSYMBOL", 18: "BPF_EVENT", 19: "CGROUP", 68: "FINISHED_ROUND", 69: "ID_INDEX", 73: "THREAD_MAP", 74: "CPU_MAP", 79: "TIME_CONV", 82: "FINISHED_INIT"}


class DecodeError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise DecodeError(message)


class Cursor:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, size):
        require(0 <= size <= len(self.data) - self.pos, "truncated record field")
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def unpack(self, fmt):
        return struct.unpack("<" + fmt, self.take(struct.calcsize("<" + fmt)))

    def u64(self):
        return self.unpack("Q")[0]

    def end(self):
        require(self.pos == len(self.data), "unexpected bytes after record fields")


def event_schema(name, item):
    text = item["format"]
    require(re.search(r"^name:\s*" + name + r"\s*$", text, re.M), "tracepoint name mismatch")
    match = re.search(r"^ID:\s*(\d+)\s*$", text, re.M)
    require(match and int(match[1]) == item["id"], "tracepoint format ID mismatch")
    fields = {}
    occupied = set()
    for line in text.splitlines():
        if "field:" not in line:
            continue
        match = re.fullmatch(r"\s*field:(.+);\s*offset:(\d+);\s*size:(\d+);\s*signed:([01]);\s*", line)
        require(match is not None, "unsupported tracepoint field declaration")
        declaration, offset, size, signed = match.groups()
        field = re.search(r"\b(\w+)(?:\[(\d+)\])?$", declaration)
        require(field and "__data_loc" not in declaration and "*" not in declaration, "dynamic tracepoint field unsupported")
        key = field[1]
        offset, size, signed = int(offset), int(size), int(signed)
        require(key not in fields and 0 < size <= 256 and offset + size <= 4096, "invalid tracepoint field bounds")
        region = set(range(offset, offset + size))
        require(not occupied.intersection(region), "overlapping tracepoint fields")
        occupied.update(region)
        if field[2]:
            require(declaration.startswith("char ") and int(field[2]) == size, "unsupported tracepoint array")
        else:
            require(size in (1, 2, 4, 8), "unsupported tracepoint scalar width")
        fields[key] = {"offset": offset, "size": size, "signed": signed, "array": bool(field[2]), "declaration": declaration}
    expected = {"common_type": (2, 0), "common_pid": (4, 1)}
    expected.update({"prev_pid": (4, 1), "next_pid": (4, 1)} if name == "sched_switch" else {"pid": (4, 1), "target_cpu": (4, 1)})
    for key, (size, signed) in expected.items():
        require(key in fields and fields[key]["size"] == size and fields[key]["signed"] == signed and not fields[key]["array"], "missing/unsupported tracepoint field " + key)
    require(fields["common_type"]["offset"] == 0, "common_type is not at raw offset zero")
    if name == "sched_switch":
        require("prev_state" in fields and fields["prev_state"]["size"] in (4, 8) and not fields["prev_state"]["array"], "unsupported prev_state field")
    require("print fmt:" in text, "missing tracepoint print format")
    return {"name": name, "id": item["id"], "format": text, "format_sha256": hashlib.sha256(text.encode()).hexdigest(), "fields": fields, "minimum_bytes": max(occupied) + 1}


class Decoder:
    def __init__(self, data, preflight):
        require(104 <= len(data) <= MAX_BYTES, "perf.data outside bounded file size")
        self.data = data
        require(set(preflight["events"]) == EVENTS, "expected exactly three scheduler schemas")
        self.schemas = {item["id"]: event_schema(name, item) for name, item in preflight["events"].items()}
        require(len(self.schemas) == 3, "duplicate tracepoint IDs")
        self.cpus = set(preflight["online_cpus"])
        require(self.cpus and all(type(x) is int and 0 <= x < 65536 for x in self.cpus), "invalid online CPUs")
        self.attrs, self.ids, self.events = [], {}, []
        self.sections, self.counts, self.anomalies = [], Counter(), []
        self.report = {"ok": False, "source_commit": SOURCE_COMMIT, "perf_sha256": hashlib.sha256(data).hexdigest(), "perf_bytes": len(data), "record_counts": self.counts, "anomalies": self.anomalies, "schemas": list(self.schemas.values()), "attributes": self.attrs, "features": [], "scheduler_accounting_qualified": False, "scope": "Numeric binary decoding only; recorder completeness, target lifetimes, state interpretation and accepted block joins remain separate."}
        self.initialized = False
        self.id_cpus = {}

    def section(self, offset, size, label):
        require(0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset, "out-of-bounds " + label)
        if size:
            require(all(offset + size <= a or b <= offset for a, b, _ in self.sections), "overlapping " + label)
            self.sections.append((offset, offset + size, label))
        return self.data[offset:offset + size]

    def header(self):
        magic, size, attr_size, ao, az, do, dz, eo, ez, *bits = struct.unpack_from("<8s12Q", self.data)
        require(magic == b"PERFILE2" and size == 104, "unsupported endian, pipe or perf header")
        require(eo == ez == 0, "legacy event_types section unsupported")
        require(attr_size in (112, 120, 128, 136, 144, 152) and az % attr_size == 0 and az // attr_size in (3, 4), "unsupported attribute section")
        self.section(0, size, "header")
        attrs = self.section(ao, az, "attrs")
        records = self.section(do, dz, "data")
        require(dz > 0, "empty data section")
        for off in range(0, len(attrs), attr_size):
            raw = attrs[off:off + attr_size]
            typ, length, config, period, sample, read, flags = struct.unpack_from("<II5Q", raw)
            require(length == attr_size - 16 and length in (96, 104, 112, 120, 128, 136), "unsupported perf_event_attr size")
            require(sample & ~ALLOWED_SAMPLE == 0 and sample & REQUIRED_SAMPLE == REQUIRED_SAMPLE and sample & (ID | IDENTIFIER), "unsupported/missing sample fields")
            require(read & ~31 == 0, "unsupported READ format")
            require(flags & (1 << 18) and flags & (1 << 25), "sample_id_all and explicit clockid required")
            require(not flags & ((1 << 10) | (1 << 27) | (1 << 31)), "frequency/overwrite/AUX unsupported")
            require(struct.unpack_from("<i", raw, 92)[0] == 1, "CLOCK_MONOTONIC required")
            require(period == 1, "sample period must be one")
            dummy = typ == 1 and config == 9
            require(dummy or typ == 2 and config in self.schemas, "unrecognized event attribute")
            require(not (sample & RAW) if dummy else bool(sample & RAW), "trace raw fields/dummy mismatch")
            require(not any(a["config"] == config and a["type"] == typ for a in self.attrs), "duplicate event attribute")
            ido, idz = struct.unpack_from("<QQ", raw, length)
            require(idz and idz % 8 == 0 and idz // 8 <= 65536, "invalid ID section")
            ids = list(struct.unpack("<" + "Q" * (idz // 8), self.section(ido, idz, "event IDs")))
            attr = {"type": typ, "size": length, "config": config, "dummy_metadata_only": dummy, "sample_type": sample, "read_format": read, "flags": flags, "clockid": 1, "ids": ids, "sha256": hashlib.sha256(raw[:length]).hexdigest()}
            for ident in ids:
                require(ident and ident not in self.ids, "zero/duplicate event ID")
                self.ids[ident] = attr
            self.attrs.append(attr)
        require({a["config"] for a in self.attrs if not a["dummy_metadata_only"]} == set(self.schemas), "tracepoint attributes incomplete")
        # All events must share the nonsample identity trailer layout, including dummy:u.
        trailer_mask = TID | TIME | ID | STREAM | CPU | IDENTIFIER
        require(len({a["sample_type"] & trailer_mask for a in self.attrs}) == 1, "heterogeneous identity trailers unsupported")
        self.trailer_type = self.attrs[0]["sample_type"] & trailer_mask
        self.trailer_bytes = 8 * self.trailer_type.bit_count()
        feature_ids = [i for i in range(256) if bits[i // 64] & (1 << (i % 64))]
        require(all(1 <= i <= 31 and i not in (15, 18, 19, 24, 27) for i in feature_ids), "unsupported/compressed feature")
        table = self.section(do + dz, len(feature_ids) * 16, "feature table")
        for i, feat in enumerate(feature_ids):
            offset, length = struct.unpack_from("<QQ", table, i * 16)
            raw = self.section(offset, length, "feature " + str(feat))
            item = {"id": feat, "offset": offset, "size": length, "sha256": hashlib.sha256(raw).hexdigest()}
            if feat == 21:
                require(length == 16, "bad sample time feature")
                item["first_ns"], item["last_ns"] = struct.unpack("<QQ", raw)
            if feat == 29:
                require(length == 24, "bad clock data feature")
                version, clock, realtime, mono = struct.unpack("<IIQQ", raw)
                require(version == clock == 1, "unsupported clock data")
                item.update(realtime_ns=realtime, monotonic_ns=mono)
            self.report["features"].append(item)
        self.report["data_section"] = {"offset": do, "size": dz}
        return do, records

    def identity(self, cur, sample_type, trailer=False):
        result = {}
        if not trailer and sample_type & IDENTIFIER:
            result["identifier"] = cur.u64()
        if not trailer and sample_type & IP:
            result["ip"] = cur.u64()
        if sample_type & TID:
            result["context_pid"], result["context_tid"] = cur.unpack("II")
        if sample_type & TIME:
            result["timestamp_ns"] = cur.u64()
        if not trailer and sample_type & ADDR:
            result["addr"] = cur.u64()
        if sample_type & ID:
            result["id"] = cur.u64()
        if sample_type & STREAM:
            result["stream_id"] = cur.u64()
        if sample_type & CPU:
            result["cpu"], reserved = cur.unpack("II")
            require(reserved == 0, "nonzero CPU reserved field")
        if trailer and sample_type & IDENTIFIER:
            result["identifier"] = cur.u64()
        if not trailer and sample_type & PERIOD:
            result["period"] = cur.u64()
        return result

    def check_identity(self, identity, synthesized=False):
        ids = [identity[k] for k in ("identifier", "id", "stream_id") if k in identity]
        require(ids, "missing sample identity")
        if "identifier" in identity and "id" in identity:
            require(identity["identifier"] == identity["id"], "identifier and ID disagree")
        if synthesized and not any(identity.values()):
            return None
        require(all(i in self.ids for i in ids), "unknown record event ID")
        attr = self.ids[ids[0]]
        require(all(self.ids[i] is attr for i in ids), "conflicting record IDs")
        require(identity["cpu"] in self.cpus, "record CPU outside captured online set")
        for ident in ids:
            if ident in self.id_cpus:
                require(self.id_cpus[ident] == identity["cpu"], "record CPU differs from ID_INDEX")
        return attr

    def sample(self, body, offset):
        # Identifier has a fixed first position. ID-only layouts are selected
        # by trying the at-most-four validated descriptors, requiring one match.
        candidates = []
        for attr in self.attrs:
            if attr["dummy_metadata_only"]:
                continue
            try:
                cur = Cursor(body)
                identity = self.identity(cur, attr["sample_type"])
                if self.check_identity(identity) is not attr:
                    continue
                raw_size = cur.unpack("I")[0]
                raw = cur.take(raw_size)
                cur.end()
                candidates.append((attr, identity, raw))
            except DecodeError:
                continue
        require(len(candidates) == 1, "sample does not match exactly one event descriptor")
        attr, identity, raw = candidates[0]
        schema = self.schemas[attr["config"]]
        minimum = schema["minimum_bytes"]
        require(minimum <= len(raw) <= ((minimum + 11) // 8) * 8 - 4, "raw tracepoint size mismatch")
        fields = {}
        for key, f in schema["fields"].items():
            value = raw[f["offset"]:f["offset"] + f["size"]]
            if f["array"]:
                fields[key] = value.split(b"\0", 1)[0].decode("utf-8", errors="replace")
            else:
                fields[key] = int.from_bytes(value, "little", signed=bool(f["signed"]))
        require(fields["common_type"] == attr["config"], "raw common_type differs from attr/ID")
        require(fields["common_pid"] == identity["context_tid"], "raw context TID differs from sample header")
        if schema["name"] != "sched_switch":
            require(fields["pid"] > 0 and fields["target_cpu"] in self.cpus, "invalid wakeup target")
        else:
            require(fields["prev_pid"] >= 0 and fields["next_pid"] >= 0, "negative scheduler PID")
        require(len(self.events) < MAX_EVENTS, "normalized event limit exceeded")
        self.events.append({"event": schema["name"], "record_offset": offset, **identity, "fields": fields})

    def read_values(self, body, attr, offset):
        cur = Cursor(body)
        cur.unpack("II")  # READ record's pid/tid are not the target tracepoint PID.
        fmt = attr["read_format"]
        group = bool(fmt & 8)
        number = cur.u64() if group else 1
        require(number <= 65536, "READ group too large")
        value = None if group else cur.u64()
        for flag in (1, 2):
            if fmt & flag:
                cur.u64()
        for _ in range(number):
            if group:
                value = cur.u64()
            if fmt & 4:
                ident = cur.u64()
                require(ident in self.ids and (group or self.ids[ident] is attr), "READ counter ID unknown/mismatched")
            if fmt & 16:
                lost = cur.u64()
                if lost:
                    self.anomalies.append({"kind": "READ_LOST", "offset": offset, "lost": lost})
        cur.end()

    def metadata(self, typ, body, offset):
        if typ in (68, 82):
            require(not body, "finished marker has payload")
            if typ == 82:
                self.initialized = True
            return
        if typ == 69:
            cur = Cursor(body)
            nr = cur.u64()
            require(nr <= 65536 and len(body) == 8 + nr * 32, "unsupported ID_INDEX layout")
            for _ in range(nr):
                ident, _, cpu, _ = cur.unpack("QQQQ")
                require(ident in self.ids and cpu in self.cpus, "bad ID_INDEX entry")
                require(ident not in self.id_cpus, "duplicate ID_INDEX entry")
                self.id_cpus[ident] = cpu
            return
        if typ == 73:
            nr = Cursor(body).u64()
            require(nr <= 65536 and len(body) == 8 + nr * 24, "bad THREAD_MAP")
            return
        if typ == 74:
            require(len(body) >= 8, "short CPU_MAP")
            kind = struct.unpack_from("<H", body)[0]
            if kind == 2:
                any_cpu, reserved, low, high = struct.unpack_from("<BBHH", body, 2)
                require(any_cpu in (0, 1) and reserved == 0 and low <= high and len(body) == 8, "bad CPU_MAP range")
                require(set(range(low, high + 1)) == self.cpus, "CPU_MAP differs from preflight")
            elif kind == 0:
                nr = struct.unpack_from("<H", body, 2)[0]
                require(4 + nr * 2 <= len(body) < 12 + nr * 2, "bad CPU_MAP list")
                require(set(struct.unpack_from("<" + "H" * nr, body, 4)) == self.cpus, "CPU_MAP differs from preflight")
            else:
                raise DecodeError("CPU_MAP bitmap unsupported")
            return
        if typ == 79:
            require(len(body) in (24, 48), "unsupported TIME_CONV layout")
            return  # Samples explicitly use mono, not hardware-cycle conversion.
        require(len(body) >= self.trailer_bytes, "truncated nonsample trailer")
        content, trailer = body[:-self.trailer_bytes], body[-self.trailer_bytes:]
        identity = self.identity(Cursor(trailer), self.trailer_type, trailer=True)
        attr = self.check_identity(identity, synthesized=not self.initialized)
        if typ in (2, 13, 5, 6):
            expected = {2: 16, 13: 8, 5: 24, 6: 24}[typ]
            require(len(content) == expected, "malformed loss/throttle record")
            detail = {"kind": RECORD_NAMES[typ], "offset": offset, "identity": identity}
            if typ == 2:
                ident, detail["lost"] = struct.unpack("<QQ", content)
                require(ident in self.ids, "LOST event ID unknown")
            elif typ == 13:
                detail["lost"] = struct.unpack("<Q", content)[0]
            self.anomalies.append(detail)
        elif typ == 8:
            require(attr is not None, "READ missing event descriptor")
            self.read_values(content, attr, offset)
        elif typ in (4, 7):
            require(len(content) == 24, "malformed task lifetime record")
        elif typ == 18:
            require(len(content) == 16, "malformed BPF metadata")
        elif typ == 16:
            require(len(content) >= 16 and len(content) == 16 + struct.unpack_from("<Q", content, 8)[0] * 16, "malformed NAMESPACES")
        elif typ in (1, 3, 10, 17, 19):
            prefix = {1: 32, 3: 8, 10: 64, 17: 16, 19: 8}[typ]
            require(len(content) > prefix and b"\0" in content[prefix:], "malformed string metadata")
        else:
            raise DecodeError("unsupported record " + str(typ))

    def decode(self):
        base, data = self.header()
        cur = Cursor(data)
        while cur.pos < len(data):
            offset = base + cur.pos
            typ, misc, size = cur.unpack("IHH")
            self.counts[RECORD_NAMES.get(typ, "UNKNOWN_" + str(typ))] += 1
            require(size >= 8 and size % 8 == 0, "invalid perf record size")
            body = cur.take(size - 8)
            require(typ in RECORD_NAMES, "unsupported perf record type " + str(typ))
            if typ == 9:
                require(misc & 7 in (0, 1, 2), "guest sample unsupported")
                self.sample(body, offset)
            else:
                self.metadata(typ, body, offset)
        self.report["data_records_complete"] = True
        self.report["normalized_events"] = len(self.events)
        require(self.events, "no scheduler samples")
        require(not self.anomalies, "loss/throttle records or positive READ lost counter")
        self.report.update(ok=True, first_timestamp_ns=min(e["timestamp_ns"] for e in self.events), last_timestamp_ns=max(e["timestamp_ns"] for e in self.events), event_counts=dict(Counter(e["event"] for e in self.events)))
        return self.report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="Normalized JSONL; created only after complete successful decoding")
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()
    decoder = None
    temporary = None
    published = False
    try:
        require(not args.output.exists() and not args.summary.exists(), "output/summary must not already exist")
        require(args.input.stat().st_size <= MAX_BYTES, "input exceeds recorder size bound")
        decoder = Decoder(args.input.read_bytes(), json.loads(args.preflight.read_text()))
        report = decoder.decode()
        with tempfile.NamedTemporaryFile(mode="w", dir=args.output.parent, prefix=args.output.name + ".", delete=False) as output:
            temporary = Path(output.name)
            for event in decoder.events:
                output.write(json.dumps(event, separators=(",", ":")) + "\n")
        os.link(temporary, args.output)  # Exclusive atomic publication, never overwrite.
        published = True
        temporary.unlink()
        temporary = None
        with args.summary.open("x") as output:
            output.write(json.dumps(report, indent=2) + "\n")
        return 0
    except (DecodeError, OSError, ValueError, KeyError, struct.error) as error:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        if published:
            args.output.unlink(missing_ok=True)
        report = dict(decoder.report) if decoder else {"ok": False, "scheduler_accounting_qualified": False}
        report.update(ok=False, error=str(error))
        # Never overwrite a prior result or expose partial normalized events.
        if not args.summary.exists():
            args.summary.write_text(json.dumps(report, indent=2) + "\n")
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
