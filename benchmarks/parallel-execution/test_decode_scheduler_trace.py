#!/usr/bin/env python3
"""Independently packed Linux perf fixtures; no perf executable or live recording."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("decode_scheduler_trace", Path(__file__).with_name("decode_scheduler_trace.py"))
decoder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(decoder)


def schema(name, number, shifted=False, state_size=8):
    rows = [("unsigned short common_type", 0, 2, 0), ("unsigned char common_flags", 2, 1, 0), ("unsigned char common_preempt_count", 3, 1, 0), ("int common_pid", 4, 4, 1)]
    if name == "sched_switch":
        # Altered offsets exercise schema use, not a hardcoded local sched.h struct.
        off = 16 if shifted else 8
        rows += [("pid_t prev_pid", off, 4, 1), ("long prev_state", off + 8, state_size, 1), ("pid_t next_pid", off + 16, 4, 1)]
    else:
        rows += [("pid_t pid", 8, 4, 1), ("int target_cpu", 12, 4, 1)]
    text = f"name: {name}\nID: {number}\nformat:\n" + "".join(f" field:{decl}; offset:{offset}; size:{size}; signed:{signed};\n" for decl, offset, size, signed in rows) + 'print fmt: "fixture only"\n'
    return {"id": number, "format": text}, rows


def preflight(shifted=False, state_size=8):
    entries = [schema("sched_switch", 100, shifted, state_size), schema("sched_wakeup", 101), schema("sched_wakeup_new", 102)]
    return {"events": {name: item[0] for name, item in zip(("sched_switch", "sched_wakeup", "sched_wakeup_new"), entries)}, "online_cpus": [0, 1]}, [x[1] for x in entries]


def record(kind, body=b"", misc=0):
    assert (len(body) + 8) % 8 == 0
    return struct.pack("<IHH", kind, misc, len(body) + 8) + body


def raw_event(index=0, rows=None, state=0x1234):
    if rows is None:
        rows = preflight()[1][index]
    raw = bytearray(max(offset + size for _, offset, size, _ in rows))
    values = {"common_type": 100 + index, "common_pid": 42, "prev_pid": 42, "next_pid": 43, "prev_state": state, "pid": 43, "target_cpu": 1}
    for declaration, offset, size, signed in rows:
        value = values.get(declaration.split()[-1], 0)
        raw[offset:offset + size] = value.to_bytes(size, "little", signed=bool(signed))
    # Kernel PERF_SAMPLE_RAW includes alignment padding after the trace payload.
    raw.extend(b"\0" * ((-(len(raw) + 4)) % 8))
    return bytes(raw)


def sample(index=0, raw=None, ident=None, time_ns=9007199254740993, id_only=False):
    raw = raw_event(index) if raw is None else raw
    ident = (11 + index) if ident is None else ident
    if id_only:
        prefix = struct.pack("<IIQQII", 40, 42, time_ns, ident, 1, 0)
    else:
        prefix = struct.pack("<QIIQII", ident, 40, 42, time_ns, 1, 0)
    return record(9, prefix + struct.pack("<I", len(raw)) + raw, misc=1)


def trailer(ident=11, time_ns=12345):
    return struct.pack("<IIQIIQ", 40, 42, time_ns, 1, 0, ident)


def binary(records=None, attribute_edit=None, features=None, id_only=False):
    # Container and attr packing follows UAPI independently of the decoder.
    records = [sample(id_only=id_only)] if records is None else records
    entry_size = 152
    header_size = 104
    ids = struct.pack("<QQQQ", 11, 12, 13, 14)
    attrs_start = header_size + len(ids)
    data_start = attrs_start + 4 * entry_size
    attrs = bytearray()
    for i in range(4):
        a = bytearray(136)
        mask = (2 | 4 | 128 | (64 if id_only else 65536)) | (1024 if i < 3 else 0)
        struct.pack_into("<II5Q", a, 0, 2 if i < 3 else 1, 136, 100 + i if i < 3 else 9, 1, mask, 20, (1 << 18) | (1 << 25))
        struct.pack_into("<i", a, 92, 1)
        if attribute_edit:
            attribute_edit(i, a)
        attrs += a + struct.pack("<QQ", header_size + i * 8, 8)
    data = b"".join(records)
    features = {} if features is None else features
    bitmap = sum(1 << i for i in features)
    feature_offset = data_start + len(data)
    feature_data_start = feature_offset + len(features) * 16
    feature_table = bytearray()
    feature_data = bytearray()
    for _, payload in sorted(features.items()):
        feature_table += struct.pack("<QQ", feature_data_start + len(feature_data), len(payload))
        feature_data += payload
    header = struct.pack("<8s12Q", b"PERFILE2", 104, entry_size, attrs_start, len(attrs), data_start, len(data), 0, 0, bitmap, 0, 0, 0)
    return header + ids + attrs + data + feature_table + feature_data


class DecodeTests(unittest.TestCase):
    def decode(self, data, proof=None):
        d = decoder.Decoder(data, preflight()[0] if proof is None else proof)
        report = d.decode()
        return d, report

    def rejects(self, data, proof=None, contains=None):
        with self.assertRaises(decoder.DecodeError) as error:
            self.decode(data, proof)
        if contains:
            self.assertIn(contains, str(error.exception))

    def test_all_events_numeric_state_cpu_tid_ns(self):
        d, report = self.decode(binary([sample(i) for i in range(3)]))
        self.assertEqual(report["event_counts"], {"sched_switch": 1, "sched_wakeup": 1, "sched_wakeup_new": 1})
        self.assertEqual(d.events[0]["timestamp_ns"], 9007199254740993)
        self.assertEqual(d.events[0]["fields"]["prev_state"], 0x1234)
        self.assertEqual((d.events[0]["cpu"], d.events[0]["context_tid"]), (1, 42))
        self.assertEqual(d.events[1]["fields"]["pid"], 43)
        self.assertFalse(report["scheduler_accounting_qualified"])
        self.assertTrue(report["attributes"][-1]["dummy_metadata_only"])

    def test_alternative_offsets_width_and_signed_state(self):
        proof, rows = preflight(shifted=True, state_size=4)
        d, _ = self.decode(binary([sample(raw=raw_event(rows=rows[0], state=-7))]), proof)
        self.assertEqual(d.events[0]["fields"]["prev_state"], -7)
        self.assertEqual(d.events[0]["fields"]["next_pid"], 43)

    def test_id_only_layout(self):
        d, _ = self.decode(binary(id_only=True))
        self.assertEqual(d.events[0]["id"], 11)
        self.assertNotIn("identifier", d.events[0])

    def test_all_loss_types_counted_and_rejected(self):
        cases = [(2, struct.pack("<QQ", 11, 7)), (13, struct.pack("<Q", 8)), (5, struct.pack("<QQQ", 123, 11, 11)), (6, struct.pack("<QQQ", 124, 11, 11))]
        d = decoder.Decoder(binary([sample()] + [record(kind, body + trailer()) for kind, body in cases]), preflight()[0])
        with self.assertRaisesRegex(decoder.DecodeError, "loss/throttle"):
            d.decode()
        self.assertEqual(len(d.anomalies), 4)
        self.assertTrue(d.report["data_records_complete"])
        for name in ("LOST", "LOST_SAMPLES", "THROTTLE", "UNTHROTTLE"):
            self.assertEqual(d.counts[name], 1)

    def test_positive_read_lost_rejected_zero_accepted(self):
        for lost in (0, 123):
            content = struct.pack("<IIQQQ", 40, 42, 100, 11, lost)
            data = binary([sample(), record(8, content + trailer())])
            if lost:
                self.rejects(data, contains="READ lost")
            else:
                self.assertTrue(self.decode(data)[1]["ok"])

    def test_group_read_lost_rejected(self):
        def edit(_, a):
            struct.pack_into("<Q", a, 32, 28)
        data = binary([sample(), record(8, struct.pack("<IIQQQQ", 40, 42, 1, 99, 11, 5) + trailer())], attribute_edit=edit)
        self.rejects(data, contains="READ lost")

    def test_bad_ids_and_context(self):
        self.rejects(binary([sample(ident=999)]), contains="descriptor")
        self.rejects(binary([sample(ident=14)]), contains="descriptor")
        raw = bytearray(raw_event())
        struct.pack_into("<i", raw, 4, 777)
        self.rejects(binary([sample(raw=bytes(raw))]), contains="context TID")
        struct.pack_into("<H", raw, 0, 102)
        self.rejects(binary([sample(raw=bytes(raw))]), contains="common_type")

    def test_unknown_record_and_truncation(self):
        self.rejects(binary([sample(), record(81)]), contains="unsupported perf record")
        for n in (1, 7, 100):
            self.rejects(binary()[:-n])
        broken = bytearray(binary())
        data_off = struct.unpack_from("<Q", broken, 40)[0]
        struct.pack_into("<H", broken, data_off + 6, 7)
        self.rejects(bytes(broken), contains="record size")

    def test_sample_masks_clock_and_attributes(self):
        edits = [(24, "Q", 65536 | 2 | 4 | 128 | 1024 | 32), (92, "i", 0), (40, "Q", 1 << 18), (0, "I", 4), (16, "Q", 100)]
        for offset, fmt, value in edits:
            with self.subTest(offset=offset):
                def edit(i, a):
                    if i == 0:
                        struct.pack_into("<" + fmt, a, offset, value)
                self.rejects(binary(attribute_edit=edit))

    def test_features_and_section_bounds(self):
        _, report = self.decode(binary(features={21: struct.pack("<QQ", 5, 7), 29: struct.pack("<IIQQ", 1, 1, 1000, 20)}))
        self.assertEqual(report["features"][-1]["monotonic_ns"], 20)
        self.rejects(binary(features={27: b"\0" * 8}), contains="compressed")
        self.rejects(binary(features={29: struct.pack("<IIQQ", 1, 0, 0, 0)}), contains="clock data")
        data = bytearray(binary())
        struct.pack_into("<Q", data, 24, 0)
        self.rejects(bytes(data), contains="overlapping")
        data = bytearray(binary())
        data[:8] = b"2ELIFREP"
        self.rejects(bytes(data), contains="endian")

    def test_schema_bounds_names_types_and_duplicate_ids(self):
        for mutate in [lambda p: p['events']['sched_switch'].update(id=101), lambda p: p['events']['sched_switch'].update(format=p['events']['sched_switch']['format'].replace('offset:24', 'offset:16')), lambda p: p['events']['sched_switch'].update(format=p['events']['sched_switch']['format'].replace('size:8', 'size:3'))]:
            p = copy.deepcopy(preflight()[0]); mutate(p)
            self.rejects(binary(), p)

    def test_zero_synthesized_metadata_and_bad_live_trailer(self):
        comm = struct.pack("<II", 40, 42) + b"engine\0\0"
        data = binary([record(3, comm + b"\0" * 32), record(82), sample()])
        self.assertTrue(self.decode(data)[1]["ok"])
        self.rejects(binary([record(82), record(3, comm + b"\0" * 32), sample()]), contains="event ID")

    def test_conflicting_identifier_and_id_rejected(self):
        def edit(_, a):
            mask = struct.unpack_from("<Q", a, 24)[0]
            struct.pack_into("<Q", a, 24, mask | 64)
        # ID=12 disagrees with leading identifier11, even though both exist.
        body = struct.pack("<QIIQQII", 11, 40, 42, 12345, 12, 1, 0)
        raw = raw_event()
        self.rejects(binary([record(9, body + struct.pack("<I", len(raw)) + raw)], attribute_edit=edit), contains="descriptor")

    def test_id_index_cpu_and_duplicate_checks(self):
        index = record(69, struct.pack("<QQQQQ", 1, 11, 0, 0, 0xffffffffffffffff))
        self.rejects(binary([index, sample()]), contains="descriptor")
        index = record(69, struct.pack("<QQQQQ", 1, 11, 0, 1, 0xffffffffffffffff))
        self.assertTrue(self.decode(binary([index, sample()]))[1]["ok"])
        self.rejects(binary([index, index, sample()]), contains="duplicate ID_INDEX")

    def test_raw_size_and_wakeup_target_rejected(self):
        self.rejects(binary([sample(raw=raw_event() + b"\0" * 8)]), contains="raw tracepoint size")
        raw = bytearray(raw_event(1))
        struct.pack_into("<i", raw, 12, 99)
        self.rejects(binary([sample(1, raw=bytes(raw))]), contains="wakeup target")

    def test_cli_failure_preserves_counts_without_events_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'input').write_bytes(binary([sample(), record(13, struct.pack('<Q', 4) + trailer())]))
            (p / 'preflight').write_text(json.dumps(preflight()[0]))
            args = [sys.executable, str(Path(__file__).with_name('decode_scheduler_trace.py')), '--input', str(p / 'input'), '--preflight', str(p / 'preflight'), '--output', str(p / 'events'), '--summary', str(p / 'summary')]
            result = subprocess.run(args, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertFalse((p / 'events').exists())
            summary = json.loads((p / 'summary').read_text())
            self.assertEqual(summary['record_counts']['LOST_SAMPLES'], 1)
            self.assertFalse(summary['ok'])


if __name__ == '__main__':
    unittest.main()
