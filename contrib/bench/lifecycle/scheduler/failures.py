"""Closed diagnostic vocabulary; never echo private exceptions or tool output."""

import json

EVIDENCE_FIELDS = frozenset(('retained', 'emitted', 'lost', 'invalid', 'overflow', 'io_error',
                             'received', 'observed_duration_ns', 'kept', 'pruned'))

STAGES = frozenset(('configuration', 'capability', 'marker', 'capture', 'cutoff', 'decode', 'publish'))
REASONS = {
    ('decode', 'scheduler publication limit exceeded'): 'decode_publication_limit',
    ('decode', 'scheduler spool I/O failed'): 'decode_spool_io',
    ('decode', 'scheduler spool limit exceeded'): 'decode_spool_limit',
    ('decode', 'scheduler capture tool reported diagnostics'): 'decode_stderr',
    ('capability', 'binary scheduler prerequisite unavailable'): 'capability_binary_transport',
    ('decode', 'unexpected binary scheduler output'): 'decode_binary_schema',
    ('decode', 'scheduler memory limit exceeded; diagnostic unavailable'): 'decode_buffer_limit',
    ('decode', 'scheduler capture tool exited unsuccessfully'): 'decode_child_exit',
    ('capture', 'scheduler memory limit exceeded; diagnostic unavailable'): 'capture_buffer_limit',
    ('capture', 'unexpected private tool output'): 'capture_encoding',
    ('capture', 'scheduler capture tool exited unsuccessfully'): 'capture_exit',
    ('capture', 'scheduler capture tool reported diagnostics'): 'capture_stderr',
    ('cutoff', 'lifecycle capture integrity failed'): 'cutoff_source_integrity',
    ('cutoff', 'lifecycle shutdown or footer incomplete'): 'cutoff_source_footer',
    ('cutoff', 'load window unavailable'): 'cutoff_window_missing',
    ('cutoff', 'invalid scheduler cutoff'): 'cutoff_invalid',
    ('decode', 'unexpected ordinal/event'): 'decode_event_schema',
    ('decode', 'unexpected scheduler state'): 'decode_state_schema',
    ('decode', 'unexpected tool output'): 'decode_output_schema',
    ('decode', 'capture tool reported event loss'): 'decode_event_loss',
    ('decode', 'unexpected private cutoff marker'): 'decode_cutoff_marker',
    ('decode', 'missing boundary/footer or event loss'): 'decode_count_or_footer',
    ('decode', 'clock mismatch'): 'decode_clock',
    ('decode', 'ordinal reused'): 'decode_ordinal_reuse',
    ('decode', 'registration/exit gap'): 'decode_registration_gap',
    ('decode', 'registration/exit coverage incomplete'): 'decode_exit_coverage',
    ('decode', 'missing switch-in'): 'decode_missing_switch_in',
    ('decode', 'missing switch-out'): 'decode_missing_switch_out',
}
CODES = STAGES | frozenset(REASONS.values())


def failure_code(stage, error):
    return REASONS.get((stage, str(error)), stage if stage in STAGES else 'unavailable')


def failure_summary(directory):
    rows = []
    for role in ('a', 'b'):
        try:
            with (directory / f'scheduler-{role}.failed').open() as source:
                value = source.read(128).strip()
        except OSError:
            value = 'unavailable'
        code = value if value in CODES else 'unavailable'
        rows.append(f'Scheduler validator {role}: startup/capture failure category {code}')
        try:
            with (directory / f'scheduler-{role}.evidence.json').open() as source:
                data = source.read(2049)
            evidence = json.loads(data) if len(data) <= 2048 else None
            if (isinstance(evidence, dict) and set(evidence) <= EVIDENCE_FIELDS
                    and all(type(value) is int and 0 <= value < 2**64 for value in evidence.values())):
                rows.append(f'Scheduler validator {role}: numeric capture evidence ' +
                            ' '.join(f'{key}={evidence[key]}' for key in sorted(evidence)))
        except (OSError, ValueError):
            pass
    return rows
