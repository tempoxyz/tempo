"""Closed diagnostic vocabulary; never echo private exceptions or tool output."""

STAGES = frozenset(('configuration', 'capability', 'marker', 'capture', 'cutoff', 'decode', 'publish'))
REASONS = {
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
    return rows
