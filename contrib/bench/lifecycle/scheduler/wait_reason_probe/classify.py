"""Closed kernel wait-path vocabulary; symbols are transient private inputs only."""
from enum import IntEnum


class Reason(IntEnum):
    UNKNOWN = 0
    FUTEX_WAIT = 1
    KERNEL_IO_SCHEDULE = 2
    TIMER_SLEEP = 3
    PIPE_READ = 4
    POLL_WAIT = 5


# Exact symbols only. Kernel/compiler variants not explicitly listed stay unknown.
SYMBOLS = {
    b'futex_wait_queue': Reason.FUTEX_WAIT,
    b'futex_wait_queue_me': Reason.FUTEX_WAIT,
    b'futex_wait': Reason.FUTEX_WAIT,
    b'__futex_wait': Reason.FUTEX_WAIT,
    b'futex_wait_multiple': Reason.FUTEX_WAIT,
    b'futex_wait_requeue_pi': Reason.FUTEX_WAIT,
    b'io_schedule': Reason.KERNEL_IO_SCHEDULE,
    b'io_schedule_timeout': Reason.KERNEL_IO_SCHEDULE,
    b'hrtimer_nanosleep': Reason.TIMER_SLEEP,
    b'do_nanosleep': Reason.TIMER_SLEEP,
    b'pipe_read': Reason.PIPE_READ,
    b'ep_poll': Reason.POLL_WAIT,
    b'do_poll': Reason.POLL_WAIT,
    b'do_select': Reason.POLL_WAIT,
}


def classify(symbols):
    """Conflicting positive categories stay unknown; absence is not an 'other' proof."""
    found = {SYMBOLS[symbol] for symbol in symbols if symbol in SYMBOLS}
    return next(iter(found)) if len(found) == 1 else Reason.UNKNOWN


def admit_sample(timestamp, cutoff, state, reason):
    """Illustrative strict-boundary contract, not a scheduler interval join."""
    if any(type(x) is not int for x in (timestamp, cutoff, state, reason)):
        raise ValueError('invalid wait reason sample')
    if timestamp < 0 or cutoff <= 0 or state not in (0, 1, 2, 4, 8, 16, 32, 64, 128, 256):
        raise ValueError('invalid wait reason sample')
    if reason not in set(Reason):
        raise ValueError('invalid wait reason sample')
    if timestamp >= cutoff or state not in (1, 2):
        return None
    return reason


def covered(registrations, samples):
    """Exact synthetic role admission; an empty successful attach proves nothing."""
    if len(registrations) != 3 or len(samples) != 3 or any(type(x) is not int or x < 0 for x in registrations + samples):
        raise ValueError('invalid synthetic coverage')
    return registrations == [1, 1, 1] and all(samples)
