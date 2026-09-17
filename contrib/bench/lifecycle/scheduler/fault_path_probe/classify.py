"""Experimental refinement; symbols remain private and only closed codes escape."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wait_reasons import classify_symbols

FAULT_REASON = 6


def classify(symbols, *, truncated=False):
    reason, status = classify_symbols(symbols, truncated=truncated)
    if (reason, status) != (2, 1):
        return reason, status
    # Kernel callchains are leaf to root: exact filemap_fault must be a caller
    # of the observed IO scheduler path, not an arbitrary symbol/prefix match.
    io = [i for i, symbol in enumerate(symbols) if symbol in (b'io_schedule', b'io_schedule_timeout')]
    ancestors = [i for i, symbol in enumerate(symbols) if symbol == b'filemap_fault']
    if any(parent > child for parent in ancestors for child in io):
        return FAULT_REASON, 1
    return reason, status
