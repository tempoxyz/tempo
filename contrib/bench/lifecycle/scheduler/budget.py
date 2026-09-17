"""Fixed opt-in diagnostic disk budgets; exceeding any budget fails closed."""
SOURCE_BYTES = 12 * 1024**3
INDEX_BYTES = 6 * 1024**3
FOCUSED_BYTES = 8 * 1024**3


class Budget:
    def __init__(self, limit):
        self.remaining = limit

    def write(self, destination, data):
        size = len(data) if isinstance(data,bytes) else len(data.encode())
        if size > self.remaining:
            raise ValueError('scheduler publication limit exceeded')
        self.remaining -= size
        return destination.write(data)

COMPRESSED_SOURCE_BYTES = 2 * 1024**3


class CappedSink:
    """Write-only gzip sink that counts compressed bytes, including its footer."""
    def __init__(self, destination, budget):
        self.destination, self.budget = destination, budget

    def write(self, data):
        return self.budget.write(self.destination,data)

    def flush(self):
        return self.destination.flush()

    def tell(self):
        return self.destination.tell()
