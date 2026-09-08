"""Keep setup receipt barriers, but pipeline the zone workload's protocol nonces.

The renderer uses one protocol-nonce lane for every workload transaction, which
already enforces FIFO execution. Txgen's additional sequence inclusion key would
wait a full block between withdrawals and throttle the benchmark sender.
"""

import json
import sys


def main():
    for line in sys.stdin:
        transaction = json.loads(line)
        if transaction["phase"] == "workload":
            transaction["inclusion_keys"] = []
        print(json.dumps(transaction), flush=True)


if __name__ == "__main__":
    main()
