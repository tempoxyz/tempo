"""Tempo compatibility hooks for EEST ``execute remote`` benchmark tests.

EEST funds generated test EOAs with native-value transfers. Tempo has no
native currency and rejects every non-zero ``msg.value`` transaction.  This
plugin keeps EEST's account and gas-budget calculation intact, then replaces
each simple EOA funding transaction with an equivalent pathUSD TIP-20
``transfer(address,uint256)`` before it is signed and submitted.

Load the module with::

    PYTHONPATH=/path/to/tempo/contrib/bench/eest \
    PYTEST_PLUGINS=tempo_eest_adapter \
    uv run execute remote ...

The adapter intentionally covers plain ``pre.fund_eoa`` calls only. Tests
which attach storage or EIP-7702 delegation to a funded EOA are left to a
future Tempo-specific account adapter and fail explicitly.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any
from urllib import request

import pytest
from execution_testing.base_types import Address, Bytes, HexNumber
from execution_testing.cli.pytest_commands.plugins.execute.pre_alloc import Alloc

# A newly generated EOA has no user fee-token preference, so a legacy
# transaction to a regular contract resolves to the protocol fallback,
# pathUSD. (The pre-funded dev seed itself has BetaUSD configured.)
DEV_FEE_TOKEN = Address("0x20c0000000000000000000000000000000000000")
TIP20_TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")
TIP20_TRANSFER_GAS_LIMIT = 2_000_000
TEMPO_CONTRACT_DEPLOY_GAS_LIMIT = 30_000_000
CAPTURE_FILE_ENV = "TEMPO_CAPTURE_FILE"
CAPTURE_RPC_ENV = "TEMPO_CAPTURE_RPC_URL"


def _rpc_block_number() -> int:
    """Read the canonical head used to delimit one EEST test execution."""
    rpc_url = os.environ.get(CAPTURE_RPC_ENV)
    if not rpc_url:
        raise RuntimeError(f"{CAPTURE_RPC_ENV} must be set when capturing blocks")
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_blockNumber",
            "params": [],
        }
    ).encode()
    last_error: Exception | None = None
    for _ in range(20):
        try:
            rpc_request = request.Request(
                rpc_url,
                data=body,
                headers={"content-type": "application/json"},
            )
            with request.urlopen(rpc_request, timeout=5) as response:
                result = json.load(response)["result"]
            return int(result, 16)
        except Exception as error:  # pragma: no cover - only exercised on RPC loss
            last_error = error
            time.sleep(0.25)
    raise RuntimeError(f"failed to read Tempo block number: {last_error}")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: Any, call: Any):
    """Remember the call outcome for the surrounding capture hook."""
    outcome = yield
    report = outcome.get_result()
    if report.when == "call":
        item._tempo_call_outcome = report.outcome


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item: Any, nextitem: Any):
    """Record the block interval created by each independently named EEST case."""
    del nextitem
    capture_file = os.environ.get(CAPTURE_FILE_ENV)
    before_block = _rpc_block_number() if capture_file else None
    yield
    if not capture_file:
        return

    record = {
        "nodeid": item.nodeid,
        "before_block": before_block,
        "after_block": _rpc_block_number(),
        "outcome": getattr(item, "_tempo_call_outcome", "failed"),
    }
    with open(capture_file, "a", encoding="utf-8") as output:
        output.write(json.dumps(record, separators=(",", ":")))
        output.write("\n")


def _tip20_transfer_data(recipient: Address, amount: int) -> Bytes:
    """ABI-encode ``transfer(recipient, amount)`` without another dependency."""
    return Bytes(
        TIP20_TRANSFER_SELECTOR
        + bytes(recipient).rjust(32, b"\x00")
        + amount.to_bytes(32, byteorder="big")
    )


def pytest_configure(config: Any) -> None:
    """Install the funding conversion once after EEST loads its plugins."""
    del config
    if getattr(Alloc, "_tempo_tip20_funding_adapter", False):
        return

    original = Alloc.minimum_balance_for_pending_transactions

    def minimum_balance_for_pending_transactions(
        self: Alloc,
        *args: Any,
        **kwargs: Any,
    ) -> tuple[int, int]:
        result = original(self, *args, **kwargs)

        for tx in self._pending_txs:
            metadata = tx.metadata
            # Tempo's state-gas and storage-credit accounting makes EEST's
            # Ethereum-only code-deposit estimate too small for the large
            # generated benchmark contracts. The dev chainspec permits a
            # 30M transaction, so give setup deployments that ceiling.
            if tx.to is None:
                tx.gas_limit = HexNumber(
                    max(int(tx.gas_limit), TEMPO_CONTRACT_DEPLOY_GAS_LIMIT)
                )
            if metadata is None or metadata.action != "fund_eoa":
                continue
            if tx.authorization_list:
                raise RuntimeError(
                    "Tempo EEST adapter does not yet support funding EOAs "
                    "with storage or EIP-7702 delegation"
                )
            if tx.to is None:
                raise RuntimeError("EEST fund_eoa transaction has no recipient")

            recipient = Address(tx.to)
            amount = int(tx.value or 0)
            tx.to = DEV_FEE_TOKEN
            tx.data = _tip20_transfer_data(recipient, amount)
            tx.value = HexNumber(0)
            tx.gas_limit = HexNumber(
                max(int(tx.gas_limit), TIP20_TRANSFER_GAS_LIMIT)
            )

        return result

    Alloc.minimum_balance_for_pending_transactions = (
        minimum_balance_for_pending_transactions
    )
    Alloc._tempo_tip20_funding_adapter = True
