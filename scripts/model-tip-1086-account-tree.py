#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pycryptodome==3.23.0"]
# ///
"""Exercise the account-tree design, not consensus execution or gas benchmarks.

Run: uv run scripts/model-tip-1086-account-tree.py
The model keeps full local tree data. Witness-only insertion/deletion encoding,
signatures, transaction serialization, and production journaling are not modeled.
"""

from dataclasses import dataclass, replace

from Crypto.Hash import keccak


def digest(data):
    return keccak.new(digest_bits=256, data=data).digest()


def branch(left, right):
    return digest(b"tempo:account-tree:model:branch" + left + right)


EMPTY = digest(b"tempo:account-tree:model:empty")
MAX_POLICIES = 256


@dataclass(frozen=True)
class Leaf:
    grant_id: int
    policy_hash: bytes
    spent: int = 0
    window: int = 0

    def hash(self):
        # A single token is sufficient for these state-transition checks.
        return digest(
            b"tempo:account-tree:model:leaf"
            + self.grant_id.to_bytes(8, "big")
            + self.policy_hash
            + self.spent.to_bytes(32, "big")
            + self.window.to_bytes(8, "big")
        )


def levels(leaves):
    count = len(leaves)
    width = 1 << (max(1, count) - 1).bit_length()
    result = [[leaf.hash() for leaf in leaves] + [EMPTY] * (width - count)]
    while len(result[-1]) > 1:
        row = result[-1]
        result.append([branch(row[i], row[i + 1]) for i in range(0, len(row), 2)])
    return result


def root(leaves):
    return levels(leaves)[-1][0]


def proof(leaves, index):
    if not 0 <= index < len(leaves):
        raise ValueError("index outside live tree")
    result = []
    for row in levels(leaves)[:-1]:
        result.append(row[index ^ 1])
        index //= 2
    return result


def root_from_proof(leaf_hash, index, count, siblings):
    if not 0 <= index < count or not 1 <= count <= MAX_POLICIES:
        raise ValueError("invalid index/count")
    if len(siblings) != (count - 1).bit_length():
        raise ValueError("noncanonical proof length")
    value = leaf_hash
    for sibling in siblings:
        if len(sibling) != 32:
            raise ValueError("invalid sibling length")
        value = branch(sibling, value) if index & 1 else branch(value, sibling)
        index //= 2
    return value


class Account:
    def __init__(self):
        self.authority = digest(b"initial-authority")
        self.epoch = 0
        self.next_id = 0
        self.leaves = []

    def commitment(self):
        return digest(
            b"tempo:account-tree:model:account:v2"
            + self.authority
            + self.epoch.to_bytes(8, "big")
            + self.next_id.to_bytes(8, "big")
            + len(self.leaves).to_bytes(2, "big")
            + root(self.leaves)
        )

    def install(self, approved_id):
        if approved_id != self.next_id or self.next_id == 2**64 - 1:
            raise ValueError("stale approval or exhausted allocator")
        if len(self.leaves) == MAX_POLICIES:
            raise ValueError("policy capacity")
        self.leaves.append(
            Leaf(approved_id, digest(b"policy" + bytes([approved_id % 256])))
        )
        self.next_id += 1

    def update(self, index, new_leaf, siblings):
        old_leaf = self.leaves[index]
        if (old_leaf.grant_id, old_leaf.policy_hash) != (
            new_leaf.grant_id,
            new_leaf.policy_hash,
        ):
            raise ValueError("spending cannot replace policy identity")
        if root_from_proof(old_leaf.hash(), index, len(self.leaves), siblings) != root(
            self.leaves
        ):
            raise ValueError("stale or invalid proof")
        expected = root_from_proof(new_leaf.hash(), index, len(self.leaves), siblings)
        self.leaves[index] = new_leaf
        assert root(self.leaves) == expected

    def remove(self, index):
        # Full-tree model of swap-delete; a consensus implementation needs a
        # bounded authenticated two-position update and contraction witness.
        removed = self.leaves[index]
        last = self.leaves.pop()
        if index < len(self.leaves):
            self.leaves[index] = last
        return removed

    def rotate(self):
        self.epoch += 1
        self.authority = digest(b"rotated" + self.epoch.to_bytes(8, "big"))
        self.leaves.clear()


def rejects(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError("expected rejection")


def check():
    account = Account()
    empty = account.commitment()
    counts = {1, 2, 4, 8, 16, 64, 256}
    proof_checks = 0
    for count in range(1, MAX_POLICIES + 1):
        account.install(account.next_id)
        assert len(account.commitment()) == 32 and account.commitment() != empty
        for index in {0, count // 2, count - 1}:
            siblings = proof(account.leaves, index)
            old_leaf = account.leaves[index]
            assert root_from_proof(old_leaf.hash(), index, count, siblings) == root(
                account.leaves
            )
            account.update(index, replace(old_leaf, spent=old_leaf.spent + 1), siblings)
            proof_checks += 1
        if count in counts:
            depth = len(proof(account.leaves, 0))
            print(
                f"{count:3} policies: {depth} siblings, {32 * depth:3} bytes, <= {512 * depth:4} byte gas"
            )
    rejects(lambda: account.install(account.next_id))
    old_ids = {leaf.grant_id for leaf in account.leaves}
    while account.leaves:
        index = len(account.leaves) // 2
        last = account.leaves[-1]
        removed = account.remove(index)
        old_ids.remove(removed.grant_id)
        assert {leaf.grant_id for leaf in account.leaves} == old_ids
        if index < len(account.leaves):
            assert account.leaves[index] == last  # full budget survives compaction
        assert len(account.commitment()) == 32
        for i in (
            {0, len(account.leaves) // 2, len(account.leaves) - 1}
            if account.leaves
            else set()
        ):
            leaf = account.leaves[i]
            assert root_from_proof(
                leaf.hash(), i, len(account.leaves), proof(account.leaves, i)
            ) == root(account.leaves)
            proof_checks += 1
    assert root(account.leaves) == EMPTY and account.commitment() != empty
    rejects(lambda: account.install(0))  # deletion does not authorize reinstallation
    account.install(account.next_id)
    old_id = account.leaves[0].grant_id
    account.rotate()
    rejects(lambda: account.install(old_id))
    account.install(account.next_id)

    # An empty sibling path is valid only for the singleton case.
    assert proof(account.leaves, 0) == []
    rejects(lambda: root_from_proof(account.leaves[0].hash(), 0, 1, [EMPTY]))
    account.install(account.next_id)
    stale = proof(account.leaves, 0)
    account.update(1, replace(account.leaves[1], spent=3), proof(account.leaves, 1))
    rejects(lambda: account.update(0, replace(account.leaves[0], spent=4), stale))
    leaf = account.leaves[0]
    account.update(0, replace(leaf, spent=4), proof(account.leaves, 0))
    rejects(
        lambda: account.update(
            0, replace(account.leaves[0], grant_id=0), proof(account.leaves, 0)
        )
    )

    # Reservation survives user-call rollback; settlement retains only actual fees.
    before = account.leaves[0]
    reserved, actual_fee, user_debit, cap = 100, 30, 50, 1000
    assert before.spent + reserved + user_debit <= cap
    account.update(
        0, replace(before, spent=before.spent + reserved), proof(account.leaves, 0)
    )
    checkpoint = account.leaves.copy()
    account.update(
        0,
        replace(account.leaves[0], spent=account.leaves[0].spent + user_debit),
        proof(account.leaves, 0),
    )
    account.leaves = checkpoint  # reverted execution, not fee reservation
    account.update(
        0,
        replace(
            account.leaves[0], spent=account.leaves[0].spent - (reserved - actual_fee)
        ),
        proof(account.leaves, 0),
    )
    assert account.leaves[0].spent == before.spent + actual_fee
    assert account.leaves[1].spent == 3
    print(
        f"PASS: {proof_checks:,} proof checks; growth/shrink, stable IDs, stale proofs, rotation, fee rollback. No gas execution benchmark."
    )


if __name__ == "__main__":
    check()
