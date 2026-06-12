import Std

set_option autoImplicit false

namespace Tempo.Nonce

/-!
Model and machine-checked invariants for `crates/precompiles/src/nonce/mod.rs`.

The model intentionally abstracts away EVM storage, events, ABI decoding, and hash
collision behavior. It captures the nonce/replay state transition that the Rust
precompile implements:

* 2D nonce keys reject key `0`, increment by one, and reject overflow.
* Expiring nonce writes accept only the configured validity window.
* An unexpired seen hash is rejected as replay.
* The ring slot can only be overwritten when empty or expired.
* Accepted writes record the hash and keep the ring pointer bounded.
-/

abbrev Account := Nat
abbrev NonceKey := Nat
abbrev Hash := Nat

def u64Max : Nat := 18446744073709551615

def expiringNonceSetCapacity : Nat := 300000

def expiringNonceMaxExpirySecs : Nat := 30

abbrev NonceTable := Account -> NonceKey -> Nat

def writeNonce
    (table : NonceTable)
    (account : Account)
    (key : NonceKey)
    (value : Nat) : NonceTable :=
  fun account' key' =>
    if account' = account ∧ key' = key then value else table account' key'

def incrementNonce
    (table : NonceTable)
    (account : Account)
    (key : NonceKey) : Option (Nat × NonceTable) :=
  if key = 0 then
    none
  else
    let current := table account key
    if current = u64Max then
      none
    else
      let next := current + 1
      some (next, writeNonce table account key next)

theorem writeNonce_same
    (table : NonceTable)
    (account : Account)
    (key : NonceKey)
    (value : Nat) :
    writeNonce table account key value account key = value := by
  simp [writeNonce]

theorem writeNonce_other_account
    (table : NonceTable)
    (account other : Account)
    (key key' : NonceKey)
    (value : Nat)
    (hother : other ≠ account) :
    writeNonce table account key value other key' = table other key' := by
  simp [writeNonce, hother]

theorem writeNonce_other_key
    (table : NonceTable)
    (account : Account)
    (key other : NonceKey)
    (value : Nat)
    (hother : other ≠ key) :
    writeNonce table account key value account other = table account other := by
  simp [writeNonce, hother]

theorem incrementNonce_rejects_protocol_key
    (table : NonceTable)
    (account : Account) :
    incrementNonce table account 0 = none := by
  simp [incrementNonce]

theorem incrementNonce_rejects_overflow
    (table : NonceTable)
    (account : Account)
    (key : NonceKey)
    (hkey : key ≠ 0)
    (hoverflow : table account key = u64Max) :
    incrementNonce table account key = none := by
  simp [incrementNonce, hkey, hoverflow]

theorem incrementNonce_success
    (table : NonceTable)
    (account : Account)
    (key : NonceKey)
    (hkey : key ≠ 0)
    (hcurrent : table account key ≠ u64Max) :
    incrementNonce table account key =
      some
        ( table account key + 1
        , writeNonce table account key (table account key + 1)
        ) := by
  simp [incrementNonce, hkey, hcurrent]

structure ExpiringState where
  seen : Hash -> Nat
  ring : Nat -> Hash
  ptr : Nat

abbrev validExpiry (now validBefore : Nat) : Prop :=
  now < validBefore ∧ validBefore ≤ now + expiringNonceMaxExpirySecs

abbrev stillSeen (state : ExpiringState) (hash : Hash) (now : Nat) : Prop :=
  state.seen hash ≠ 0 ∧ now < state.seen hash

inductive MarkError where
  | invalidExpiry
  | replay
  | setFull
  deriving DecidableEq, Repr

def ringNext (capacity ptr : Nat) : Nat :=
  if ptr + 1 ≥ capacity then 0 else ptr + 1

def writeRing (ring : Nat -> Hash) (ptr : Nat) (hash : Hash) : Nat -> Hash :=
  fun ptr' => if ptr' = ptr then hash else ring ptr'

def clearThenSet
    (seen : Hash -> Nat)
    (oldHash hash : Hash)
    (validBefore : Nat) : Hash -> Nat :=
  fun hash' =>
    if hash' = hash then
      validBefore
    else if hash' = oldHash then
      0
    else
      seen hash'

def setSeen
    (seen : Hash -> Nat)
    (hash : Hash)
    (validBefore : Nat) : Hash -> Nat :=
  fun hash' => if hash' = hash then validBefore else seen hash'

def checkAndMarkExpiringNonce
    (capacity now expiringNonceHash validBefore : Nat)
    (state : ExpiringState) : Except MarkError ExpiringState :=
  if validExpiry now validBefore then
    if stillSeen state expiringNonceHash now then
      .error .replay
    else
      let oldHash := state.ring state.ptr
      if oldHash = 0 then
        .ok
          { seen := setSeen state.seen expiringNonceHash validBefore
            ring := writeRing state.ring state.ptr expiringNonceHash
            ptr := ringNext capacity state.ptr }
      else if stillSeen state oldHash now then
        .error .setFull
      else
        .ok
          { seen := clearThenSet state.seen oldHash expiringNonceHash validBefore
            ring := writeRing state.ring state.ptr expiringNonceHash
            ptr := ringNext capacity state.ptr }
  else
    .error .invalidExpiry

theorem setSeen_new
    (seen : Hash -> Nat)
    (hash : Hash)
    (validBefore : Nat) :
    setSeen seen hash validBefore hash = validBefore := by
  simp [setSeen]

theorem clearThenSet_new
    (seen : Hash -> Nat)
    (oldHash hash : Hash)
    (validBefore : Nat) :
    clearThenSet seen oldHash hash validBefore hash = validBefore := by
  simp [clearThenSet]

theorem clearThenSet_old
    (seen : Hash -> Nat)
    (oldHash hash : Hash)
    (validBefore : Nat)
    (hneq : oldHash ≠ hash) :
    clearThenSet seen oldHash hash validBefore oldHash = 0 := by
  simp [clearThenSet, hneq]

theorem writeRing_at
    (ring : Nat -> Hash)
    (ptr : Nat)
    (hash : Hash) :
    writeRing ring ptr hash ptr = hash := by
  simp [writeRing]

theorem ringNext_lt_capacity
    (capacity ptr : Nat)
    (hcapacity : 0 < capacity) :
    ringNext capacity ptr < capacity := by
  unfold ringNext
  by_cases hwrap : ptr + 1 ≥ capacity
  · simp [hwrap, hcapacity]
  · simp [hwrap]
    omega

theorem invalid_expiry_rejected
    (capacity now expiringNonceHash validBefore : Nat)
    (state : ExpiringState)
    (hexpiry : ¬ validExpiry now validBefore) :
    checkAndMarkExpiringNonce capacity now expiringNonceHash validBefore state =
      .error .invalidExpiry := by
  unfold checkAndMarkExpiringNonce
  rw [if_neg hexpiry]

theorem unexpired_seen_hash_rejected
    (capacity now expiringNonceHash validBefore : Nat)
    (state : ExpiringState)
    (hexpiry : validExpiry now validBefore)
    (hreplay : stillSeen state expiringNonceHash now) :
    checkAndMarkExpiringNonce capacity now expiringNonceHash validBefore state =
      .error .replay := by
  unfold checkAndMarkExpiringNonce
  rw [if_pos hexpiry, if_pos hreplay]

theorem unexpired_ring_slot_rejected
    (capacity now expiringNonceHash validBefore : Nat)
    (state : ExpiringState)
    (hexpiry : validExpiry now validBefore)
    (hnoReplay : ¬ stillSeen state expiringNonceHash now)
    (hold : state.ring state.ptr ≠ 0)
    (hfull : stillSeen state (state.ring state.ptr) now) :
    checkAndMarkExpiringNonce capacity now expiringNonceHash validBefore state =
      .error .setFull := by
  unfold checkAndMarkExpiringNonce
  rw [if_pos hexpiry, if_neg hnoReplay, if_neg hold, if_pos hfull]

theorem accepted_empty_slot_records_hash
    (capacity now expiringNonceHash validBefore : Nat)
    (state : ExpiringState)
    (hexpiry : validExpiry now validBefore)
    (hnoReplay : ¬ stillSeen state expiringNonceHash now)
    (hempty : state.ring state.ptr = 0) :
    match checkAndMarkExpiringNonce capacity now expiringNonceHash validBefore state with
    | .ok state' =>
        state'.seen expiringNonceHash = validBefore ∧
          state'.ring state.ptr = expiringNonceHash
    | .error _ => False := by
  unfold checkAndMarkExpiringNonce
  rw [if_pos hexpiry, if_neg hnoReplay, if_pos hempty]
  simp [setSeen, writeRing]

theorem accepted_evictable_slot_records_hash
    (capacity now expiringNonceHash validBefore : Nat)
    (state : ExpiringState)
    (hexpiry : validExpiry now validBefore)
    (hnoReplay : ¬ stillSeen state expiringNonceHash now)
    (hold : state.ring state.ptr ≠ 0)
    (hevict : ¬ stillSeen state (state.ring state.ptr) now) :
    match checkAndMarkExpiringNonce capacity now expiringNonceHash validBefore state with
    | .ok state' =>
        state'.seen expiringNonceHash = validBefore ∧
          state'.ring state.ptr = expiringNonceHash
    | .error _ => False := by
  unfold checkAndMarkExpiringNonce
  rw [if_pos hexpiry, if_neg hnoReplay, if_neg hold, if_neg hevict]
  simp [clearThenSet, writeRing]

theorem accepted_empty_slot_ptr_bounded
    (capacity now expiringNonceHash validBefore : Nat)
    (state : ExpiringState)
    (hcapacity : 0 < capacity)
    (hexpiry : validExpiry now validBefore)
    (hnoReplay : ¬ stillSeen state expiringNonceHash now)
    (hempty : state.ring state.ptr = 0) :
    match checkAndMarkExpiringNonce capacity now expiringNonceHash validBefore state with
    | .ok state' => state'.ptr < capacity
    | .error _ => False := by
  unfold checkAndMarkExpiringNonce
  rw [if_pos hexpiry, if_neg hnoReplay, if_pos hempty]
  simpa using ringNext_lt_capacity capacity state.ptr hcapacity

theorem accepted_evictable_slot_ptr_bounded
    (capacity now expiringNonceHash validBefore : Nat)
    (state : ExpiringState)
    (hcapacity : 0 < capacity)
    (hexpiry : validExpiry now validBefore)
    (hnoReplay : ¬ stillSeen state expiringNonceHash now)
    (hold : state.ring state.ptr ≠ 0)
    (hevict : ¬ stillSeen state (state.ring state.ptr) now) :
    match checkAndMarkExpiringNonce capacity now expiringNonceHash validBefore state with
    | .ok state' => state'.ptr < capacity
    | .error _ => False := by
  unfold checkAndMarkExpiringNonce
  rw [if_pos hexpiry, if_neg hnoReplay, if_neg hold, if_neg hevict]
  simpa using ringNext_lt_capacity capacity state.ptr hcapacity

end Tempo.Nonce
