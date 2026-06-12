import Tempo.Nonce.Model
import Lean.Data.Json.FromToJson

open Lean

namespace Tempo.Nonce

structure FixtureMapEntry where
  key : Nat
  value : Nat

instance : ToJson FixtureMapEntry where
  toJson entry :=
    Json.mkObj
      [ ("key", toJson entry.key)
      , ("value", toJson entry.value)
      ]

structure FixtureInput where
  name : String
  capacity : Nat
  now : Nat
  ptr : Nat
  seen : List FixtureMapEntry
  ring : List FixtureMapEntry
  hash : Nat
  validBefore : Nat

structure FixtureExpected where
  result : String
  ptr : Nat
  seen : List FixtureMapEntry
  ring : List FixtureMapEntry

instance : ToJson FixtureExpected where
  toJson expected :=
    Json.mkObj
      [ ("result", toJson expected.result)
      , ("ptr", toJson expected.ptr)
      , ("seen", toJson expected.seen)
      , ("ring", toJson expected.ring)
      ]

structure FixtureCase where
  name : String
  capacity : Nat
  now : Nat
  ptr : Nat
  seen : List FixtureMapEntry
  ring : List FixtureMapEntry
  hash : Nat
  validBefore : Nat
  expected : FixtureExpected

instance : ToJson FixtureCase where
  toJson testCase :=
    Json.mkObj
      [ ("name", toJson testCase.name)
      , ("capacity", toJson testCase.capacity)
      , ("now", toJson testCase.now)
      , ("ptr", toJson testCase.ptr)
      , ("seen", toJson testCase.seen)
      , ("ring", toJson testCase.ring)
      , ("hash", toJson testCase.hash)
      , ("valid_before", toJson testCase.validBefore)
      , ("expected", toJson testCase.expected)
      ]

def lookupSparse (entries : List FixtureMapEntry) (key default : Nat) : Nat :=
  match entries with
  | [] => default
  | entry :: rest =>
      if entry.key = key then entry.value else lookupSparse rest key default

def stateOfFixture (testCase : FixtureInput) : ExpiringState :=
  { seen := fun hash => lookupSparse testCase.seen hash 0
    ring := fun ptr => lookupSparse testCase.ring ptr 0
    ptr := testCase.ptr }

def pushUnique (values : List Nat) (value : Nat) : List Nat :=
  if values.contains value then values else values ++ [value]

def unique (values : List Nat) : List Nat :=
  values.foldl pushUnique []

def nonzeroUnique (values : List Nat) : List Nat :=
  unique (values.filter fun value => value != 0)

def relevantHashes (testCase : FixtureInput) : List Nat :=
  let ringHashes := testCase.ring.map (fun entry => entry.value)
  let seenHashes := testCase.seen.map (fun entry => entry.key)
  let oldHash := lookupSparse testCase.ring testCase.ptr 0
  nonzeroUnique ([testCase.hash, oldHash] ++ ringHashes ++ seenHashes)

def relevantRingSlots (testCase : FixtureInput) : List Nat :=
  unique ([testCase.ptr] ++ testCase.ring.map (fun entry => entry.key))

def seenAssertions (state : ExpiringState) (hashes : List Nat) : List FixtureMapEntry :=
  hashes.map fun hash => { key := hash, value := state.seen hash }

def ringAssertions (state : ExpiringState) (slots : List Nat) : List FixtureMapEntry :=
  slots.map fun ptr => { key := ptr, value := state.ring ptr }

def markErrorName : MarkError -> String
  | .invalidExpiry => "invalid_expiry"
  | .replay => "replay"
  | .setFull => "set_full"

def expectedFor (testCase : FixtureInput) : FixtureExpected :=
  let state := stateOfFixture testCase
  let hashes := relevantHashes testCase
  let ringSlots := relevantRingSlots testCase
  match
    checkAndMarkExpiringNonce
      testCase.capacity
      testCase.now
      testCase.hash
      testCase.validBefore
      state
  with
  | .ok state' =>
      { result := "ok"
        ptr := state'.ptr
        seen := seenAssertions state' hashes
        ring := ringAssertions state' ringSlots }
  | .error error =>
      { result := markErrorName error
        ptr := state.ptr
        seen := seenAssertions state hashes
        ring := ringAssertions state ringSlots }

def toFixtureCase (input : FixtureInput) : FixtureCase :=
  { name := input.name
    capacity := input.capacity
    now := input.now
    ptr := input.ptr
    seen := input.seen
    ring := input.ring
    hash := input.hash
    validBefore := input.validBefore
    expected := expectedFor input }

def fixtureInputs : List FixtureInput :=
  [ { name := "empty_slot_accepts_and_records_hash"
      capacity := expiringNonceSetCapacity
      now := 1000
      ptr := 0
      seen := []
      ring := []
      hash := 17
      validBefore := 1020 }
  , { name := "unexpired_seen_hash_rejects_replay"
      capacity := expiringNonceSetCapacity
      now := 1000
      ptr := 0
      seen := [{ key := 17, value := 1020 }]
      ring := [{ key := 0, value := 17 }]
      hash := 17
      validBefore := 1020 }
  , { name := "valid_before_at_now_is_invalid"
      capacity := expiringNonceSetCapacity
      now := 1000
      ptr := 0
      seen := []
      ring := []
      hash := 34
      validBefore := 1000 }
  , { name := "valid_before_past_max_window_is_invalid"
      capacity := expiringNonceSetCapacity
      now := 1000
      ptr := 0
      seen := []
      ring := []
      hash := 35
      validBefore := 1031 }
  , { name := "unexpired_ring_slot_rejects_when_set_full"
      capacity := expiringNonceSetCapacity
      now := 1000
      ptr := 0
      seen := [{ key := 48, value := 1020 }]
      ring := [{ key := 0, value := 48 }]
      hash := 49
      validBefore := 1010 }
  , { name := "expired_ring_slot_evicts_and_records_new_hash"
      capacity := expiringNonceSetCapacity
      now := 1000
      ptr := 0
      seen := [{ key := 64, value := 990 }]
      ring := [{ key := 0, value := 64 }]
      hash := 65
      validBefore := 1010 }
  , { name := "expired_same_hash_at_ring_slot_can_be_reused"
      capacity := expiringNonceSetCapacity
      now := 1000
      ptr := 0
      seen := [{ key := 80, value := 990 }]
      ring := [{ key := 0, value := 80 }]
      hash := 80
      validBefore := 1015 }
  , { name := "ring_pointer_wraps_at_capacity"
      capacity := expiringNonceSetCapacity
      now := 1000
      ptr := expiringNonceSetCapacity - 1
      seen := []
      ring := []
      hash := 96
      validBefore := 1020 }
  ]

def fixtureJson : Json :=
  toJson (fixtureInputs.map toFixtureCase)

end Tempo.Nonce

def main : IO Unit :=
  IO.println Tempo.Nonce.fixtureJson.pretty
