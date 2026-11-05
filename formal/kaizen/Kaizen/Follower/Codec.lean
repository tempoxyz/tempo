/-
Kaizen follower: Commonware Finalization certificate codec (Mathlib-free, executable).

Wire format (commonware-consensus simplex Finalization<Scheme<_, MinSig>, Digest>):
  epoch  : u64 varint (LEB128, canonical)
  view   : u64 varint
  parent : u64 varint
  payload: 32 bytes (block digest)
  cert   : 96 bytes (threshold BLS12-381 MinSig: two 48-byte G1 signatures)

Varint rules mirror commonware_codec::varint::Decoder::feed exactly:
  * a byte equal to 0 after the first byte is rejected (non-canonical),
  * the 10th byte (bits_read = 63) may only carry 1 data bit (so it must be 1),
    which rejects both > 10-byte encodings and overflow past 64 bits.
-/

namespace Kaizen.Follower

/-! ## Spec level codec over List UInt8 / Nat -/

/-- Spec varint decoder. i is the byte index (bits_read = 7*i), acc the value so far. -/
def varAux : Nat → Nat → List UInt8 → Option (Nat × List UInt8)
  | _, _, [] => none
  | i, acc, b :: rest =>
    if i ≠ 0 ∧ b.toNat = 0 then none
    else if i = 9 ∧ 2 ≤ b.toNat then none
    else
      let acc' := acc + (b.toNat % 128) * 2 ^ (7 * i)
      if b.toNat < 128 then some (acc', rest) else varAux (i + 1) acc' rest

/-- Spec varint decoder for a u64. -/
def decodeVarint (bs : List UInt8) : Option (Nat × List UInt8) := varAux 0 0 bs

/-- Spec (canonical LEB128) varint encoder. -/
def encodeVarint (n : Nat) : List UInt8 :=
  if n < 128 then [n.toUInt8]
  else (n % 128 + 128).toUInt8 :: encodeVarint (n / 128)
termination_by n
decreasing_by omega

/-- Spec-level decoded finalization certificate. -/
structure SpecCert where
  epoch : Nat
  view : Nat
  parent : Nat
  payload : List UInt8
  sig : List UInt8
  deriving DecidableEq, Repr

/-- Spec decoder: rejects malformed varints, short input and trailing bytes. -/
def specDecode (bs : List UInt8) : Option SpecCert :=
  match varAux 0 0 bs with
  | none => none
  | some (e, r1) =>
    match varAux 0 0 r1 with
    | none => none
    | some (v, r2) =>
      match varAux 0 0 r2 with
      | none => none
      | some (p, r3) =>
        if r3.length = 128 then some ⟨e, v, p, r3.take 32, r3.drop 32⟩ else none

/-- Spec encoder. -/
def specEncode (c : SpecCert) : List UInt8 :=
  encodeVarint c.epoch ++ encodeVarint c.view ++ encodeVarint c.parent ++ c.payload ++ c.sig

/-- Well-formed certificates: u64 fields and exact byte lengths. -/
def SpecCert.WF (c : SpecCert) : Prop :=
  c.epoch < 2 ^ 64 ∧ c.view < 2 ^ 64 ∧ c.parent < 2 ^ 64 ∧
    c.payload.length = 32 ∧ c.sig.length = 96

/-! ## Executable codec over ByteArray / UInt64 -/

/-- Executable decoded certificate. -/
structure Cert where
  epoch : UInt64
  view : UInt64
  parent : UInt64
  payload : ByteArray
  sig : ByteArray

/-- Executable varint reader starting at byte offset pos (byte index i, accumulator acc).
Returns the value and the offset just past it. -/
def readVarint (b : ByteArray) (pos i : Nat) (acc : UInt64) : Option (UInt64 × Nat) :=
  if h : pos < b.size then
    let x := b[pos]
    if i ≠ 0 ∧ x = 0 then none
    else if i = 9 ∧ 2 ≤ x then none
    else
      let acc' := acc + ((x % 128).toUInt64 <<< (7 * i).toUInt64)
      if x < 128 then some (acc', pos + 1) else readVarint b (pos + 1) (i + 1) acc'
  else none
termination_by b.size - pos

/-- Executable certificate decoder. -/
def decodeCert (b : ByteArray) : Option Cert :=
  match readVarint b 0 0 0 with
  | none => none
  | some (e, p1) =>
    match readVarint b p1 0 0 with
    | none => none
    | some (v, p2) =>
      match readVarint b p2 0 0 with
      | none => none
      | some (pv, p3) =>
        if p3 + 128 = b.size then
          some ⟨e, v, pv, b.extract p3 (p3 + 32), b.extract (p3 + 32) (p3 + 128)⟩
        else none

/-- Abstraction of an executable certificate to the spec certificate. -/
def Cert.toSpec (c : Cert) : SpecCert :=
  ⟨c.epoch.toNat, c.view.toNat, c.parent.toNat, c.payload.data.toList, c.sig.data.toList⟩

end Kaizen.Follower
