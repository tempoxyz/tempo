/-!
# Arithmetic soundness of the BitZ encoding

BitZ checks rank-1 constraints modulo `q = 2^100 - 15` over integers assembled
from lifted bits, so every lifted value is a natural number below `2^width`.
These lemmas justify each integer gadget in `src/relation.rs`: when all
operands are small enough, a constraint that holds modulo `q` holds over the
integers, and gated equalities on 64-bit chunks imply bitwise equality.
-/

namespace Tip1136

/-- The proof field modulus `Q100 = 2^100 - 15`. -/
def q : Int := 1267650600228229401496703205361

/-- Little-endian value of a bit list. -/
def lift : List Bool → Nat
  | [] => 0
  | b :: bs => b.toNat + 2 * lift bs

theorem lift_lt : ∀ bits : List Bool, lift bits < 2 ^ bits.length
  | [] => by simp [lift]
  | b :: bs => by
    have := lift_lt bs
    cases b <;> simp [lift, Nat.pow_succ] <;> omega

/-- Lifting is injective on equal-length bit lists. -/
theorem lift_injective : ∀ {a b : List Bool}, a.length = b.length → lift a = lift b → a = b
  | [], [], _, _ => rfl
  | x :: xs, y :: ys, hl, h => by
    simp only [lift] at h
    have hx : x = y := by cases x <;> cases y <;> simp at h ⊢ <;> omega
    subst hx
    have : lift xs = lift ys := by omega
    rw [lift_injective (by simpa using hl) this]

/-- A gated equality on chunks of at most 64 bits, `e * (lift a - lift b) ≡ 0
(mod q)` with Boolean `e = 1`, forces `a = b`. -/
theorem gated_chunk_eq {e : Int} {a b : List Bool} (hl : a.length = b.length)
    (hlen : a.length ≤ 64) (hgate : e = 1)
    (h : (e * ((lift a : Int) - lift b)) % q = 0) : a = b := by
  have ha := lift_lt a
  have hb := lift_lt b
  have hpow : 2 ^ a.length ≤ 2 ^ 64 := Nat.pow_le_pow_right (by decide) hlen
  rw [hl] at ha hpow
  subst hgate
  apply lift_injective hl
  simp only [q, Int.one_mul] at h
  have : (2 : Nat) ^ 64 = 18446744073709551616 := by decide
  omega

/-- The Merkle-step selector `d * (s - c) ≡ l - c (mod q)` with Boolean `d`
and 64-bit chunks picks `l = s` when `d = 1` and `l = c` when `d = 0`. -/
theorem select_chunk {d c s l : Int} (hd : d = 0 ∨ d = 1)
    (hc : 0 ≤ c ∧ c < 18446744073709551616) (hs : 0 ≤ s ∧ s < 18446744073709551616)
    (hl : 0 ≤ l ∧ l < 18446744073709551616)
    (h : (d * (s - c) - (l - c)) % q = 0) : l = if d = 1 then s else c := by
  rcases hd with rfl | rfl <;> simp [q] at h ⊢ <;> omega

/-- `threshold - 1 - m ≡ 0 (mod q)` with 32-bit `threshold` and `m` forces
`threshold ≥ 1`. -/
theorem threshold_positive {threshold m : Int}
    (ht : 0 ≤ threshold ∧ threshold < 4294967296) (hm : 0 ≤ m ∧ m < 4294967296)
    (h : (threshold - 1 - m) % q = 0) : 1 ≤ threshold := by
  simp [q] at h; omega

/-- `total - threshold - slack ≡ 0 (mod q)` with a 35-bit slack, a 32-bit
threshold, and a total of four 32-bit weights forces `threshold ≤ total`. -/
theorem threshold_met {total threshold slack : Int}
    (htotal : 0 ≤ total ∧ total < 4 * 4294967296)
    (ht : 0 ≤ threshold ∧ threshold < 4294967296)
    (hs : 0 ≤ slack ∧ slack < 34359738368)
    (h : (total - threshold - slack) % q = 0) : threshold ≤ total := by
  simp [q] at h; omega

/-- Packing: `next * (1 - current) ≡ 0` for Boolean flags means an enabled slot
is preceded by an enabled slot. -/
theorem packed_flags {current next : Int} (hc : current = 0 ∨ current = 1)
    (hn : next = 0 ∨ next = 1) (h : (next * (1 - current)) % q = 0) :
    next = 1 → current = 1 := by
  rcases hc with rfl | rfl <;> rcases hn with rfl | rfl <;> simp [q] at h ⊢

/-- Ordering: `next * (j - i - 1 - gap) ≡ 0` with 4-bit positions and gap
forces `i < j` for an enabled next slot. -/
theorem increasing_index {next i j gap : Int} (hn : next = 1)
    (hi : 0 ≤ i ∧ i < 16) (hj : 0 ≤ j ∧ j < 16) (hg : 0 ≤ gap ∧ gap < 16)
    (h : (next * (j - i - 1 - gap)) % q = 0) : i < j := by
  subst hn; simp [q] at h; omega

/-- Weight gating: `enabled * weight = counted` with Boolean `enabled` and
32-bit operands counts the weight exactly when the slot is enabled. -/
theorem counted_weight {enabled weight counted : Int} (he : enabled = 0 ∨ enabled = 1)
    (hw : 0 ≤ weight ∧ weight < 4294967296) (hc : 0 ≤ counted ∧ counted < 4294967296)
    (h : (enabled * weight - counted) % q = 0) :
    counted = if enabled = 1 then weight else 0 := by
  rcases he with rfl | rfl <;> simp [q] at h ⊢ <;> omega

end Tip1136
