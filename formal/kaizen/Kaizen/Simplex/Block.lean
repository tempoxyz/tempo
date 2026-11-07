import Mathlib

/-!
Kaizen.Simplex.Block: abstract proposals (blocks), ancestry and height.

A proposal is either the genesis proposal (view 0) or a proposal at view v carrying an
application payload and its parent proposal. Carrying the parent itself (not only its
view) models the assumption that a proposal's payload digest commits to its parent.
-/

namespace Kaizen.Simplex

/-- Abstract Simplex proposals. 'P' is the type of application payloads (block digests). -/
inductive Block (P : Type) where
  /-- The genesis proposal, implicitly finalized at view 0. -/
  | genesis : Block P
  /-- A proposal at view 'view' with payload 'payload' building on 'parent'. -/
  | mk (view : ℕ) (payload : P) (parent : Block P) : Block P
  deriving DecidableEq

namespace Block

variable {P : Type}

/-- The view (round) of a proposal; genesis is at view 0. -/
def view : Block P → ℕ
  | genesis => 0
  | mk v _ _ => v

/-- Height in the chain: genesis has height 0, each proposal one more than its parent. -/
def height : Block P → ℕ
  | genesis => 0
  | mk _ _ p => height p + 1

/-- 'Extends c b': 'b' is an ancestor-or-equal of 'c'. -/
inductive Extends : Block P → Block P → Prop where
  | refl (b : Block P) : Extends b b
  | step {v : ℕ} {x : P} {p b : Block P} : Extends p b → Extends (mk v x p) b

theorem Extends.trans {a b c : Block P} (h1 : Extends c b) (h2 : Extends b a) :
    Extends c a := by
  induction h1 with
  | refl => exact h2
  | step _ ih => exact Extends.step (ih h2)

theorem Extends.height_le {b c : Block P} (h : Extends c b) : b.height ≤ c.height := by
  induction h with
  | refl => exact le_rfl
  | step _ ih => simp only [height]; omega

/-- Two blocks on one chain with equal height are equal. -/
theorem Extends.eq_of_height_eq {b c : Block P} (h : Extends c b)
    (hh : c.height = b.height) : c = b := by
  cases h with
  | refl => rfl
  | step h' =>
    have := h'.height_le
    simp only [height] at hh
    omega

/-- Genesis is an ancestor of every proposal. -/
theorem extends_genesis (b : Block P) : Extends b genesis := by
  induction b with
  | genesis => exact Extends.refl _
  | mk _ _ _ ih => exact Extends.step ih

end Block

end Kaizen.Simplex
