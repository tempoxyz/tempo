import Kaizen.Simplex.Protocol

/-!
Kaizen.Simplex.Safety: inductive invariant of the Simplex protocol and its safety.
-/

namespace Kaizen.Simplex

open Block

variable {P : Type}

namespace State

variable {n : ℕ}

theorem mem_cast {s : State n P} {i j : Fin n} {m m' : Vote P} :
    (j, m') ∈ (s.cast i m).votes ↔ (j = i ∧ m' = m) ∨ (j, m') ∈ s.votes := by
  simp [cast]

theorem Cert.cast {q : ℕ} {s : State n P} {m : Vote P} (i : Fin n) (m' : Vote P)
    (h : s.Cert q m) : (s.cast i m').Cert q m := by
  obtain ⟨Q, hQ, hv⟩ := h
  exact ⟨Q, hQ, fun j hj => Set.mem_insert_of_mem _ (hv j hj)⟩

end State

section
variable {C : Config}

/-- The facts an honest notarize vote for 'b' certifies about the state when it was cast. -/
def NotarWF (C : Config) (s : State C.n P) (b : Block P) : Prop :=
  ∃ v x p, b = .mk v x p ∧ p.view < v ∧ (p = .genesis ∨ notarized C s p ∨ finalized C s p) ∧
    ∀ w, p.view < w → w < v → nullified C s w

theorem NotarWF.cast {s : State C.n P} {b : Block P} (i : Fin C.n) (m : Vote P)
    (h : NotarWF C s b) : NotarWF C (s.cast i m) b := by
  obtain ⟨v, x, p, hb, hv, hp, hw⟩ := h
  refine ⟨v, x, p, hb, hv, ?_, fun w h1 h2 => (hw w h1 h2).cast i m⟩
  rcases hp with hp | hp | hp
  · exact Or.inl hp
  · exact Or.inr (Or.inl (hp.cast i m))
  · exact Or.inr (Or.inr (hp.cast i m))

variable (C) in
/-- The inductive invariant: facts about honest validators' votes only. -/
structure Inv (s : State C.n P) : Prop where
  /-- An honest validator notarizes at most one proposal per view. -/
  notarize_once : ∀ i ∉ C.byz, ∀ b b' : Block P, (i, .notarize b) ∈ s.votes →
    (i, .notarize b') ∈ s.votes → b.view = b'.view → b = b'
  /-- An honest validator finalizes only the proposal it notarized at that view, if any. -/
  fin_notar : ∀ i ∉ C.byz, ∀ b b' : Block P, (i, .finalize b) ∈ s.votes →
    (i, .notarize b') ∈ s.votes → b.view = b'.view → b = b'
  /-- An honest validator never both finalizes and nullifies a view. -/
  fin_null : ∀ i ∉ C.byz, ∀ b : Block P, (i, .finalize b) ∈ s.votes →
    (i, .nullify b.view) ∉ s.votes
  /-- Honest notarize votes are well-founded on certified ancestry. -/
  notar_wf : ∀ i ∉ C.byz, ∀ b : Block P, (i, .notarize b) ∈ s.votes → NotarWF C s b
  /-- Honest finalize votes follow a notarization certificate. -/
  fin_cert : ∀ i ∉ C.byz, ∀ b : Block P, (i, .finalize b) ∈ s.votes → notarized C s b

theorem inv_init : Inv C (State.init : State C.n P) := by
  constructor <;> intros <;> simp_all [State.init]

theorem Inv.step {s s' : State C.n P} (hI : Inv C s) (hs : Step C s s') : Inv C s' := by
  cases hs with
  | byzantine i hi m =>
    have hne : ∀ j ∉ C.byz, j ≠ i := fun j hj h => hj (h ▸ hi)
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · intro j hj b b' h1 h2 hv
      simp only [State.mem_cast, hne j hj, false_and, false_or] at h1 h2
      exact hI.notarize_once j hj b b' h1 h2 hv
    · intro j hj b b' h1 h2 hv
      simp only [State.mem_cast, hne j hj, false_and, false_or] at h1 h2
      exact hI.fin_notar j hj b b' h1 h2 hv
    · intro j hj b h1 h2
      simp only [State.mem_cast, hne j hj, false_and, false_or] at h1 h2
      exact hI.fin_null j hj b h1 h2
    · intro j hj b h1
      simp only [State.mem_cast, hne j hj, false_and, false_or] at h1
      exact (hI.notar_wf j hj b h1).cast i m
    · intro j hj b h1
      simp only [State.mem_cast, hne j hj, false_and, false_or] at h1
      exact (hI.fin_cert j hj b h1).cast i m
  | notarize i hi v x p hview hparent hskip honce hfin =>
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · intro j hj b b' h1 h2 hv
      simp only [State.mem_cast, Vote.notarize.injEq] at h1 h2
      rcases h1 with ⟨rfl, rfl⟩ | h1 <;> rcases h2 with ⟨h2j, rfl⟩ | h2
      · rfl
      · exact (honce b' h2 (by simpa [view] using hv.symm)).symm
      · subst h2j; exact honce b h1 (by simpa [view] using hv)
      · exact hI.notarize_once j hj b b' h1 h2 hv
    · intro j hj b b' h1 h2 hv
      simp only [State.mem_cast, Vote.notarize.injEq, reduceCtorEq, and_false, false_or]
        at h1 h2
      rcases h2 with ⟨rfl, rfl⟩ | h2
      · exact hfin b h1 (by simpa [view] using hv)
      · exact hI.fin_notar j hj b b' h1 h2 hv
    · intro j hj b h1 h2
      simp only [State.mem_cast, reduceCtorEq, and_false, false_or] at h1 h2
      exact hI.fin_null j hj b h1 h2
    · intro j hj b h1
      simp only [State.mem_cast, Vote.notarize.injEq] at h1
      rcases h1 with ⟨rfl, rfl⟩ | h1
      · refine ⟨v, x, p, rfl, hview, ?_, fun w h1 h2 => (hskip w h1 h2).cast _ _⟩
        rcases hparent with hp | hp | hp
        · exact Or.inl hp
        · exact Or.inr (Or.inl (hp.cast _ _))
        · exact Or.inr (Or.inr (hp.cast _ _))
      · exact (hI.notar_wf j hj b h1).cast _ _
    · intro j hj b h1
      simp only [State.mem_cast, reduceCtorEq, and_false, false_or] at h1
      exact (hI.fin_cert j hj b h1).cast _ _
  | nullify i hi v hnf =>
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · intro j hj b b' h1 h2 hv
      simp only [State.mem_cast, reduceCtorEq, and_false, false_or] at h1 h2
      exact hI.notarize_once j hj b b' h1 h2 hv
    · intro j hj b b' h1 h2 hv
      simp only [State.mem_cast, reduceCtorEq, and_false, false_or] at h1 h2
      exact hI.fin_notar j hj b b' h1 h2 hv
    · intro j hj b h1 h2
      simp only [State.mem_cast, reduceCtorEq, and_false, false_or, Vote.nullify.injEq]
        at h1 h2
      rcases h2 with ⟨rfl, h2⟩ | h2
      · exact hnf b h1 h2
      · exact hI.fin_null j hj b h1 h2
    · intro j hj b h1
      simp only [State.mem_cast, reduceCtorEq, and_false, false_or] at h1
      exact (hI.notar_wf j hj b h1).cast _ _
    · intro j hj b h1
      simp only [State.mem_cast, reduceCtorEq, and_false, false_or] at h1
      exact (hI.fin_cert j hj b h1).cast _ _
  | finalize i hi b0 hcert hnn hno =>
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · intro j hj b b' h1 h2 hv
      simp only [State.mem_cast, reduceCtorEq, and_false, false_or] at h1 h2
      exact hI.notarize_once j hj b b' h1 h2 hv
    · intro j hj b b' h1 h2 hv
      simp only [State.mem_cast, reduceCtorEq, and_false, false_or, Vote.finalize.injEq]
        at h1 h2
      rcases h1 with ⟨rfl, rfl⟩ | h1
      · exact (hno b' h2 hv.symm).symm
      · exact hI.fin_notar j hj b b' h1 h2 hv
    · intro j hj b h1 h2
      simp only [State.mem_cast, reduceCtorEq, and_false, false_or, Vote.finalize.injEq]
        at h1 h2
      rcases h1 with ⟨rfl, rfl⟩ | h1
      · exact hnn h2
      · exact hI.fin_null j hj b h1 h2
    · intro j hj b h1
      simp only [State.mem_cast, reduceCtorEq, and_false, false_or] at h1
      exact (hI.notar_wf j hj b h1).cast _ _
    · intro j hj b h1
      simp only [State.mem_cast, Vote.finalize.injEq] at h1
      rcases h1 with ⟨rfl, rfl⟩ | h1
      · exact hcert.cast _ _
      · exact (hI.fin_cert j hj b h1).cast _ _

/-- Every reachable state satisfies the invariant. -/
theorem Reachable.inv {s : State C.n P} (hs : Reachable C s) : Inv C s := by
  induction hs with
  | init => exact inv_init
  | step _ hst ih => exact ih.step hst

/-- Quorum intersection: two quorums share an honest validator. -/
theorem honest_in_inter (A B : Finset (Fin C.n)) (hA : C.q ≤ A.card) (hB : C.q ≤ B.card) :
    ∃ i ∈ A, i ∈ B ∧ i ∉ C.byz := by
  by_contra h
  push Not at h
  have hsub : A ∩ B ⊆ C.byz := fun i hi => by
    rw [Finset.mem_inter] at hi
    exact h i hi.1 hi.2
  have h1 := Finset.card_le_card hsub
  have h2 := Finset.card_union_add_card_inter A B
  have h3 : (A ∪ B).card ≤ C.n := by simpa using Finset.card_le_univ (A ∪ B)
  have := C.byz_card
  have := C.quorum_inter
  omega

theorem cert_honest_pair {s : State C.n P} {m m' : Vote P} (h : s.Cert C.q m)
    (h' : s.Cert C.q m') : ∃ i ∉ C.byz, (i, m) ∈ s.votes ∧ (i, m') ∈ s.votes := by
  obtain ⟨A, hA, hAv⟩ := h
  obtain ⟨B, hB, hBv⟩ := h'
  obtain ⟨i, hiA, hiB, hi⟩ := honest_in_inter A B hA hB
  exact ⟨i, hi, hAv i hiA, hBv i hiB⟩

theorem cert_honest {s : State C.n P} {m : Vote P} (h : s.Cert C.q m) :
    ∃ i ∉ C.byz, (i, m) ∈ s.votes := by
  obtain ⟨i, hi, h1, -⟩ := cert_honest_pair h h
  exact ⟨i, hi, h1⟩

section
variable {s : State C.n P} (hI : Inv C s)
include hI

/-- A finalized view has no nullification certificate. -/
theorem Inv.finalized_not_nullified {b : Block P} (hb : finalized C s b) :
    ¬ nullified C s b.view := by
  intro hn
  obtain ⟨i, hi, h1, h2⟩ := cert_honest_pair hb hn
  exact hI.fin_null i hi b h1 h2

/-- A finalized proposal is the only notarized proposal at its view. -/
theorem Inv.finalized_notarized_unique {b b' : Block P} (hb : finalized C s b)
    (hb' : notarized C s b') (hv : b'.view = b.view) : b' = b := by
  obtain ⟨i, hi, h1, h2⟩ := cert_honest_pair hb hb'
  exact (hI.fin_notar i hi b b' h1 h2 hv.symm).symm

theorem Inv.notarized_wf {b : Block P} (hb : notarized C s b) : NotarWF C s b := by
  obtain ⟨i, hi, h⟩ := cert_honest hb
  exact hI.notar_wf i hi b h

theorem Inv.finalized_notarized {b : Block P} (hb : finalized C s b) : notarized C s b := by
  obtain ⟨i, hi, h⟩ := cert_honest hb
  exact hI.fin_cert i hi b h

theorem Inv.notarized_view_pos {b : Block P} (hb : notarized C s b) : 0 < b.view := by
  obtain ⟨v, x, p, rfl, hv, -⟩ := hI.notarized_wf hb
  simp only [view]
  omega

/-- Key lemma: every notarized proposal at a view at or above a finalized proposal's view
extends it (strong induction on the view). -/
theorem Inv.notarized_extends_finalized {b : Block P} (hb : finalized C s b) :
    ∀ w, ∀ c : Block P, c.view = w → notarized C s c → b.view ≤ w → Extends c b := by
  intro w
  induction w using Nat.strong_induction_on with
  | _ w ih =>
    intro c hcw hc hle
    rcases Nat.eq_or_lt_of_le hle with heq | hlt
    · rw [hI.finalized_notarized_unique hb hc (by omega)]
      exact Extends.refl _
    · obtain ⟨v, x, p, rfl, hpv, hpar, hskip⟩ := hI.notarized_wf hc
      simp only [view] at hcw
      subst hcw
      by_cases hpb : p.view < b.view
      · exact absurd (hskip _ hpb hlt) (hI.finalized_not_nullified hb)
      · push Not at hpb
        rcases hpar with rfl | hpn | hpf
        · have := hI.notarized_view_pos (hI.finalized_notarized hb)
          have h0 : (Block.genesis : Block P).view = 0 := rfl
          omega
        · exact Extends.step (ih p.view hpv p rfl hpn hpb)
        · exact Extends.step (ih p.view hpv p rfl (hI.finalized_notarized hpf) hpb)

end

/-- **Safety.** In every reachable state, any two proposals with finalization
certificates lie on one chain. -/
theorem safety {s : State C.n P} (hs : Reachable C s) {b b' : Block P}
    (hb : finalized C s b) (hb' : finalized C s b') :
    Block.Extends b b' ∨ Block.Extends b' b := by
  have hI := hs.inv
  rcases le_total b.view b'.view with h | h
  · exact Or.inr (hI.notarized_extends_finalized hb _ b' rfl (hI.finalized_notarized hb') h)
  · exact Or.inl (hI.notarized_extends_finalized hb' _ b rfl (hI.finalized_notarized hb) h)

/-- Two finalized proposals at the same height are equal. -/
theorem finalized_unique_at_height {s : State C.n P} (hs : Reachable C s) {b b' : Block P}
    (hb : finalized C s b) (hb' : finalized C s b') (hh : b.height = b'.height) : b = b' := by
  rcases safety hs hb hb' with h | h
  · exact h.eq_of_height_eq hh
  · exact (h.eq_of_height_eq hh.symm).symm

/-- Two finalized proposals at the same view are equal. -/
theorem finalized_unique_at_view {s : State C.n P} (hs : Reachable C s) {b b' : Block P}
    (hb : finalized C s b) (hb' : finalized C s b') (hv : b.view = b'.view) : b = b' :=
  (hs.inv.finalized_notarized_unique hb (hs.inv.finalized_notarized hb') hv.symm).symm

/-- A view with a finalization certificate never also gets a nullification certificate. -/
theorem finalized_not_nullified {s : State C.n P} (hs : Reachable C s) {b : Block P}
    (hb : finalized C s b) : ¬ nullified C s b.view :=
  hs.inv.finalized_not_nullified hb

end

end Kaizen.Simplex
