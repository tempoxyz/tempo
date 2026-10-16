import Tip1136.Relation

/-!
# Split profile: two kind-typed slot groups

`Profile::Split` orders slots only within each group (secp256k1 slots, then
passkey slots). `quorum_of_holds_split` shows this still never counts a roster
position twice: positions in different groups hold members of different
committed kinds, and each leaf commits to exactly one kind.
-/

namespace Tip1136

variable {Member Evidence Digest Kind : Type}

/-- The relation for two groups whose enabled members have kinds `ka ≠ kb`. -/
def HoldsSplit (approves : Member → Evidence → Digest → Prop) (weight : Member → Nat)
    (kind : Member → Kind) (policy : Policy Member) (digest : Digest) (ka kb : Kind)
    (ga gb : List (Slot Member Evidence)) : Prop :=
  ka ≠ kb ∧
  1 ≤ policy.threshold ∧
  Packed ga ∧
  Packed gb ∧
  (∀ s ∈ ga ++ gb, s.enabled = true →
    policy.roster[s.index]? = some s.member ∧ approves s.member s.evidence digest) ∧
  (∀ s ∈ ga, s.enabled = true → kind s.member = ka) ∧
  (∀ s ∈ gb, s.enabled = true → kind s.member = kb) ∧
  policy.threshold ≤ countedWeight weight (ga ++ gb)

/-- **Quorum soundness for the split profile.** -/
theorem quorum_of_holds_split {approves : Member → Evidence → Digest → Prop}
    {weight : Member → Nat} {kind : Member → Kind} {policy : Policy Member}
    {digest : Digest} {ka kb : Kind} {ga gb : List (Slot Member Evidence)}
    (h : HoldsSplit approves weight kind policy digest ka kb ga gb) :
    ∃ positions : List Nat,
      positions.Nodup ∧
      (∀ i ∈ positions, ∃ m e, policy.roster[i]? = some m ∧ approves m e digest) ∧
      policy.threshold ≤ (positions.map (rosterWeight weight policy)).sum := by
  obtain ⟨hk, _, hpa, hpb, hmember, hka, hkb, hweight⟩ := h
  refine ⟨((ga ++ gb).filter (·.enabled)).map (·.index), ?_, ?_, ?_⟩
  · rw [List.filter_append, List.map_append, List.nodup_append]
    refine ⟨(enabled_increasing hpa).imp Nat.ne_of_lt,
      (enabled_increasing hpb).imp Nat.ne_of_lt, ?_⟩
    intro i hi j hj hij
    subst hij
    obtain ⟨sa, hmem_a, rfl⟩ := List.mem_map.mp hi
    obtain ⟨sb, hmem_b, hidx⟩ := List.mem_map.mp hj
    have hmem_a' := List.mem_filter.mp hmem_a
    have hmem_b' := List.mem_filter.mp hmem_b
    have ea : sa.enabled = true := by simpa using hmem_a'.2
    have eb : sb.enabled = true := by simpa using hmem_b'.2
    have ra := (hmember sa (List.mem_append_left _ hmem_a'.1) ea).1
    have rb := (hmember sb (List.mem_append_right _ hmem_b'.1) eb).1
    rw [hidx] at rb
    have hm : sb.member = sa.member := Option.some.inj (rb.symm.trans ra)
    exact hk ((hka sa hmem_a'.1 ea).symm.trans (hm ▸ hkb sb hmem_b'.1 eb))
  · intro i hi
    obtain ⟨s, hs, rfl⟩ := List.mem_map.mp hi
    have hs' := List.mem_filter.mp hs
    obtain ⟨hroster, happroves⟩ := hmember s hs'.1 (by simpa using hs'.2)
    exact ⟨s.member, s.evidence, hroster, happroves⟩
  · have hsame : (((ga ++ gb).filter (·.enabled)).map (·.index)).map
        (rosterWeight weight policy) =
        ((ga ++ gb).filter (·.enabled)).map fun s => weight s.member := by
      rw [List.map_map]
      apply List.map_congr_left
      intro s hs
      have hs' := List.mem_filter.mp hs
      have hroster := (hmember s hs'.1 (by simpa using hs'.2)).1
      simp [rosterWeight, hroster]
    rw [hsame]
    exact hweight

end Tip1136
