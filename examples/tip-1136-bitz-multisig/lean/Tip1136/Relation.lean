/-!
# TIP-1136 private weighted multisig: relation and quorum soundness

`Holds` is the statement the BitZ circuit enforces once its hash and signature
gadgets are abstracted: Merkle membership plus the policy-commitment opening
become `roster[index]? = some member` (by collision resistance of SHA-256), and
each credential check becomes `approves member evidence digest`.

`quorum_of_holds` shows that any satisfying slot assignment exhibits a set of
*distinct* roster positions, each approving the digest, whose committed
weights reach the threshold. `holds_of_quorum` is the converse: any such
quorum of at most `slots` members, listed in increasing roster order, can be
encoded.
-/

namespace Tip1136

/-- One approval slot. Disabled slots are padding. -/
structure Slot (Member Evidence : Type) where
  enabled : Bool
  index : Nat
  member : Member
  evidence : Evidence

/-- The private policy: roster position `i` holds leaf `i`. -/
structure Policy (Member : Type) where
  roster : List Member
  threshold : Nat

variable {Member Evidence Digest : Type}

/-- Enabled slots come first, with strictly increasing roster positions. -/
def Packed : List (Slot Member Evidence) → Prop
  | a :: b :: rest => (b.enabled → a.enabled ∧ a.index < b.index) ∧ Packed (b :: rest)
  | _ => True

/-- Total weight counted by the enabled slots. -/
def countedWeight (weight : Member → Nat) (slots : List (Slot Member Evidence)) : Nat :=
  ((slots.filter (·.enabled)).map fun s => weight s.member).sum

/-- The relation proved by the circuit, with cryptography abstracted. -/
def Holds (approves : Member → Evidence → Digest → Prop) (weight : Member → Nat)
    (policy : Policy Member) (digest : Digest) (slots : List (Slot Member Evidence)) : Prop :=
  1 ≤ policy.threshold ∧
  Packed slots ∧
  (∀ s ∈ slots, s.enabled = true →
    policy.roster[s.index]? = some s.member ∧ approves s.member s.evidence digest) ∧
  policy.threshold ≤ countedWeight weight slots

theorem packed_tail {a : Slot Member Evidence} {l : List (Slot Member Evidence)}
    (h : Packed (a :: l)) : Packed l := by
  match l, h with
  | [], _ => trivial
  | _ :: _, h => exact h.2

/-- An enabled slot later in a packed list forces every earlier slot to be
enabled and to sit at a strictly smaller roster position. -/
theorem packed_before {a : Slot Member Evidence} :
    ∀ {l : List (Slot Member Evidence)}, Packed (a :: l) →
      ∀ s ∈ l, s.enabled = true → a.enabled = true ∧ a.index < s.index
  | [], _, s, hs, _ => by simp at hs
  | b :: rest, h, s, hs, he => by
    have hab := h.1
    rcases List.mem_cons.mp hs with rfl | hs
    · exact hab he
    · have hb := packed_before h.2 s hs he
      have ha := hab hb.1
      exact ⟨ha.1, Nat.lt_trans ha.2 hb.2⟩

/-- Enabled slots have pairwise strictly increasing roster positions. -/
theorem enabled_increasing :
    ∀ {l : List (Slot Member Evidence)}, Packed l →
      ((l.filter (·.enabled)).map (·.index)).Pairwise (· < ·)
  | [], _ => by simp
  | a :: l, h => by
    have ih := enabled_increasing (packed_tail h)
    by_cases ha : a.enabled = true
    · simp only [List.filter_cons, ha, if_true, List.map_cons, List.pairwise_cons]
      refine ⟨?_, ih⟩
      intro i hi
      obtain ⟨s, hs, rfl⟩ := List.mem_map.mp hi
      have hs' := List.mem_filter.mp hs
      exact (packed_before h s hs'.1 (by simpa using hs'.2)).2
    · simp only [List.filter_cons, ha]
      simpa using ih

/-- Roster weight at a position (zero for empty positions). -/
def rosterWeight (weight : Member → Nat) (policy : Policy Member) (i : Nat) : Nat :=
  (policy.roster[i]?.map weight).getD 0

/-- **Quorum soundness.** A satisfying assignment exhibits distinct roster
positions, each holding a member that approved `digest`, whose committed
weights reach the threshold. Padding contributes nothing, and the same member
position cannot be counted twice. -/
theorem quorum_of_holds {approves : Member → Evidence → Digest → Prop}
    {weight : Member → Nat} {policy : Policy Member} {digest : Digest}
    {slots : List (Slot Member Evidence)}
    (h : Holds approves weight policy digest slots) :
    ∃ positions : List Nat,
      positions.Nodup ∧
      (∀ i ∈ positions, ∃ m e, policy.roster[i]? = some m ∧ approves m e digest) ∧
      policy.threshold ≤ (positions.map (rosterWeight weight policy)).sum := by
  obtain ⟨_, hpacked, hmember, hweight⟩ := h
  refine ⟨(slots.filter (·.enabled)).map (·.index), ?_, ?_, ?_⟩
  · exact (enabled_increasing hpacked).imp Nat.ne_of_lt
  · intro i hi
    obtain ⟨s, hs, rfl⟩ := List.mem_map.mp hi
    have hs' := List.mem_filter.mp hs
    obtain ⟨hroster, happroves⟩ := hmember s hs'.1 (by simpa using hs'.2)
    exact ⟨s.member, s.evidence, hroster, happroves⟩
  · have hsame : ((slots.filter (·.enabled)).map (·.index)).map (rosterWeight weight policy) =
        (slots.filter (·.enabled)).map fun s => weight s.member := by
      rw [List.map_map]
      apply List.map_congr_left
      intro s hs
      have hs' := List.mem_filter.mp hs
      have hroster := (hmember s hs'.1 (by simpa using hs'.2)).1
      simp [rosterWeight, hroster]
    rw [hsame]
    exact hweight

/-- A disabled padding slot. -/
def pad (filler : Slot Member Evidence) : Slot Member Evidence :=
  { filler with enabled := false }

theorem packed_pad (filler : Slot Member Evidence) :
    ∀ n, Packed (List.replicate n (pad filler))
  | 0 => trivial
  | 1 => trivial
  | n + 2 => by
    refine ⟨fun h => by simp [pad] at h, ?_⟩
    simpa [List.replicate_succ] using packed_pad filler (n + 1)

theorem packed_append_pad (filler : Slot Member Evidence) :
    ∀ {l : List (Slot Member Evidence)} (n : Nat),
      (l.map (·.index)).Pairwise (· < ·) → (∀ s ∈ l, s.enabled = true) →
      Packed (l ++ List.replicate n (pad filler))
  | [], n, _, _ => by simpa using packed_pad filler n
  | [_], 0, _, _ => trivial
  | [_], n + 1, _, _ => by
    refine ⟨fun h => by simp [pad] at h, ?_⟩
    simpa [List.replicate_succ] using packed_pad filler (n + 1)
  | a :: b :: rest, n, hinc, hen => by
    simp only [List.map_cons, List.pairwise_cons] at hinc
    refine ⟨fun _ => ⟨hen a (by simp), hinc.1 b.index (by simp)⟩, ?_⟩
    exact packed_append_pad filler n
      (by simpa using hinc.2) (fun s hs => hen s (List.mem_cons_of_mem a hs))

/-- **Completeness.** Approvals by members at strictly increasing roster
positions whose weights reach a positive threshold can be encoded in
`approvals.length + padding` slots. -/
theorem holds_of_quorum {approves : Member → Evidence → Digest → Prop}
    {weight : Member → Nat} {policy : Policy Member} {digest : Digest}
    (approvals : List (Slot Member Evidence)) (filler : Slot Member Evidence) (padding : Nat)
    (hthreshold : 1 ≤ policy.threshold)
    (henabled : ∀ s ∈ approvals, s.enabled = true)
    (hincreasing : (approvals.map (·.index)).Pairwise (· < ·))
    (hvalid : ∀ s ∈ approvals,
      policy.roster[s.index]? = some s.member ∧ approves s.member s.evidence digest)
    (hweight : policy.threshold ≤ (approvals.map fun s => weight s.member).sum) :
    Holds approves weight policy digest (approvals ++ List.replicate padding (pad filler)) := by
  refine ⟨hthreshold, packed_append_pad filler padding hincreasing henabled, ?_, ?_⟩
  · intro s hs he
    rcases List.mem_append.mp hs with hs | hs
    · exact hvalid s hs
    · obtain ⟨rfl⟩ := (List.eq_of_mem_replicate hs)
      simp [pad] at he
  · have hfilter : (approvals ++ List.replicate padding (pad filler)).filter (·.enabled) =
        approvals := by
      rw [List.filter_append, List.filter_eq_self.mpr (fun s hs => by simpa using henabled s hs)]
      simp [pad]
    simp only [countedWeight, hfilter]
    exact hweight

end Tip1136
