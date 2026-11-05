/-
Kaizen follower: Stage I theorems about the abstract follower (soundness, chain linkage,
agreement, progress) for arbitrary, adversarial input sequences.

The outside world is abstract:
* Finalized h d p : the block at height h with digest d and parent digest p was finalized
  by the validator set of its epoch.
* Committed c : the candidate's header-derived fields (height, parentDigest, dkg) are the ones
  committed by c.blockDigest (the unverified shim computes blockDigest by hashing the header it
  parsed these fields from; this is the hash-binding obligation of the shim).
* Sound e k : k is a trustworthy identity (group public key) for epoch e.
* Executed pre d post : executing the block with digest d on the state with root pre is a valid
  state transition yielding the state with root post. Committed c also binds c.stateRoot (a
  header field) to c.blockDigest.
-/
import Mathlib.Tactic
import Kaizen.Follower.Spec
import Kaizen.Follower.CodecProofs

namespace Kaizen.Follower

set_option linter.deprecated false

/-- Assumptions about cryptography, Simplex and the shim. -/
structure Assumptions (verify : Verify) (verifyExec : VerifyExec)
    (Finalized : Nat → ByteArray → ByteArray → Prop) (Committed : Candidate → Prop)
    (Executed : ByteArray → ByteArray → ByteArray → Prop) (Sound : Nat → ByteArray → Prop)
    (epochLength fromEpoch : Nat) (networkKey : ByteArray) : Prop where
  /-- H_crypto: a certificate that verifies under a sound identity for its epoch means the
  block with that payload digest was finalized (BLS soundness + Simplex certificate meaning). -/
  crypto : ∀ (e : Nat) (k : ByteArray) (v p : UInt64) (sig : ByteArray) (c : Candidate),
    Sound e k → verify k e.toUInt64 v p c.blockDigest sig = true → Committed c →
    Finalized c.height c.blockDigest c.parentDigest
  /-- The configured network identity is sound for every epoch from fromEpoch on. -/
  network : ∀ e, fromEpoch ≤ e → Sound e networkKey
  /-- H_boundary: identities learned from finalized boundary blocks are sound. -/
  boundary : ∀ (c : Candidate) (e : Nat) (k : ByteArray), Committed c →
    Finalized c.height c.blockDigest c.parentDigest →
    c.height % epochLength = epochLength - 1 → c.dkg = some (e, k) → Sound e k
  /-- H_exec: the execution oracle is sound for a header-committed post-state root. -/
  exec : ∀ (pre : ByteArray) (c : Candidate), verifyExec pre c.blockDigest c.stateRoot = true →
    Committed c → Executed pre c.blockDigest c.stateRoot

/-- H_unique: at most one finalized digest per height (from Simplex safety). -/
def UniqueFinalized (Finalized : Nat → ByteArray → ByteArray → Prop) : Prop :=
  ∀ h d1 p1 d2 p2, Finalized h d1 p1 → Finalized h d2 p2 → d1 = d2

/-- Follower invariant. -/
def Inv (Finalized : Nat → ByteArray → ByteArray → Prop) (Sound : Nat → ByteArray → Prop)
    (s : State) : Prop :=
  (∀ t, s.tip = some t → ∃ p, Finalized t.height t.digest p) ∧
  (∀ e k, s.learned e = some k → Sound e k)

theorem inv_init (Finalized : Nat → ByteArray → ByteArray → Prop) (Sound : Nat → ByteArray → Prop)
    (L f : Nat) (k : ByteArray) : Inv Finalized Sound (State.init L f k) := by
  constructor <;> simp [State.init]

lemma payload_eq {fc : SpecCert} {d : ByteArray} (h : fc.payload = d.data.toList) :
    (⟨fc.payload.toArray⟩ : ByteArray) = d := by
  apply ByteArray.ext; simp [h]

lemma tipCheck_some (t : Tip) (c : Candidate) (fc : SpecCert) :
    tipCheck (some t) c fc = none ↔
      c.height = t.height + 1 ∧ c.parentDigest = t.digest ∧
          roundLt t.epoch t.view fc.epoch fc.view := by
  simp only [tipCheck]; split_ifs <;> simp_all

/-- Shape of an accepting step. -/
theorem step_accept_shape {verify : Verify} {verifyExec : VerifyExec} {s s' : State} {c : Candidate}
    (h : step verify verifyExec s c = (Code.accepted, s')) :
    ∃ fc key learned', specDecode c.cert.data.toList = some fc ∧
      fc.payload = c.blockDigest.data.toList ∧ s.epochLength ≠ 0 ∧
      fc.epoch = c.height / s.epochLength ∧ tipCheck s.tip c fc = none ∧
      dkgCheck s.epochLength s.learned c fc = .ok learned' ∧ s.identity fc.epoch = some key ∧
      verify key fc.epoch.toUInt64 fc.view.toUInt64 fc.parent.toUInt64
        ⟨fc.payload.toArray⟩ ⟨fc.sig.toArray⟩ = true ∧
      execOk verifyExec s.tip c = true ∧
      s' = { s with tip := some ⟨c.height, c.blockDigest, fc.epoch, fc.view, c.stateRoot⟩,
                    learned := learned' } := by
  unfold step at h
  split_ifs at h with hL
  · simp [Code.badConfig, Code.accepted] at h
  split at h
  · simp [Code.malformed, Code.accepted] at h
  rename_i fc hdec
  split_ifs at h with hp he
  · simp [Code.digestMismatch, Code.accepted] at h
  · simp [Code.epochMismatch, Code.accepted] at h
  split at h
  · rename_i code htc
    have : code ≠ Code.accepted := by
      unfold tipCheck at htc; split at htc
      · simp at htc
      · split_ifs at htc <;> simp at htc <;> subst htc <;> decide
    simp only [Prod.mk.injEq] at h; exact absurd h.1 this
  rename_i htc
  split at h
  · rename_i code hdk
    have : code ≠ Code.accepted := by
      unfold dkgCheck at hdk; split_ifs at hdk
      · split at hdk
        · simp at hdk; subst hdk; decide
        · split_ifs at hdk
          all_goals (simp at hdk; subst hdk; decide)
    simp only [Prod.mk.injEq] at h; exact absurd h.1 this
  rename_i learned' hdk
  split at h
  · simp [Code.identityUnavailable, Code.accepted] at h
  rename_i key hid
  split_ifs at h with hv
  · simp [Code.badSignature, Code.accepted] at h
  unfold accept at h
  split_ifs at h with hx
  · simp [Code.executionInvalid, Code.accepted] at h
  simp only [Prod.mk.injEq] at h
  refine ⟨fc, key, learned', hdec, not_not.mp hp, hL, not_not.mp he, htc, hdk, hid, ?_, ?_,
    h.2.symm⟩
  · simpa using hv
  · simpa using hx

/-- A rejecting step leaves the state unchanged. -/
theorem step_reject_unchanged {verify : Verify} {verifyExec : VerifyExec} {s : State}
    {c : Candidate}
    (h : (step verify verifyExec s c).1 ≠ Code.accepted) : (step verify verifyExec s c).2 = s := by
  revert h
  unfold step
  split_ifs <;> try (intro; rfl)
  split <;> try (intro; rfl)
  split_ifs <;> try (intro; rfl)
  split <;> try (intro; rfl)
  split <;> try (intro; rfl)
  split <;> try (intro; rfl)
  split_ifs <;> try (intro; rfl)
  unfold accept
  split_ifs <;> try (intro; rfl)
  intro h; exact absurd rfl h

lemma step_config (verify : Verify) (verifyExec : VerifyExec) (s : State) (c : Candidate) :
    (step verify verifyExec s c).2.epochLength = s.epochLength ∧
        (step verify verifyExec s c).2.fromEpoch = s.fromEpoch ∧
    (step verify verifyExec s c).2.networkKey = s.networkKey := by
  by_cases h : (step verify verifyExec s c).1 = Code.accepted
  · obtain ⟨fc, key, l, -, -, -, -, -, -, -, -, -, hs⟩ := step_accept_shape (s' :=
      (step verify verifyExec s c).2)
      (by rw [← h])
    rw [hs]; simp
  · rw [step_reject_unchanged h]; simp

lemma identity_sound {Finalized : Nat → ByteArray → ByteArray → Prop}
    {Sound : Nat → ByteArray → Prop} {s : State} (hnet : ∀ e, s.fromEpoch ≤ e →
        Sound e s.networkKey)
    (hinv : Inv Finalized Sound s) {e : Nat} {k : ByteArray} (h : s.identity e = some k) :
    Sound e k := by
  unfold State.identity at h
  split at h
  · rename_i k' hk; simp at h; subst h; exact hinv.2 e k' hk
  · split_ifs at h with hf; simp at h; subst h; exact hnet e hf

/-- One accepting step: the candidate is Finalized, becomes the new tip, links to the old tip,
and the invariant is preserved. -/
theorem step_sound {verify : Verify} {verifyExec : VerifyExec} {Finalized : Nat → ByteArray →
    ByteArray → Prop}
    {Committed : Candidate → Prop}
    {Executed : ByteArray → ByteArray → ByteArray → Prop} {Sound : Nat → ByteArray → Prop}
        {s s' : State} {c : Candidate}
    (A : Assumptions verify verifyExec Finalized Committed Executed Sound s.epochLength s.fromEpoch
        s.networkKey)
    (hinv : Inv Finalized Sound s) (hc : Committed c) (h : step verify verifyExec s c =
        (Code.accepted, s')) :
    Finalized c.height c.blockDigest c.parentDigest ∧
    (∃ e v, s'.tip = some ⟨c.height, c.blockDigest, e, v, c.stateRoot⟩) ∧
    (∀ t, s.tip = some t → c.height = t.height + 1 ∧ c.parentDigest = t.digest) ∧
    Inv Finalized Sound s' := by
  obtain ⟨fc, key, learned', hdec, hp, hL, he, htc, hdk, hid, hv, -, rfl⟩ := step_accept_shape h
  have hsound := identity_sound A.network hinv hid
  have hfin : Finalized c.height c.blockDigest c.parentDigest := by
    rw [payload_eq hp] at hv
    exact A.crypto fc.epoch key _ _ _ c hsound hv hc
  refine ⟨hfin, ⟨fc.epoch, fc.view, rfl⟩, ?_, ?_, ?_⟩
  · intro t ht
    rw [ht, tipCheck_some] at htc
    exact ⟨htc.1, htc.2.1⟩
  · intro t ht; simp only [Option.some.injEq] at ht; subst ht; exact ⟨_, hfin⟩
  · intro e k hk
    simp only at hk
    unfold dkgCheck at hdk
    split_ifs at hdk with hb
    · split at hdk
      · simp at hdk
      · rename_i e' k' hdkg
        split_ifs at hdk
        simp only [Except.ok.injEq] at hdk; subst hdk
        beta_reduce at hk
        split_ifs at hk with hx
        · simp only [Option.some.injEq] at hk; rw [hx, ← hk]
          exact A.boundary c e' k' hc hfin hb hdkg
        · exact hinv.2 e k hk
    · simp only [Except.ok.injEq] at hdk; subst hdk; exact hinv.2 e k hk

/-- Parent linkage of a sequence of accepted candidates, starting from an optional tip. -/
def Linked : Option (Nat × ByteArray) → List Candidate → Prop
  | _, [] => True
  | none, c :: cs => Linked (some (c.height, c.blockDigest)) cs
  | some (h, d), c :: cs =>
    c.height = h + 1 ∧ c.parentDigest = d ∧ Linked (some (c.height, c.blockDigest)) cs

/-- Inputs the shim is responsible for: every candidate's header fields are bound to its digest. -/
def AllCommitted (Committed : Candidate → Prop) (cs : List Candidate) : Prop :=
  ∀ c ∈ cs, Committed c

/-- Main run theorem: invariant, every accepted block Finalized (i), the accepted chain is
parent-linked with consecutive heights starting from the initial tip (ii), configuration is
preserved, and the final tip is the last accepted candidate (or the initial tip). -/
theorem run_sound {verify : Verify} {verifyExec : VerifyExec} {Finalized : Nat → ByteArray →
    ByteArray → Prop}
    {Committed : Candidate → Prop}
    {Executed : ByteArray → ByteArray → ByteArray → Prop} {Sound : Nat → ByteArray → Prop} :
    ∀ (cs : List Candidate) (s : State),
    Assumptions verify verifyExec Finalized Committed Executed Sound s.epochLength s.fromEpoch
        s.networkKey →
    Inv Finalized Sound s → AllCommitted Committed cs →
    Inv Finalized Sound (run verify verifyExec s cs).1 ∧
    (∀ c ∈ (run verify verifyExec s cs).2, Finalized c.height c.blockDigest c.parentDigest) ∧
    Linked (s.tip.map fun t => (t.height, t.digest)) (run verify verifyExec s cs).2 ∧
    (run verify verifyExec s cs).1.epochLength = s.epochLength ∧
    (run verify verifyExec s cs).1.fromEpoch = s.fromEpoch ∧
        (run verify verifyExec s cs).1.networkKey = s.networkKey ∧
    (∀ t, (run verify verifyExec s cs).1.tip = some t →
      (s.tip = some t ∧ (run verify verifyExec s cs).2 = []) ∨
      (∃ c, (run verify verifyExec s cs).2.getLast? = some c ∧ t.height = c.height ∧
        t.digest = c.blockDigest ∧ t.stateRoot = c.stateRoot))
  | [], s, _, hinv, _ => by
    refine ⟨hinv, by simp [run], by simp [run, Linked], rfl, rfl, rfl, ?_⟩
    intro t ht; left; simp [run] at ht ⊢; exact ht
  | c :: cs, s, A, hinv, hcs => by
    have hc : Committed c := hcs c (by simp)
    have hcs' : AllCommitted Committed cs := fun x hx => hcs x (by simp [hx])
    obtain ⟨hL, hF, hN⟩ := step_config verify verifyExec s c
    by_cases hacc : (step verify verifyExec s c).1 = Code.accepted
    · have A' : Assumptions verify verifyExec Finalized Committed Executed Sound
        (step verify verifyExec s c).2.epochLength
          (step verify verifyExec s c).2.fromEpoch (step verify verifyExec s c).2.networkKey := by
        rw [hL, hF, hN]; exact A
      have hstep : step verify verifyExec s c = (Code.accepted, (step verify verifyExec s c).2) :=
          by
        rw [← hacc]
      obtain ⟨hfin, ⟨e, v, htip⟩, hlink, hinv'⟩ := step_sound A hinv hc hstep
      obtain ⟨i1, i2, i3, i4, i5, i6, i7⟩ := run_sound cs _ A' hinv' hcs'
      have hrun : run verify verifyExec s (c :: cs) =
          ((run verify verifyExec (step verify verifyExec s c).2 cs).1, c :: (run verify verifyExec
              (step verify verifyExec s c).2 cs).2) := by
        simp [run, hacc]
      rw [hrun]
      refine ⟨i1, ?_, ?_, by rw [i4, hL], by rw [i5, hF], by rw [i6, hN], ?_⟩
      · intro x hx; simp only [List.mem_cons] at hx; rcases hx with rfl | hx
        · exact hfin
        · exact i2 x hx
      · rw [htip] at i3; simp only [Option.map_some] at i3
        cases ht : s.tip with
        | none => simpa [Linked] using i3
        | some t =>
          obtain ⟨h1, h2⟩ := hlink t ht
          exact ⟨h1, h2, i3⟩
      · intro t ht
        rcases i7 t ht with ⟨h1, h2⟩ | ⟨x, hx, h3, h4, h5⟩
        · right; refine ⟨c, ?_, ?_, ?_, ?_⟩
          · simp [h2]
          · rw [htip] at h1; simp only [Option.some.injEq] at h1; rw [← h1]
          · rw [htip] at h1; simp only [Option.some.injEq] at h1; rw [← h1]
          · rw [htip] at h1; simp only [Option.some.injEq] at h1; rw [← h1]
        · right; refine ⟨x, ?_, h3, h4, h5⟩
          rw [List.getLast?_cons, hx]; rfl
    · have hrej := step_reject_unchanged hacc
      have hrun : run verify verifyExec s (c :: cs) = run verify verifyExec s cs := by
        simp only [run, hacc, if_false]; rw [hrej]
      rw [hrun]
      exact run_sound cs s A hinv hcs'

/-- (i) Every accepted tip is Finalized, for any (adversarial) input sequence. -/
theorem run_tip_finalized {verify : Verify} {verifyExec : VerifyExec} {Finalized : Nat →
    ByteArray → ByteArray → Prop}
    {Committed : Candidate → Prop}
    {Executed : ByteArray → ByteArray → ByteArray → Prop} {Sound : Nat → ByteArray → Prop}
    {L f : Nat} {k : ByteArray}
        (A : Assumptions verify verifyExec Finalized Committed Executed Sound L f k)
    (cs : List Candidate) (hcs : AllCommitted Committed cs) {t : Tip}
    (ht : (run verify verifyExec (State.init L f k) cs).1.tip = some t) :
    ∃ p, Finalized t.height t.digest p :=
  (run_sound cs (State.init L f k) A (inv_init _ _ L f k) hcs).1.1 t ht

/-- (i) Every block accepted along the way is Finalized. -/
theorem run_accepted_finalized {verify : Verify} {verifyExec : VerifyExec} {Finalized : Nat →
    ByteArray → ByteArray → Prop}
    {Committed : Candidate → Prop}
    {Executed : ByteArray → ByteArray → ByteArray → Prop} {Sound : Nat → ByteArray → Prop}
    {L f : Nat} {k : ByteArray}
        (A : Assumptions verify verifyExec Finalized Committed Executed Sound L f k)
    (cs : List Candidate) (hcs : AllCommitted Committed cs) :
    ∀ c ∈ (run verify verifyExec (State.init L f k) cs).2,
        Finalized c.height c.blockDigest c.parentDigest :=
  (run_sound cs (State.init L f k) A (inv_init _ _ L f k) hcs).2.1

/-- (ii) The accepted chain is parent-linked with consecutive heights (no hypotheses needed). -/
theorem run_linked (verify : Verify) (verifyExec : VerifyExec) : ∀ (cs : List Candidate)
    (s : State),
    Linked (s.tip.map fun t => (t.height, t.digest)) (run verify verifyExec s cs).2
  | [], s => by simp [run, Linked]
  | c :: cs, s => by
    by_cases hacc : (step verify verifyExec s c).1 = Code.accepted
    · have hstep : step verify verifyExec s c = (Code.accepted, (step verify verifyExec s c).2) :=
        by rw [← hacc]
      obtain ⟨fc, key, l, -, -, -, -, htc, -, -, -, -, hs⟩ := step_accept_shape hstep
      have ih := run_linked verify verifyExec cs (step verify verifyExec s c).2
      rw [hs] at ih; simp only [Option.map_some] at ih
      rw [← hs] at ih
      have hrun : (run verify verifyExec s (c :: cs)).2 = c :: (run verify verifyExec
          (step verify verifyExec s c).2 cs).2 := by
        simp [run, hacc]
      rw [hrun]
      cases ht : s.tip with
      | none => simpa [Linked] using ih
      | some t =>
        rw [ht, tipCheck_some] at htc
        exact ⟨htc.1, htc.2.1, ih⟩
    · have hrun : run verify verifyExec s (c :: cs) = run verify verifyExec s cs := by
        simp only [run, hacc, if_false]; rw [step_reject_unchanged hacc]
      rw [hrun]; exact run_linked verify verifyExec cs s

/-- (iii) Agreement: two followers (possibly with different trusted configurations), fed
arbitrary different input sequences, never accept different digests at the same height. -/
theorem agreement {verify : Verify} {verifyExec : VerifyExec} {Finalized : Nat → ByteArray →
    ByteArray → Prop}
    {Committed : Candidate → Prop}
    {Executed : ByteArray → ByteArray → ByteArray → Prop} {Sound : Nat → ByteArray → Prop}
    (hU : UniqueFinalized Finalized) {s1 s2 : State}
    (A1 : Assumptions verify verifyExec Finalized Committed Executed Sound s1.epochLength
        s1.fromEpoch s1.networkKey)
    (A2 : Assumptions verify verifyExec Finalized Committed Executed Sound s2.epochLength
        s2.fromEpoch s2.networkKey)
    (I1 : Inv Finalized Sound s1) (I2 : Inv Finalized Sound s2)
    (xs1 xs2 : List Candidate) (C1 : AllCommitted Committed xs1) (C2 : AllCommitted Committed xs2) :
    (∀ c1 ∈ (run verify verifyExec s1 xs1).2, ∀ c2 ∈ (run verify verifyExec s2 xs2).2,
      c1.height = c2.height → c1.blockDigest = c2.blockDigest) ∧
    (∀ t1 t2, (run verify verifyExec s1 xs1).1.tip = some t1 →
        (run verify verifyExec s2 xs2).1.tip = some t2 →
      t1.height = t2.height → t1.digest = t2.digest) := by
  have R1 := run_sound xs1 s1 A1 I1 C1
  have R2 := run_sound xs2 s2 A2 I2 C2
  constructor
  · intro c1 h1 c2 h2 hh
    have f1 := R1.2.1 c1 h1
    have f2 := R2.2.1 c2 h2
    rw [hh] at f1
    exact hU _ _ _ _ _ f1 f2
  · intro t1 t2 h1 h2 hh
    obtain ⟨p1, f1⟩ := R1.1.1 t1 h1
    obtain ⟨p2, f2⟩ := R2.1.1 t2 h2
    rw [hh] at f1
    exact hU _ _ _ _ _ f1 f2

/-- (iv) Progress: a genuine successor (canonically encoded well-formed certificate for this
block, correct epoch, linked to the tip with a higher round, carrying the next epoch's DKG
outcome if it is a boundary block) whose certificate verifies under the follower's identity for
its epoch, and whose execution from the tip's state root verifies, is accepted and becomes the
new tip. -/
theorem step_progress (verify : Verify) (verifyExec : VerifyExec) (s : State) (c : Candidate)
    (fc : SpecCert)
    (key : ByteArray) (hL : s.epochLength ≠ 0)
    (hcert : c.cert.data.toList = specEncode fc) (hwf : fc.WF)
    (hpay : fc.payload = c.blockDigest.data.toList)
    (hep : fc.epoch = c.height / s.epochLength)
    (hlink : ∀ t, s.tip = some t → c.height = t.height + 1 ∧ c.parentDigest = t.digest ∧
      roundLt t.epoch t.view fc.epoch fc.view)
    (hdkg : c.height % s.epochLength = s.epochLength - 1 → ∃ k, c.dkg = some (fc.epoch + 1, k))
    (hid : s.identity fc.epoch = some key)
    (hv : verify key fc.epoch.toUInt64 fc.view.toUInt64 fc.parent.toUInt64 c.blockDigest
      ⟨fc.sig.toArray⟩ = true)
    (hx : ∀ t, s.tip = some t → verifyExec t.stateRoot c.blockDigest c.stateRoot = true) :
    (step verify verifyExec s c).1 = Code.accepted ∧
    (step verify verifyExec s c).2.tip =
      some ⟨c.height, c.blockDigest, fc.epoch, fc.view, c.stateRoot⟩ := by
  have hx' : execOk verifyExec s.tip c = true := by
    unfold execOk
    cases ht : s.tip with
    | none => rfl
    | some t => exact hx t ht
  have htc : tipCheck s.tip c fc = none := by
    unfold tipCheck
    cases ht : s.tip with
    | none => rfl
    | some t =>
      obtain ⟨h1, h2, h3⟩ := hlink t ht
      simp [h1, h2, h3]
  obtain ⟨l, hdk⟩ : ∃ l, dkgCheck s.epochLength s.learned c fc = .ok l := by
    unfold dkgCheck
    by_cases hb : c.height % s.epochLength = s.epochLength - 1
    · obtain ⟨k, hk⟩ := hdkg hb
      simp [hb, hk]
    · simp [hb]
  have hv' : verify key fc.epoch.toUInt64 fc.view.toUInt64 fc.parent.toUInt64
      ⟨fc.payload.toArray⟩ ⟨fc.sig.toArray⟩ = true := by rw [payload_eq hpay]; exact hv
  unfold step
  rw [hcert, specDecode_specEncode fc hwf]
  simp only [hep, hpay] at hid hv'
  simp [hL, hpay, hep, htc, hdk, hid, hv', accept, hx']

/-- Execution chain of a sequence of accepted candidates, starting from an optional anchor state
root: each candidate's block executes from the previous candidate's state root to its own. -/
def ExecChain (Executed : ByteArray → ByteArray → ByteArray → Prop) :
    Option ByteArray → List Candidate → Prop
  | _, [] => True
  | none, c :: cs => ExecChain Executed (some c.stateRoot) cs
  | some r, c :: cs => Executed r c.blockDigest c.stateRoot ∧ ExecChain Executed
      (some c.stateRoot) cs

/-- The accepted chain is an execution chain from the initial tip's state root (or, with no tip,
from the first accepted block's state root, the anchor). Needs only H_exec and AllCommitted. -/
theorem run_exec_chain (verify : Verify) (verifyExec : VerifyExec) {Committed : Candidate → Prop}
    {Executed : ByteArray → ByteArray → ByteArray → Prop}
    (hX : ∀ (pre : ByteArray) (c : Candidate), verifyExec pre c.blockDigest c.stateRoot = true →
      Committed c → Executed pre c.blockDigest c.stateRoot) :
    ∀ (cs : List Candidate) (s : State), AllCommitted Committed cs →
    ExecChain Executed (s.tip.map Tip.stateRoot) (run verify verifyExec s cs).2
  | [], s, _ => by simp [run, ExecChain]
  | c :: cs, s, hcs => by
    have hc : Committed c := hcs c (by simp)
    have hcs' : AllCommitted Committed cs := fun x hx => hcs x (by simp [hx])
    by_cases hacc : (step verify verifyExec s c).1 = Code.accepted
    · have hstep : step verify verifyExec s c = (Code.accepted, (step verify verifyExec s c).2) :=
        by
        rw [← hacc]
      obtain ⟨fc, key, l, -, -, -, -, -, -, -, -, hx, hs⟩ := step_accept_shape hstep
      have ih := run_exec_chain verify verifyExec hX cs (step verify verifyExec s c).2 hcs'
      rw [hs] at ih; simp only [Option.map_some] at ih
      rw [← hs] at ih
      have hrun : (run verify verifyExec s (c :: cs)).2 =
          c :: (run verify verifyExec (step verify verifyExec s c).2 cs).2 := by
        simp [run, hacc]
      rw [hrun]
      cases ht : s.tip with
      | none => simpa [ExecChain] using ih
      | some t =>
        rw [ht] at hx
        exact ⟨hX t.stateRoot c hx hc, ih⟩
    · have hrun : run verify verifyExec s (c :: cs) = run verify verifyExec s cs := by
        simp only [run, hacc, if_false]; rw [step_reject_unchanged hacc]
      rw [hrun]; exact run_exec_chain verify verifyExec hX cs s hcs'

lemma execChain_pairs {Executed : ByteArray → ByteArray → ByteArray → Prop} :
    ∀ (r : Option ByteArray) (l : List Candidate), ExecChain Executed r l →
    ∀ (i : Nat) (h : i + 1 < l.length),
      Executed l[i].stateRoot l[i + 1].blockDigest l[i + 1].stateRoot
  | _, [], _, i, h => by simp at h
  | _, [_], _, i, h => by simp at h
  | none, c :: d :: cs, hc, i, h => by
    have hc' : ExecChain Executed (some c.stateRoot) (d :: cs) := hc
    cases i with
    | zero => exact hc'.1
    | succ i => exact execChain_pairs _ (d :: cs) hc' i (by simp at h ⊢; omega)
  | some r, c :: d :: cs, hc, i, h => by
    have hc' : ExecChain Executed (some c.stateRoot) (d :: cs) := hc.2
    cases i with
    | zero => exact hc'.1
    | succ i => exact execChain_pairs _ (d :: cs) hc' i (by simp at h ⊢; omega)

/-- (v) Execution: in a run from the initial state on any (adversarial) input sequence, every
consecutive pair of accepted candidates is a valid state transition: the accepted chain is a
valid execution chain from the anchor (the first accepted block's state root). -/
theorem run_executed {verify : Verify} {verifyExec : VerifyExec}
    {Finalized : Nat → ByteArray → ByteArray → Prop} {Committed : Candidate → Prop}
    {Executed : ByteArray → ByteArray → ByteArray → Prop} {Sound : Nat → ByteArray → Prop}
    {L f : Nat} {k : ByteArray}
    (A : Assumptions verify verifyExec Finalized Committed Executed Sound L f k)
    (cs : List Candidate) (hcs : AllCommitted Committed cs) :
    let acc := (run verify verifyExec (State.init L f k) cs).2
    ∀ (i : Nat) (h : i + 1 < acc.length),
      Executed acc[i].stateRoot acc[i + 1].blockDigest acc[i + 1].stateRoot :=
  execChain_pairs _ _ (run_exec_chain verify verifyExec A.exec cs _ hcs)

/-- Accepted candidates come from the input. -/
theorem run_accepted_mem (verify : Verify) (verifyExec : VerifyExec) :
    ∀ (cs : List Candidate) (s : State), ∀ c ∈ (run verify verifyExec s cs).2, c ∈ cs
  | [], s => by simp [run]
  | c :: cs, s => by
    intro x hx
    simp only [run] at hx
    split_ifs at hx
    · simp only [List.mem_cons] at hx
      rcases hx with rfl | hx
      · simp
      · exact List.mem_cons_of_mem _ (run_accepted_mem verify verifyExec cs _ x hx)
    · exact List.mem_cons_of_mem _ (run_accepted_mem verify verifyExec cs _ x hx)

/-- (vi) The tip is the last accepted candidate, including its state root (no hypotheses). -/
theorem run_tip_last (verify : Verify) (verifyExec : VerifyExec) :
    ∀ (cs : List Candidate) (s : State) (t : Tip), (run verify verifyExec s cs).1.tip = some t →
      (s.tip = some t ∧ (run verify verifyExec s cs).2 = []) ∨
      (∃ c, (run verify verifyExec s cs).2.getLast? = some c ∧ t.height = c.height ∧
        t.digest = c.blockDigest ∧ t.stateRoot = c.stateRoot)
  | [], s, t, ht => by left; simp [run] at ht ⊢; exact ht
  | c :: cs, s, t, ht => by
    by_cases hacc : (step verify verifyExec s c).1 = Code.accepted
    · have hstep : step verify verifyExec s c = (Code.accepted, (step verify verifyExec s c).2) :=
        by
        rw [← hacc]
      obtain ⟨fc, key, l, -, -, -, -, -, -, -, -, -, hs⟩ := step_accept_shape hstep
      have hrun : run verify verifyExec s (c :: cs) =
          ((run verify verifyExec (step verify verifyExec s c).2 cs).1,
            c :: (run verify verifyExec (step verify verifyExec s c).2 cs).2) := by
        simp [run, hacc]
      rw [hrun] at ht ⊢
      right
      rcases run_tip_last verify verifyExec cs _ t ht with ⟨h1, h2⟩ | ⟨x, hx, h3, h4, h5⟩
      · rw [hs] at h1; simp only [Option.some.injEq] at h1; subst h1
        exact ⟨c, by simp [h2], rfl, rfl, rfl⟩
      · exact ⟨x, by rw [List.getLast?_cons, hx]; rfl, h3, h4, h5⟩
    · have hrun : run verify verifyExec s (c :: cs) = run verify verifyExec s cs := by
        simp only [run, hacc, if_false]; rw [step_reject_unchanged hacc]
      rw [hrun] at ht ⊢; exact run_tip_last verify verifyExec cs s t ht

/-- (vi) From the initial state, the tip's height, digest and state root are those of the last
accepted candidate. -/
theorem run_tip_state_root (verify : Verify) (verifyExec : VerifyExec) (L f : Nat) (k : ByteArray)
    (cs : List Candidate) {t : Tip} (ht : (run verify verifyExec
        (State.init L f k) cs).1.tip = some t) :
    ∃ c, (run verify verifyExec (State.init L f k) cs).2.getLast? = some c ∧
      t.height = c.height ∧ t.digest = c.blockDigest ∧ t.stateRoot = c.stateRoot := by
  rcases run_tip_last verify verifyExec cs _ t ht with ⟨h1, -⟩ | h
  · simp [State.init] at h1
  · exact h

end Kaizen.Follower
