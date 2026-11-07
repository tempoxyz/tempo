/-
Kaizen follower: Stage II refinement proof: implStep refines step through ImplState.abs.
-/
import Mathlib.Tactic
import Kaizen.Follower.Impl
import Kaizen.Follower.CodecProofs

namespace Kaizen.Follower

set_option linter.deprecated false

lemma u64_ne_zero_iff (a : UInt64) : a ≠ 0 ↔ a.toNat ≠ 0 := by
  rw [ne_eq, ne_eq, ← UInt64.toNat_inj]; simp

lemma u64_sub_one (a : UInt64) (h : a.toNat ≠ 0) : (a - 1).toNat = a.toNat - 1 := by
  rw [UInt64.toNat_sub_of_le _ _ (UInt64.le_iff_toNat_le.mpr (by simp; omega))]; simp

lemma u64_succ_iff (a b : UInt64) : (a ≠ 0 ∧ a - 1 = b) ↔ a.toNat = b.toNat + 1 := by
  rw [u64_ne_zero_iff, ← UInt64.toNat_inj]
  constructor
  · rintro ⟨h0, h1⟩; rw [u64_sub_one a h0] at h1; omega
  · intro h; have h0 : a.toNat ≠ 0 := by omega
    exact ⟨h0, by rw [u64_sub_one a h0]; omega⟩

lemma u64_eq_iff (a b : UInt64) : a = b ↔ a.toNat = b.toNat := UInt64.toNat_inj.symm

lemma u64_lt_iff (a b : UInt64) : a < b ↔ a.toNat < b.toNat := UInt64.lt_iff_toNat_lt

lemma u64_le_iff (a b : UInt64) : a ≤ b ↔ a.toNat ≤ b.toNat := UInt64.le_iff_toNat_le

lemma u64_mod_last_iff (h L : UInt64) (hL : L.toNat ≠ 0) :
    h % L = L - 1 ↔ h.toNat % L.toNat = L.toNat - 1 := by
  rw [u64_eq_iff, UInt64.toNat_mod, u64_sub_one L hL]

lemma u64_div_iff (e h L : UInt64) : e = h / L ↔ e.toNat = h.toNat / L.toNat := by
  rw [u64_eq_iff, UInt64.toNat_div]

lemma u64_toNat_toUInt64 (a : UInt64) : a.toNat.toUInt64 = a := by simp

lemma ba_eq_iff (a b : ByteArray) : a = b ↔ a.data.toList = b.data.toList := by
  constructor
  · rintro rfl; rfl
  · intro h; apply ByteArray.ext; exact Array.toList_inj.mp h

lemma ba_toArray (a : ByteArray) : (⟨a.data.toList.toArray⟩ : ByteArray) = a := by
  apply ByteArray.ext; simp

lemma absLearned_get (m : Std.HashMap UInt64 ByteArray) (e : UInt64) :
    absLearned m e.toNat = m[e]? := by
  simp [absLearned, UInt64.toNat_lt_size]

lemma absLearned_insert (m : Std.HashMap UInt64 ByteArray) (e : UInt64) (k : ByteArray) :
    absLearned (m.insert e k) = fun x => if x = e.toNat then some k else absLearned m x := by
  funext x
  unfold absLearned
  by_cases hx : x < 2 ^ 64
  · rw [if_pos hx, if_pos hx, Std.HashMap.getElem?_insert]
    have : (e == x.toUInt64) = true ↔ x = e.toNat := by
      rw [beq_iff_eq, u64_eq_iff, UInt64.toNat_ofNat_of_lt' hx]; omega
    by_cases hxe : x = e.toNat
    · rw [if_pos (this.mpr hxe), if_pos hxe]
    · rw [if_neg (fun h => hxe (this.mp h)), if_neg hxe]
  · rw [if_neg hx, if_neg hx]
    have : x ≠ e.toNat := by
      have := UInt64.toNat_lt_size e; have h2 : UInt64.size = 2 ^ 64 := rfl; omega
    rw [if_neg this]

lemma identity_refines (s : ImplState) (e : UInt64) : s.identity e = s.abs.identity e.toNat := by
  unfold ImplState.identity State.identity
  simp only [ImplState.abs, absLearned_get]
  cases s.learned[e]?
  · simp only [u64_le_iff]
    by_cases h : s.fromEpoch.toNat ≤ e.toNat <;> simp [h]
  · rfl

lemma tipCheck_refines (tip : Option ImplTip) (c : ImplCandidate) (fc : Cert) :
    implTipCheck tip c fc = tipCheck (tip.map ImplTip.abs) c.abs fc.toSpec := by
  cases tip with
  | none => rfl
  | some t =>
    simp only [implTipCheck, tipCheck, Option.map_some, ImplTip.abs, ImplCandidate.abs,
      Cert.toSpec, roundLt]
    simp only [u64_succ_iff, u64_lt_iff, u64_eq_iff t.epoch]
    split_ifs <;> simp_all

lemma dkgCheck_refines (L : UInt64) (hL : L.toNat ≠ 0) (m : Std.HashMap UInt64 ByteArray)
    (c : ImplCandidate) (fc : Cert) :
    (implDkgCheck L m c fc).map absLearned = dkgCheck L.toNat (absLearned m) c.abs fc.toSpec := by
  unfold implDkgCheck dkgCheck
  simp only [ImplCandidate.abs, Cert.toSpec]
  simp only [u64_mod_last_iff _ _ hL]
  by_cases hb : c.height.toNat % L.toNat = L.toNat - 1
  · simp only [hb, if_true]
    cases hd : c.dkg with
    | none => rfl
    | some p =>
      obtain ⟨e', k⟩ := p
      simp only [Option.map_some, u64_succ_iff]
      by_cases h1 : e'.toNat = fc.epoch.toNat + 1
      · simp [h1, Except.map, absLearned_insert]
      · simp [h1, Except.map]
  · simp [hb, Except.map]

lemma execOk_refines (verifyExec : VerifyExec) (tip : Option ImplTip) (c : ImplCandidate) :
    implExecOk verifyExec tip c = execOk verifyExec (tip.map ImplTip.abs) c.abs := by
  cases tip <;> rfl

/-- Stage II refinement: the executable step refines the abstract step, with identical result
codes, for every implementation state and input. -/
theorem implStep_refines (verify : Verify) (verifyExec : VerifyExec) (s : ImplState)
    (c : ImplCandidate) :
    (implStep verify verifyExec s c).1 = (step verify verifyExec s.abs c.abs).1 ∧
    (implStep verify verifyExec s c).2.abs = (step verify verifyExec s.abs c.abs).2 := by
  have hdec := decodeCert_refines c.cert
  unfold implStep step
  have hL : (s.epochLength = 0) ↔ s.abs.epochLength = 0 := by
    simp only [ImplState.abs]; rw [u64_eq_iff]; simp
  by_cases hL0 : s.epochLength = 0
  · rw [if_pos hL0, if_pos (hL.mp hL0)]; exact ⟨rfl, rfl⟩
  rw [if_neg hL0, if_neg (fun h => hL0 (hL.mpr h))]
  have hL' : s.epochLength.toNat ≠ 0 := by rwa [← u64_ne_zero_iff]
  have hcert : c.abs.cert = c.cert := rfl
  rw [hcert, ← hdec]
  cases hd : decodeCert c.cert with
  | none => exact ⟨rfl, rfl⟩
  | some fc =>
    simp only [Option.map_some]
    have hp : (fc.payload ≠ c.blockDigest) ↔
        (fc.toSpec.payload ≠ c.abs.blockDigest.data.toList) := by
      simp only [Cert.toSpec, ImplCandidate.abs]; rw [ne_eq, ne_eq, ba_eq_iff]
    by_cases hp0 : fc.payload ≠ c.blockDigest
    · rw [if_pos hp0, if_pos (hp.mp hp0)]; exact ⟨rfl, rfl⟩
    rw [if_neg hp0, if_neg (fun h => hp0 (hp.mpr h))]
    have he : (fc.epoch ≠ c.height / s.epochLength) ↔
        (fc.toSpec.epoch ≠ c.abs.height / s.abs.epochLength) := by
      simp only [Cert.toSpec, ImplCandidate.abs, ImplState.abs]; rw [ne_eq, u64_div_iff]
    by_cases he0 : fc.epoch ≠ c.height / s.epochLength
    · rw [if_pos he0, if_pos (he.mp he0)]; exact ⟨rfl, rfl⟩
    rw [if_neg he0, if_neg (fun h => he0 (he.mpr h))]
    by_cases hr0 : 2 ^ 64 < fc.epoch.toNat * s.epochLength.toNat + s.epochLength.toNat
    · rw [if_pos hr0, if_pos (by simpa [Cert.toSpec, ImplState.abs] using hr0)]
      exact ⟨rfl, rfl⟩
    rw [if_neg hr0, if_neg (by simpa [Cert.toSpec, ImplState.abs] using hr0)]
    have htc : s.abs.tip = s.tip.map ImplTip.abs := rfl
    rw [htc, ← tipCheck_refines]
    cases implTipCheck s.tip c fc with
    | some code => exact ⟨rfl, rfl⟩
    | none =>
      simp only
      have hdk := dkgCheck_refines s.epochLength hL' s.learned c fc
      have hsl : s.abs.learned = absLearned s.learned := rfl
      have hsL : s.abs.epochLength = s.epochLength.toNat := rfl
      rw [hsl, hsL, ← hdk]
      cases implDkgCheck s.epochLength s.learned c fc with
      | error code => exact ⟨rfl, rfl⟩
      | ok l =>
        simp only [Except.map]
        have hid := identity_refines s fc.epoch
        have hfe : fc.toSpec.epoch = fc.epoch.toNat := rfl
        rw [hfe, ← hid]
        cases s.identity fc.epoch with
        | none => exact ⟨rfl, rfl⟩
        | some key =>
          simp only [Cert.toSpec, u64_toNat_toUInt64, ba_toArray]
          split_ifs
          · exact ⟨rfl, rfl⟩
          · unfold implAccept accept
            rw [execOk_refines, ← htc]
            split_ifs <;> exact ⟨rfl, rfl⟩

/-- Iterated refinement: running the implementation on a sequence of inputs refines running the
spec on the abstracted inputs. -/
def implRun (verify : Verify) (verifyExec : VerifyExec) :
    ImplState → List ImplCandidate → ImplState × List ImplCandidate
  | s, [] => (s, [])
  | s, c :: cs =>
    let r := implStep verify verifyExec s c
    let rest := implRun verify verifyExec r.2 cs
    if r.1 = Code.accepted then (rest.1, c :: rest.2) else rest

theorem implRun_refines (verify : Verify) (verifyExec : VerifyExec) :
    ∀ (cs : List ImplCandidate) (s : ImplState),
    (implRun verify verifyExec s cs).1.abs =
      (run verify verifyExec s.abs (cs.map ImplCandidate.abs)).1 ∧
    (implRun verify verifyExec s cs).2.map ImplCandidate.abs =
      (run verify verifyExec s.abs (cs.map ImplCandidate.abs)).2
  | [], s => ⟨rfl, rfl⟩
  | c :: cs, s => by
    obtain ⟨h1, h2⟩ := implStep_refines verify verifyExec s c
    obtain ⟨i1, i2⟩ := implRun_refines verify verifyExec cs (implStep verify verifyExec s c).2
    rw [h2] at i1 i2
    simp only [implRun, run, List.map_cons]
    rw [← h1]
    split_ifs <;> simp [i1, i2]

theorem init_refines (L f : UInt64) (k : ByteArray) :
    (ImplState.init L f k).abs = State.init L.toNat f.toNat k := by
  simp only [ImplState.init, ImplState.abs, State.init, Option.map_none]
  congr 1
  funext e
  simp [absLearned]

end Kaizen.Follower
