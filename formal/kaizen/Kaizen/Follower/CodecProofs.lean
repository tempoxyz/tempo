/-
Kaizen follower: codec proofs (round trip, canonicity / no trailing bytes, ByteArray refinement).
-/
import Mathlib.Tactic
import Kaizen.Follower.Codec

namespace Kaizen.Follower

set_option linter.deprecated false

lemma pow_split64 {i : Nat} (hi : i ≤ 8) : 2 ^ (64 - 7 * i) = 2 ^ (64 - 7 * (i + 1)) * 128 := by
  rw [show 64 - 7 * i = (64 - 7 * (i + 1)) + 7 by omega, pow_add]; norm_num

lemma pow_step7 (i : Nat) : 2 ^ (7 * (i + 1)) = 2 ^ (7 * i) * 128 := by
  rw [show 7 * (i + 1) = 7 * i + 7 by ring, pow_add]; norm_num

lemma pow_ge256 {i : Nat} (hi : i ≤ 8) : 256 ≤ 2 ^ (64 - 7 * i) := by
  calc (256 : Nat) = 2 ^ 8 := by norm_num
    _ ≤ 2 ^ (64 - 7 * i) := Nat.pow_le_pow_right (by norm_num) (by omega)

lemma toUInt8_toNat_of_lt {n : Nat} (h : n < 256) : n.toUInt8.toNat = n := by
  simp [Nat.toUInt8, UInt8.toNat_ofNat, Nat.mod_eq_of_lt h]

lemma toNat_toUInt8 (b : UInt8) : b.toNat.toUInt8 = b := by
  apply UInt8.toNat_inj.mp
  exact toUInt8_toNat_of_lt (UInt8.toNat_lt b)

lemma encodeVarint_lt {n : Nat} (h : n < 128) : encodeVarint n = [n.toUInt8] := by
  rw [encodeVarint]; simp [h]

lemma encodeVarint_ge {n : Nat} (h : ¬ n < 128) :
    encodeVarint n = (n % 128 + 128).toUInt8 :: encodeVarint (n / 128) := by
  rw [encodeVarint]; simp [h]

/-- Varint round trip at byte index i. -/
theorem varAux_encode (n : Nat) : ∀ (i acc : Nat) (rest : List UInt8), i ≤ 9 → (i ≠ 0 → 0 < n) →
    n < 2 ^ (64 - 7 * i) →
    varAux i acc (encodeVarint n ++ rest) = some (acc + n * 2 ^ (7 * i), rest) := by
  induction n using Nat.strong_induction_on with
  | _ n ih =>
  intro i acc rest hi hpos hlt
  by_cases h128 : n < 128
  · rw [encodeVarint_lt h128]
    have hb : (n.toUInt8).toNat = n := toUInt8_toNat_of_lt (by omega)
    simp only [List.cons_append, List.nil_append, varAux, hb]
    have h9 : ¬ (i = 9 ∧ 2 ≤ n) := by
      rintro ⟨rfl, h2⟩; norm_num at hlt; omega
    have h0 : ¬ (i ≠ 0 ∧ n = 0) := by
      rintro ⟨h1, h2⟩; have := hpos h1; omega
    simp [h9, h0, h128, Nat.mod_eq_of_lt h128]
  · rw [encodeVarint_ge h128]
    have hb : ((n % 128 + 128).toUInt8).toNat = n % 128 + 128 :=
      toUInt8_toNat_of_lt (by omega)
    have hi8 : i ≤ 8 := by
      by_contra hc
      have : i = 9 := by omega
      subst this; norm_num at hlt; omega
    simp only [List.cons_append, varAux, hb]
    have h9 : ¬ (i = 9 ∧ 2 ≤ n % 128 + 128) := by omega
    have h0 : ¬ (i ≠ 0 ∧ n % 128 + 128 = 0) := by omega
    have hc : ¬ (n % 128 + 128 < 128) := by omega
    simp only [h9, h0, hc, if_false]
    have hm : (n % 128 + 128) % 128 = n % 128 := by omega
    rw [hm]
    have hsplit := pow_split64 hi8
    have hq : n / 128 < 2 ^ (64 - 7 * (i + 1)) := by
      rw [Nat.div_lt_iff_lt_mul (by norm_num)]; omega
    rw [ih (n / 128) (by omega) (i + 1) _ rest (by omega) (fun _ => by omega) hq]
    congr 1
    rw [pow_step7]
    have hn : n * 2 ^ (7 * i) = (n % 128 + 128 * (n / 128)) * 2 ^ (7 * i) := by
      rw [Nat.mod_add_div]
    rw [hn]; ring_nf

/-- Varint decoding is exactly inverse to encoding: the consumed prefix is the canonical encoding. -/
theorem varAux_sound (bs : List UInt8) : ∀ (i acc v : Nat) (rest : List UInt8), i ≤ 9 →
    varAux i acc bs = some (v, rest) →
    ∃ n, v = acc + n * 2 ^ (7 * i) ∧ bs = encodeVarint n ++ rest ∧ (i ≠ 0 → 0 < n) ∧
      n < 2 ^ (64 - 7 * i) := by
  induction bs with
  | nil => intro i acc v rest _ h; simp [varAux] at h
  | cons b bs ih =>
    intro i acc v rest hi h
    have hb256 := UInt8.toNat_lt b
    simp only [varAux] at h
    split_ifs at h with h0 h9 h128
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      refine ⟨b.toNat, by rw [Nat.mod_eq_of_lt h128], ?_, ?_, ?_⟩
      · rw [encodeVarint_lt h128, toNat_toUInt8]; rfl
      · intro hi0; omega
      · by_cases hi9 : i = 9
        · subst hi9; norm_num; omega
        · have := pow_ge256 (i := i) (by omega); omega
    · have hi8 : i ≤ 8 := by
        by_contra hc; have : i = 9 := by omega
        subst this; omega
      obtain ⟨n', hv, hbs, hpos, hlt⟩ := ih (i + 1) _ v rest (by omega) h
      have hn'pos := hpos (by omega)
      refine ⟨b.toNat % 128 + 128 * n', ?_, ?_, fun _ => by omega, ?_⟩
      · rw [hv, pow_step7]; ring
      · have hge : ¬ (b.toNat % 128 + 128 * n' < 128) := by omega
        rw [encodeVarint_ge hge, hbs]
        have e1 : (b.toNat % 128 + 128 * n') % 128 + 128 = b.toNat := by omega
        have e2 : (b.toNat % 128 + 128 * n') / 128 = n' := by omega
        rw [e1, e2, toNat_toUInt8]; rfl
      · rw [pow_split64 hi8]; omega

theorem varAux_append (bs extra : List UInt8) : ∀ (i acc v : Nat) (rest : List UInt8),
    varAux i acc bs = some (v, rest) → varAux i acc (bs ++ extra) = some (v, rest ++ extra) := by
  induction bs with
  | nil => intro i acc v rest h; simp [varAux] at h
  | cons b bs ih =>
    intro i acc v rest h
    simp only [List.cons_append, varAux] at h ⊢
    split_ifs at h ⊢
    · simp only [Option.some.injEq, Prod.mk.injEq] at h ⊢
      exact ⟨h.1, by rw [h.2]⟩
    · exact ih _ _ v rest h

/-- (b) Round trip: decoding the encoding of a well-formed certificate returns it. -/
theorem specDecode_specEncode (c : SpecCert) (hc : c.WF) : specDecode (specEncode c) = some c := by
  obtain ⟨he, hv, hp, hpl, hsl⟩ := hc
  unfold specDecode specEncode
  simp only [List.append_assoc]
  rw [varAux_encode c.epoch 0 0 _ (by norm_num) (by simp) (by simpa using he)]
  simp only [Nat.zero_add, Nat.mul_zero, pow_zero, Nat.mul_one]
  rw [varAux_encode c.view 0 0 _ (by norm_num) (by simp) (by simpa using hv)]
  simp only [Nat.zero_add, Nat.mul_zero, pow_zero, Nat.mul_one]
  rw [varAux_encode c.parent 0 0 _ (by norm_num) (by simp) (by simpa using hp)]
  simp only [Nat.zero_add, Nat.mul_zero, pow_zero, Nat.mul_one, List.length_append, hpl, hsl]
  simp [← hpl]

/-- (c) Soundness / canonicity: anything accepted is well formed and is exactly the canonical
encoding of the result (so non-canonical varints, wrong lengths and trailing bytes are rejected). -/
theorem specDecode_sound {bs : List UInt8} {c : SpecCert} (h : specDecode bs = some c) :
    c.WF ∧ specEncode c = bs := by
  unfold specDecode at h
  split at h; · simp at h
  rename_i e r1 h1
  split at h; · simp at h
  rename_i v r2 h2
  split at h; · simp at h
  rename_i p r3 h3
  split_ifs at h with hl
  simp only [Option.some.injEq] at h
  subst h
  obtain ⟨ne, rfl, hbs1, -, hlt1⟩ := varAux_sound _ 0 0 _ _ (by norm_num) h1
  obtain ⟨nv, rfl, hbs2, -, hlt2⟩ := varAux_sound _ 0 0 _ _ (by norm_num) h2
  obtain ⟨np, rfl, hbs3, -, hlt3⟩ := varAux_sound _ 0 0 _ _ (by norm_num) h3
  simp only [Nat.zero_add, Nat.mul_zero, pow_zero, Nat.mul_one] at hlt1 hlt2 hlt3 ⊢
  refine ⟨⟨hlt1, hlt2, hlt3, by simp [hl], by simp [hl]⟩, ?_⟩
  simp only [specEncode, List.append_assoc, List.take_append_drop]
  rw [hbs1, hbs2, hbs3]

/-- (c) Trailing bytes are rejected. -/
theorem specDecode_trailing {bs extra : List UInt8} {c : SpecCert} (h : specDecode bs = some c)
    (hx : extra ≠ []) : specDecode (bs ++ extra) = none := by
  unfold specDecode at h ⊢
  split at h; · simp at h
  rename_i e r1 h1
  split at h; · simp at h
  rename_i v r2 h2
  split at h; · simp at h
  rename_i p r3 h3
  split_ifs at h with hl
  rw [varAux_append _ extra _ _ _ _ h1]
  simp only
  rw [varAux_append _ extra _ _ _ _ h2]
  simp only
  rw [varAux_append _ extra _ _ _ _ h3]
  simp only [List.length_append, hl]
  have : extra.length ≠ 0 := by simpa using hx
  simp [this]

/-- (c) Wrong lengths are rejected: an accepted input has exactly the canonical length and the
decoded payload / signature are exactly 32 / 96 bytes. -/
theorem specDecode_length {bs : List UInt8} {c : SpecCert} (h : specDecode bs = some c) :
    bs.length = (encodeVarint c.epoch).length + (encodeVarint c.view).length +
      (encodeVarint c.parent).length + 128 ∧ c.payload.length = 32 ∧ c.sig.length = 96 := by
  obtain ⟨⟨-, -, -, hp, hs⟩, he⟩ := specDecode_sound h
  refine ⟨?_, hp, hs⟩
  rw [← he]; simp [specEncode, hp, hs]; omega

/-! ## ByteArray refinement -/

lemma acc_step (acc : UInt64) (x : UInt8) (i : Nat) (hi : i ≤ 9) (ha : acc.toNat < 2 ^ (7 * i))
    (h9 : i = 9 → x.toNat < 2) :
    (acc + ((x % 128).toUInt64 <<< (7 * i).toUInt64)).toNat =
      acc.toNat + x.toNat % 128 * 2 ^ (7 * i) := by
  have hsh : ((7 * i).toUInt64).toNat % 64 = 7 * i := by
    simp [Nat.toUInt64, UInt64.toNat_ofNat]; omega
  rw [UInt64.toNat_add, UInt64.toNat_shiftLeft, hsh, Nat.shiftLeft_eq]
  simp only [UInt8.toNat_toUInt64, UInt8.toNat_mod]
  have hx := UInt8.toNat_lt x
  set P := 2 ^ (7 * i) with hP
  set a := x.toNat % 128 with ha'
  have hbound : acc.toNat + a * P < 2 ^ 64 := by
    by_cases hi9 : i = 9
    · subst hi9
      have : a ≤ 1 := by have := h9 rfl; omega
      have hP' : P = 2 ^ 63 := by rw [hP]
      rcases Nat.le_one_iff_eq_zero_or_eq_one.mp this with h | h <;> rw [h] <;> omega
    · have hP128 : P * 128 ≤ 2 ^ 63 := by
        rw [hP, ← pow_step7]; exact Nat.pow_le_pow_right (by norm_num) (by omega)
      have : a * P ≤ 127 * P := Nat.mul_le_mul_right _ (by omega)
      omega
  have h128 : (128 : UInt8).toNat = 128 := rfl
  rw [h128, ← ha']
  have h1 : a * P % 2 ^ 64 = a * P := Nat.mod_eq_of_lt (by omega)
  rw [h1, Nat.mod_eq_of_lt hbound]

lemma ba_toList_length (b : ByteArray) : b.data.toList.length = b.size := by
  rw [Array.length_toList]; rfl

theorem readVarint_refines (b : ByteArray) (pos i : Nat) (acc : UInt64) (hi : i ≤ 9)
    (ha : acc.toNat < 2 ^ (7 * i)) :
    (readVarint b pos i acc).map (fun r => (r.1.toNat, b.data.toList.drop r.2)) =
      varAux i acc.toNat (b.data.toList.drop pos) := by
  rw [readVarint]
  split
  · rename_i h
    rw [List.drop_eq_getElem_cons (by rw [ba_toList_length]; exact h)]
    have hx : b.data.toList[pos]'(by rw [ba_toList_length]; exact h) = b[pos] := by
      rw [Array.getElem_toList]; rfl
    rw [hx]
    simp only [varAux]
    have e0 : (b[pos] = 0) ↔ b[pos].toNat = 0 := by
      rw [← UInt8.toNat_inj]; simp
    have e2 : (2 ≤ b[pos]) ↔ 2 ≤ b[pos].toNat := by rw [UInt8.le_iff_toNat_le]; simp
    have e128 : (b[pos] < 128) ↔ b[pos].toNat < 128 := by rw [UInt8.lt_iff_toNat_lt]; simp
    by_cases c0 : i ≠ 0 ∧ b[pos].toNat = 0
    · have : i ≠ 0 ∧ b[pos] = 0 := ⟨c0.1, e0.mpr c0.2⟩
      simp [this, c0]
    · have : ¬ (i ≠ 0 ∧ b[pos] = 0) := fun h' => c0 ⟨h'.1, e0.mp h'.2⟩
      rw [if_neg this, if_neg c0]
      by_cases c9 : i = 9 ∧ 2 ≤ b[pos].toNat
      · have : i = 9 ∧ 2 ≤ b[pos] := ⟨c9.1, e2.mpr c9.2⟩
        simp [this, c9]
      · have : ¬ (i = 9 ∧ 2 ≤ b[pos]) := fun h' => c9 ⟨h'.1, e2.mp h'.2⟩
        rw [if_neg this, if_neg c9]
        have hstep := acc_step acc b[pos] i hi ha (fun h9 => by
          by_contra hc; exact c9 ⟨h9, by omega⟩)
        by_cases c128 : b[pos].toNat < 128
        · rw [if_pos (e128.mpr c128), if_pos c128, Option.map_some, hstep]
        · rw [if_neg (fun h' => c128 (e128.mp h')), if_neg c128]
          have hi8 : i ≤ 8 := by
            by_contra hc; exact c9 ⟨by omega, by omega⟩
          rw [readVarint_refines b (pos + 1) (i + 1) _ (by omega) ?_, hstep]
          rw [hstep, pow_step7]
          have : b[pos].toNat % 128 * 2 ^ (7 * i) ≤ 127 * 2 ^ (7 * i) :=
            Nat.mul_le_mul_right _ (by omega)
          omega
  · rename_i h
    rw [List.drop_eq_nil_of_le (by rw [ba_toList_length]; omega)]
    simp [varAux]
termination_by b.size - pos

lemma readVarint_spec0 (b : ByteArray) (pos : Nat) :
    (readVarint b pos 0 0).map (fun r => (r.1.toNat, b.data.toList.drop r.2)) =
      varAux 0 0 (b.data.toList.drop pos) := by
  simpa using readVarint_refines b pos 0 0 (by norm_num) (by simp)

lemma extract_toList (b : ByteArray) (s n : Nat) :
    (b.extract s (s + n)).data.toList = (b.data.toList.drop s).take n := by
  simp [ByteArray.data_extract, Array.toList_extract, List.extract]

/-- (a) Refinement: the ByteArray decoder agrees with the list spec decoder. -/
theorem decodeCert_refines (b : ByteArray) :
    (decodeCert b).map Cert.toSpec = specDecode b.data.toList := by
  have h0 := readVarint_spec0 b 0
  simp only [List.drop_zero] at h0
  unfold decodeCert specDecode
  rcases hr1 : readVarint b 0 0 0 with _ | ⟨e, p1⟩
  · rw [hr1] at h0; simp at h0; rw [← h0]; simp
  rw [hr1] at h0; simp only [Option.map_some] at h0; rw [← h0]; simp only
  have h1 := readVarint_spec0 b p1
  rcases hr2 : readVarint b p1 0 0 with _ | ⟨v, p2⟩
  · rw [hr2] at h1; simp at h1; rw [← h1]; simp
  rw [hr2] at h1; simp only [Option.map_some] at h1; rw [← h1]; simp only
  have h2 := readVarint_spec0 b p2
  rcases hr3 : readVarint b p2 0 0 with _ | ⟨pv, p3⟩
  · rw [hr3] at h2; simp at h2; rw [← h2]; simp
  rw [hr3] at h2; simp only [Option.map_some] at h2; rw [← h2]; simp only
  have hlen : (b.data.toList.drop p3).length = 128 ↔ p3 + 128 = b.size := by
    rw [List.length_drop, ba_toList_length]; omega
  by_cases hc : p3 + 128 = b.size
  · rw [if_pos hc, if_pos (hlen.mpr hc)]
    simp only [Option.map_some, Cert.toSpec, Option.some.injEq, SpecCert.mk.injEq, true_and]
    refine ⟨extract_toList b p3 32, ?_⟩
    rw [show p3 + 128 = (p3 + 32) + 96 by omega, extract_toList, List.drop_drop]
    rw [List.take_of_length_le]
    rw [List.length_drop, ba_toList_length]; omega
  · rw [if_neg hc, if_neg (fun h' => hc (hlen.mp h'))]; rfl

end Kaizen.Follower
