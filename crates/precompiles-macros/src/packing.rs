//! Shared code generation utilities for storage slot packing.
//!
//! This module provides common logic for computing slot and offset assignments
//! used by both the `#[derive(Storable)]` and `#[contract]` macros.

use alloy::primitives::U256;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Ident, Type};

use crate::{FieldInfo, FieldKind};

/// Helper for generating packing constant identifiers
pub(crate) struct PackingConstants(String);

impl PackingConstants {
    /// Create packing constant helper struct
    pub(crate) fn new(name: &Ident) -> Self {
        Self(const_name(name))
    }

    /// The bare field name constant (U256 slot, used by `#[contract]` macro)
    pub(crate) fn slot(&self) -> Ident {
        format_ident!("{}", &self.0)
    }

    /// The `_LOC` suffixed constant
    pub(crate) fn location(&self) -> Ident {
        let span = proc_macro2::Span::call_site();
        Ident::new(&format!("{}_LOC", self.0), span)
    }

    /// The `_OFFSET` constant identifier
    pub(crate) fn offset(&self) -> Ident {
        let span = proc_macro2::Span::call_site();
        Ident::new(&format!("{}_OFFSET", self.0), span)
    }

    /// Returns the constant identifiers required by both macros (slot, offset)
    pub(crate) fn into_tuple(self) -> (Ident, Ident) {
        (self.slot(), self.offset())
    }
}

/// Convert a field name to a constant name (SCREAMING_SNAKE_CASE)
pub(crate) fn const_name(name: &Ident) -> String {
    name.to_string().to_uppercase()
}

/// Represents how a slot is assigned
#[derive(Debug, Clone)]
pub(crate) enum SlotAssignment {
    /// Manual slot value: `#[slot(N)]` or `#[base_slot(N)]`
    Manual(U256),
    /// Auto-assigned: stores after the latest auto-assigned field
    Auto {
        /// Base slot for packing decisions.
        base_slot: U256,
    },
}

impl SlotAssignment {
    pub(crate) fn ref_slot(&self) -> &U256 {
        match self {
            Self::Manual(slot) => slot,
            Self::Auto { base_slot } => base_slot,
        }
    }
}

/// A single field in the storage layout with computed slot information.
#[derive(Debug)]
pub(crate) struct LayoutField<'a> {
    /// Field name
    pub name: &'a Ident,
    /// Field type
    pub ty: &'a Type,
    /// Field kind (Direct or Mapping)
    pub kind: FieldKind<'a>,
    /// The assigned storage slot for this field (or base for const-eval chain)
    pub assigned_slot: SlotAssignment,
}

/// Build layout IR from field information.
///
/// This function performs slot allocation and packing decisions, returning
/// a complete layout that can be used for code generation. The actual byte-level
/// packing calculations (offsets, whether fields actually pack) are computed
/// at compile-time via const expressions in the generated code.
///
/// The IR captures the *structure* of the layout (which fields share base slots,
/// which are manually assigned, etc.) using the `SlotAssignment` enum.
pub(crate) fn allocate_slots(fields: &[FieldInfo]) -> syn::Result<Vec<LayoutField<'_>>> {
    let mut result = Vec::with_capacity(fields.len());
    let mut current_base_slot = U256::ZERO;

    for field in fields.iter() {
        let kind = classify_field_type(&field.ty)?;

        // Explicit fixed slot, doesn't affect auto-assignment chain
        let assigned_slot = if let Some(explicit) = field.slot {
            SlotAssignment::Manual(explicit)
        } else if let Some(new_base) = field.base_slot {
            // Explicit base slot, resets auto-assignment chain
            current_base_slot = new_base;
            SlotAssignment::Auto {
                base_slot: new_base,
            }
        } else {
            SlotAssignment::Auto {
                base_slot: current_base_slot,
            }
        };

        result.push(LayoutField {
            name: &field.name,
            ty: &field.ty,
            kind,
            assigned_slot,
        });
    }

    Ok(result)
}

/// Generate packing constants from layout IR.
///
/// This function generates compile-time constants (`<FIELD>`, `<FIELD>_OFFSET`, `<FIELD>_BYTES`)
/// for slot assignments, offsets, and byte sizes based on the layout IR using field-name-based naming.
/// Slot constants (`<FIELD>`) are generated as `U256` types, while offset and bytes constants use `usize`.
pub(crate) fn gen_constants_from_ir(fields: &[LayoutField<'_>], gen_location: bool) -> TokenStream {
    let mut constants = TokenStream::new();
    let mut current_base_slot: Option<&LayoutField<'_>> = None;

    for field in fields {
        let ty = field.ty;
        let consts = PackingConstants::new(field.name);
        let (loc_const, (slot_const, offset_const)) = (consts.location(), consts.into_tuple());
        let slots_to_end = quote! {
            ::alloy::primitives::U256::from_limbs([<#ty as crate::storage::StorableType>::SLOTS as u64, 0, 0, 0])
                .saturating_sub(::alloy::primitives::U256::ONE)
        };

        // Generate byte count constants for each field
        let bytes_expr = quote! { <#ty as crate::storage::StorableType>::BYTES };

        // Generate slot and offset constants for each field
        let (slot_expr, offset_expr) = match &field.assigned_slot {
            // Manual slot assignment always has offset 0
            SlotAssignment::Manual(manual_slot) => {
                let hex_value = format!("{manual_slot}_U256");
                let slot_lit = syn::LitInt::new(&hex_value, proc_macro2::Span::call_site());
                // HACK: we leverage compiler evaluation checks to ensure that the full type can fit
                // by computing the slot as: `SLOT = SLOT + (TYPE_LEN - 1)  - (TYPE_LEN - 1)`
                let slot_expr = quote! {
                    ::alloy::primitives::uint!(#slot_lit)
                        .checked_add(#slots_to_end).expect("slot overflow")
                        .saturating_sub(#slots_to_end)
                };
                (slot_expr, quote! { 0 })
            }
            // Auto-assignment computes slot/offset using const expressions
            SlotAssignment::Auto { base_slot, .. } => {
                let output = if let Some(current_base) = current_base_slot
                    && current_base.assigned_slot.ref_slot() == field.assigned_slot.ref_slot()
                {
                    // Fields that share the same base compute their slots based on the previous field
                    let (prev_slot, prev_offset) =
                        PackingConstants::new(current_base.name).into_tuple();
                    gen_slot_packing_logic(
                        current_base.ty,
                        field.ty,
                        quote! { #prev_slot },
                        quote! { #prev_offset },
                    )
                } else {
                    // If a new base is adopted, start from the base slot and offset 0
                    let limbs = *base_slot.as_limbs();

                    // HACK: we leverage compiler evaluation checks to ensure that the full type can fit
                    // by computing the slot as: `SLOT = SLOT + (TYPE_LEN - 1)  - (TYPE_LEN - 1)`
                    let slot_expr = quote! {
                        ::alloy::primitives::U256::from_limbs([#(#limbs),*])
                            .checked_add(#slots_to_end).expect("slot overflow")
                            .saturating_sub(#slots_to_end)
                    };
                    (slot_expr, quote! { 0 })
                };
                // update cache
                current_base_slot = Some(field);
                output
            }
        };

        // Generate slot constant without suffix (U256) and offset constant (usize)
        constants.extend(quote! {
            pub const #slot_const: ::alloy::primitives::U256 = #slot_expr;
            pub const #offset_const: usize = #offset_expr;
        });

        // For the `Storable` macro, also generate the location constant
        // NOTE: `slot_const` refers to the slot offset of the struct field relative to the struct's base slot.
        // Because of that it is safe to use the usize -> U256 conversion (a struct will never have 2**64 fields).
        if gen_location {
            constants.extend(quote! {
                pub const #loc_const: crate::storage::packing::FieldLocation =
                    crate::storage::packing::FieldLocation::new(#slot_const.as_limbs()[0] as usize, #offset_const, #bytes_expr);
            });
        }

        // generate constants used in tests for solidity layout compatibility assertions
        #[cfg(debug_assertions)]
        {
            let bytes_const = format_ident!("{slot_const}_BYTES");
            constants.extend(quote! { pub const #bytes_const: usize = #bytes_expr; });
        }
    }

    constants
}

/// Classify a field based on its type.
///
/// Determines if a field is a direct value or a mapping.
/// Nested mappings like `Mapping<K, Mapping<K2, V>>` are handled automatically
/// since the value type includes the full nested type.
pub(crate) fn classify_field_type(ty: &Type) -> syn::Result<FieldKind<'_>> {
    use crate::utils::extract_mapping_types;

    // Check if it's a mapping (mappings have fundamentally different API)
    if let Some((key_ty, value_ty)) = extract_mapping_types(ty) {
        return Ok(FieldKind::Mapping {
            key: key_ty,
            value: value_ty,
        });
    }

    // All non-mapping fields use the same accessor pattern
    Ok(FieldKind::Direct(ty))
}

/// Helper to compute prev and next slot constant references for a field at a given index.
///
/// Generic over the field type - uses a closure to extract the field name.
///
/// - `use_full_slot=true`: returns `*_SLOT` (U256) for contracts
/// - `use_full_slot=false`: returns `*_LOC.offset_slots` (usize) for storable structs
pub(crate) fn get_neighbor_slot_refs<T, F>(
    idx: usize,
    fields: &[T],
    packing: &Ident,
    get_name: F,
    use_full_slot: bool,
) -> (Option<TokenStream>, Option<TokenStream>)
where
    F: Fn(&T) -> &Ident,
{
    let prev_slot_ref = if idx > 0 {
        let prev_name = get_name(&fields[idx - 1]);
        if use_full_slot {
            let prev_slot = PackingConstants::new(prev_name).slot();
            Some(quote! { #packing::#prev_slot })
        } else {
            let prev_loc = PackingConstants::new(prev_name).location();
            Some(quote! { #packing::#prev_loc.offset_slots })
        }
    } else {
        None
    };

    let next_slot_ref = if idx + 1 < fields.len() {
        let next_name = get_name(&fields[idx + 1]);
        if use_full_slot {
            let next_slot = PackingConstants::new(next_name).slot();
            Some(quote! { #packing::#next_slot })
        } else {
            let next_loc = PackingConstants::new(next_name).location();
            Some(quote! { #packing::#next_loc.offset_slots })
        }
    } else {
        None
    };

    (prev_slot_ref, next_slot_ref)
}

/// Generate slot packing decision logic.
///
/// This function generates const expressions that determine whether two consecutive
/// fields can be packed into the same storage slot, and if so, calculates the
/// appropriate slot index and offset. Slot expressions use U256 arithmetic,
/// while offset expressions use usize.
pub(crate) fn gen_slot_packing_logic(
    prev_ty: &Type,
    curr_ty: &Type,
    prev_slot_expr: TokenStream,
    prev_offset_expr: TokenStream,
) -> (TokenStream, TokenStream) {
    // Helper for converting SLOTS to U256
    let prev_layout_slots = quote! {
        ::alloy::primitives::U256::from_limbs([<#prev_ty as crate::storage::StorableType>::SLOTS as u64, 0, 0, 0])
    };
    let curr_slots_to_end = quote! {
        ::alloy::primitives::U256::from_limbs([<#curr_ty as crate::storage::StorableType>::SLOTS as u64, 0, 0, 0])
            .saturating_sub(::alloy::primitives::U256::ONE)
    };

    // Compute packing decision at compile-time
    let can_pack_expr = quote! {
        #prev_offset_expr
            + <#prev_ty as crate::storage::StorableType>::BYTES
            + <#curr_ty as crate::storage::StorableType>::BYTES <= 32
    };

    let slot_expr = quote! {{
        if #can_pack_expr {
            #prev_slot_expr
        } else {
            // HACK: we leverage compiler evaluation checks to ensure that the full type can fit
            // by computing the slot as: `CURR_SLOT = PREV_SLOT + PREV_LEN + (CURR_LEN - 1) - (CURR_LEN - 1)`
            #prev_slot_expr
                .checked_add(#prev_layout_slots).expect("slot overflow")
                .checked_add(#curr_slots_to_end).expect("slot overflow")
                .saturating_sub(#curr_slots_to_end)
        }
    }};

    let offset_expr = quote! {{
        if #can_pack_expr { #prev_offset_expr + <#prev_ty as crate::storage::StorableType>::BYTES } else { 0 }
    }};

    (slot_expr, offset_expr)
}

/// Generate a `LayoutCtx` expression for accessing a field.
///
/// This helper unifies the logic for choosing between `LayoutCtx::FULL` and
/// `LayoutCtx::packed` based on compile-time slot comparison with neighboring fields.
///
/// A field uses `Packed` if it shares a slot with any neighboring field.
pub(crate) fn gen_layout_ctx_expr(
    ty: &Type,
    is_manual_slot: bool,
    slot_const_ref: TokenStream,
    offset_const_ref: TokenStream,
    prev_slot_const_ref: Option<TokenStream>,
    next_slot_const_ref: Option<TokenStream>,
) -> TokenStream {
    if !is_manual_slot && (prev_slot_const_ref.is_some() || next_slot_const_ref.is_some()) {
        // Check if this field shares a slot with prev or next field
        let prev_check = prev_slot_const_ref.map(|prev| quote! { #slot_const_ref == #prev });
        let next_check = next_slot_const_ref.map(|next| quote! { #slot_const_ref == #next });

        let shares_slot_check = match (prev_check, next_check) {
            (Some(prev), Some(next)) => quote! { (#prev || #next) },
            (Some(prev), None) => prev,
            (None, Some(next)) => next,
            (None, None) => unreachable!(),
        };

        quote! {
            {
                if #shares_slot_check && <#ty as crate::storage::StorableType>::IS_PACKABLE {
                    crate::storage::LayoutCtx::packed(#offset_const_ref)
                } else {
                    crate::storage::LayoutCtx::FULL
                }
            }
        }
    } else {
        quote! { crate::storage::LayoutCtx::FULL }
    }
}

/// Generate collision detection debug assertions for a field against all other fields.
///
/// This function generates runtime checks that verify storage slots don't overlap.
/// Checks are generated for all fields (both manual and auto-assigned) to ensure
/// comprehensive collision detection.
pub(crate) fn gen_collision_check_fn(
    idx: usize,
    field: &LayoutField<'_>,
    all_fields: &[LayoutField<'_>],
) -> (Ident, TokenStream) {
    fn gen_slot_count_expr(ty: &Type) -> TokenStream {
        quote! { ::alloy::primitives::U256::from_limbs([<#ty as crate::storage::StorableType>::SLOTS as u64, 0, 0, 0]) }
    }

    let check_fn_name = format_ident!("__check_collision_{}", field.name);
    let consts = PackingConstants::new(field.name);
    let (slot_const, offset_const) = consts.into_tuple();
    let (field_name, field_ty) = (field.name, field.ty);

    let mut checks = TokenStream::new();

    // Check against all other fields
    for (other_idx, other_field) in all_fields.iter().enumerate() {
        if other_idx == idx {
            continue;
        }

        let other_consts = PackingConstants::new(other_field.name);
        let (other_slot_const, other_offset_const) = other_consts.into_tuple();
        let other_name = other_field.name;
        let other_ty = other_field.ty;

        // Generate slot count expressions
        let current_count_expr = gen_slot_count_expr(field.ty);
        let other_count_expr = gen_slot_count_expr(other_field.ty);

        // Generate runtime assertion that checks for overlap
        // Two fields collide if their slot ranges overlap AND (if same slot) their byte ranges overlap
        checks.extend(quote! {
            {
                let slot = #slot_const;
                let slot_end = slot.checked_add(#current_count_expr).expect("slot range overflow");
                let other_slot = #other_slot_const;
                let other_slot_end = other_slot.checked_add(#other_count_expr).expect("slot range overflow");

                // Determine if there's no overlap:
                // - If starting in different slots: rely on slot range check
                // - If starting in same slot (packed fields): check byte ranges
                let no_overlap = if slot == other_slot {
                    let byte_end = #offset_const + <#field_ty as crate::storage::StorableType>::BYTES;
                    let other_byte_end = #other_offset_const + <#other_ty as crate::storage::StorableType>::BYTES;
                    byte_end <= #other_offset_const || other_byte_end <= #offset_const
                } else {
                    slot_end.le(&other_slot) || other_slot_end.le(&slot)
                };

                debug_assert!(
                    no_overlap,
                    "Storage slot collision: field `{}` (slot {:?}, offset {}) overlaps with field `{}` (slot {:?}, offset {})",
                    stringify!(#field_name),
                    slot,
                    #offset_const,
                    stringify!(#other_name),
                    other_slot,
                    #other_offset_const
                );
            }
        });
    }

    let check_fn = quote! {
        #[cfg(debug_assertions)]
        #[inline(always)]
        #[allow(non_snake_case)]
        fn #check_fn_name() {
            #checks
        }
    };

    (check_fn_name, check_fn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    /// Helper to build a simple `FieldInfo` for testing.
    fn field(name: &str, ty: Type, slot: Option<u64>, base_slot: Option<u64>) -> FieldInfo {
        FieldInfo {
            name: Ident::new(name, proc_macro2::Span::call_site()),
            ty,
            slot: slot.map(U256::from),
            base_slot: base_slot.map(U256::from),
        }
    }

    // -- allocate_slots ---------------------------------------------------------

    #[test]
    fn allocate_empty_fields() {
        let fields: Vec<FieldInfo> = vec![];
        let result = allocate_slots(&fields).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn allocate_single_auto_field() {
        let fields = vec![field("balance", parse_quote!(U256), None, None)];
        let result = allocate_slots(&fields).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(*result[0].assigned_slot.ref_slot(), U256::ZERO);
        assert!(matches!(result[0].assigned_slot, SlotAssignment::Auto { .. }));
    }

    #[test]
    fn allocate_single_manual_field() {
        let fields = vec![field("balance", parse_quote!(U256), Some(5), None)];
        let result = allocate_slots(&fields).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(*result[0].assigned_slot.ref_slot(), U256::from(5));
        assert!(matches!(result[0].assigned_slot, SlotAssignment::Manual(_)));
    }

    #[test]
    fn allocate_multiple_auto_fields_share_base_slot() {
        let fields = vec![
            field("a", parse_quote!(u8), None, None),
            field("b", parse_quote!(u16), None, None),
            field("c", parse_quote!(u32), None, None),
        ];
        let result = allocate_slots(&fields).unwrap();
        // All three should share base_slot = 0 (packing decided at compile-time)
        for r in &result {
            assert!(matches!(r.assigned_slot, SlotAssignment::Auto { base_slot } if base_slot == U256::ZERO));
        }
    }

    #[test]
    fn allocate_manual_slot_does_not_advance_auto_chain() {
        let fields = vec![
            field("a", parse_quote!(u8), None, None),        // auto, base=0
            field("b", parse_quote!(U256), Some(10), None),  // manual slot=10
            field("c", parse_quote!(u8), None, None),        // auto, should still be base=0
        ];
        let result = allocate_slots(&fields).unwrap();
        assert!(matches!(result[0].assigned_slot, SlotAssignment::Auto { base_slot } if base_slot == U256::ZERO));
        assert!(matches!(result[1].assigned_slot, SlotAssignment::Manual(s) if s == U256::from(10)));
        // Manual slot must NOT reset the auto chain
        assert!(matches!(result[2].assigned_slot, SlotAssignment::Auto { base_slot } if base_slot == U256::ZERO));
    }

    #[test]
    fn allocate_base_slot_resets_auto_chain() {
        let fields = vec![
            field("a", parse_quote!(u8), None, None),         // auto, base=0
            field("b", parse_quote!(u8), None, Some(5)),      // base_slot=5
            field("c", parse_quote!(u8), None, None),          // auto, should be base=5
        ];
        let result = allocate_slots(&fields).unwrap();
        assert!(matches!(result[0].assigned_slot, SlotAssignment::Auto { base_slot } if base_slot == U256::ZERO));
        assert!(matches!(result[1].assigned_slot, SlotAssignment::Auto { base_slot } if base_slot == U256::from(5)));
        assert!(matches!(result[2].assigned_slot, SlotAssignment::Auto { base_slot } if base_slot == U256::from(5)));
    }

    #[test]
    fn allocate_multiple_base_slot_resets() {
        let fields = vec![
            field("a", parse_quote!(u8), None, None),         // base=0
            field("b", parse_quote!(u8), None, Some(3)),      // base=3
            field("c", parse_quote!(u8), None, None),          // base=3
            field("d", parse_quote!(u8), None, Some(10)),     // base=10
            field("e", parse_quote!(u8), None, None),          // base=10
        ];
        let result = allocate_slots(&fields).unwrap();
        assert_eq!(*result[0].assigned_slot.ref_slot(), U256::ZERO);
        assert_eq!(*result[1].assigned_slot.ref_slot(), U256::from(3));
        assert_eq!(*result[2].assigned_slot.ref_slot(), U256::from(3));
        assert_eq!(*result[3].assigned_slot.ref_slot(), U256::from(10));
        assert_eq!(*result[4].assigned_slot.ref_slot(), U256::from(10));
    }

    #[test]
    fn allocate_interleaved_manual_and_base_slot() {
        let fields = vec![
            field("a", parse_quote!(u8), None, None),         // auto base=0
            field("b", parse_quote!(U256), Some(50), None),   // manual=50
            field("c", parse_quote!(u8), None, Some(20)),     // base_slot=20
            field("d", parse_quote!(u8), None, None),          // auto base=20
            field("e", parse_quote!(U256), Some(99), None),   // manual=99
            field("f", parse_quote!(u8), None, None),          // auto base=20 (manual doesn't change chain)
        ];
        let result = allocate_slots(&fields).unwrap();
        assert_eq!(*result[0].assigned_slot.ref_slot(), U256::ZERO);
        assert!(matches!(result[1].assigned_slot, SlotAssignment::Manual(s) if s == U256::from(50)));
        assert_eq!(*result[2].assigned_slot.ref_slot(), U256::from(20));
        assert_eq!(*result[3].assigned_slot.ref_slot(), U256::from(20));
        assert!(matches!(result[4].assigned_slot, SlotAssignment::Manual(s) if s == U256::from(99)));
        assert_eq!(*result[5].assigned_slot.ref_slot(), U256::from(20));
    }

    #[test]
    fn allocate_mapping_field_classified_correctly() {
        let fields = vec![
            field("balances", parse_quote!(Mapping<Address, U256>), None, None),
        ];
        let result = allocate_slots(&fields).unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0].kind, FieldKind::Mapping { .. }));
    }

    #[test]
    fn allocate_direct_field_classified_correctly() {
        let fields = vec![field("name", parse_quote!(String), None, None)];
        let result = allocate_slots(&fields).unwrap();
        assert!(matches!(result[0].kind, FieldKind::Direct(_)));
    }

    #[test]
    fn allocate_mixed_direct_and_mapping() {
        let fields = vec![
            field("name", parse_quote!(String), None, None),
            field("balances", parse_quote!(Mapping<Address, U256>), None, None),
            field("supply", parse_quote!(U256), None, None),
        ];
        let result = allocate_slots(&fields).unwrap();
        assert!(matches!(result[0].kind, FieldKind::Direct(_)));
        assert!(matches!(result[1].kind, FieldKind::Mapping { .. }));
        assert!(matches!(result[2].kind, FieldKind::Direct(_)));
    }

    #[test]
    fn allocate_preserves_field_names_and_types() {
        let fields = vec![
            field("alpha", parse_quote!(u64), None, None),
            field("beta", parse_quote!(U256), Some(7), None),
        ];
        let result = allocate_slots(&fields).unwrap();
        assert_eq!(result[0].name.to_string(), "alpha");
        assert_eq!(result[1].name.to_string(), "beta");
    }

    #[test]
    fn allocate_base_slot_zero_explicit() {
        // Explicitly setting base_slot=0 should behave same as default
        let fields = vec![
            field("a", parse_quote!(u8), None, Some(0)),
            field("b", parse_quote!(u8), None, None),
        ];
        let result = allocate_slots(&fields).unwrap();
        assert_eq!(*result[0].assigned_slot.ref_slot(), U256::ZERO);
        assert_eq!(*result[1].assigned_slot.ref_slot(), U256::ZERO);
    }

    #[test]
    fn allocate_large_manual_slot() {
        let fields = vec![field(
            "data",
            parse_quote!(U256),
            Some(u64::MAX),
            None,
        )];
        let result = allocate_slots(&fields).unwrap();
        assert!(matches!(result[0].assigned_slot, SlotAssignment::Manual(s) if s == U256::from(u64::MAX)));
    }

    // -- classify_field_type ----------------------------------------------------

    #[test]
    fn classify_simple_type_is_direct() {
        let ty: Type = parse_quote!(u64);
        assert!(matches!(classify_field_type(&ty).unwrap(), FieldKind::Direct(_)));
    }

    #[test]
    fn classify_mapping_type() {
        let ty: Type = parse_quote!(Mapping<Address, U256>);
        assert!(matches!(classify_field_type(&ty).unwrap(), FieldKind::Mapping { .. }));
    }

    #[test]
    fn classify_nested_mapping_type() {
        let ty: Type = parse_quote!(Mapping<Address, Mapping<Address, U256>>);
        if let FieldKind::Mapping { key: _, value } = classify_field_type(&ty).unwrap() {
            // The value type should itself be a Mapping
            assert!(extract_mapping_types(value).is_some());
        } else {
            panic!("expected Mapping kind");
        }
    }

    #[test]
    fn classify_non_mapping_generic_is_direct() {
        let ty: Type = parse_quote!(Vec<u8>);
        assert!(matches!(classify_field_type(&ty).unwrap(), FieldKind::Direct(_)));
    }

    // -- PackingConstants -------------------------------------------------------

    #[test]
    fn packing_constants_naming() {
        let name = Ident::new("total_supply", proc_macro2::Span::call_site());
        let consts = PackingConstants::new(&name);
        assert_eq!(consts.location().to_string(), "TOTAL_SUPPLY_LOC");
        let (slot, offset) = consts.into_tuple();
        assert_eq!(slot.to_string(), "TOTAL_SUPPLY");
        assert_eq!(offset.to_string(), "TOTAL_SUPPLY_OFFSET");
    }

    #[test]
    fn const_name_screaming_snake() {
        let name = Ident::new("my_field", proc_macro2::Span::call_site());
        assert_eq!(const_name(&name), "MY_FIELD");
    }

    // -- SlotAssignment ---------------------------------------------------------

    #[test]
    fn slot_assignment_ref_slot_manual() {
        let sa = SlotAssignment::Manual(U256::from(42));
        assert_eq!(*sa.ref_slot(), U256::from(42));
    }

    #[test]
    fn slot_assignment_ref_slot_auto() {
        let sa = SlotAssignment::Auto { base_slot: U256::from(7) };
        assert_eq!(*sa.ref_slot(), U256::from(7));
    }

    use crate::utils::extract_mapping_types;
}
