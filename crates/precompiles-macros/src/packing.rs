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

        // Generate byte count constants for each field
        let bytes_expr = quote! { <#ty as crate::storage::StorableType>::BYTES };

        // Generate slot and offset constants for each field
        let (slot_expr, offset_expr) = match &field.assigned_slot {
            // Manual slot assignment always has offset 0
            SlotAssignment::Manual(manual_slot) => {
                let hex_value = format!("{manual_slot}_U256");
                let slot_lit = syn::LitInt::new(&hex_value, proc_macro2::Span::call_site());
                let slot_expr = quote! { ::alloy::primitives::uint!(#slot_lit) };
                (slot_expr, quote! { 0 })
            }
            // Auto-assignment computes slot/offset using const expressions
            SlotAssignment::Auto { base_slot, .. } => {
                let output = if let Some(current_base) = current_base_slot {
                    // Fields that share the same base compute their slots based on the previous field
                    if current_base.assigned_slot.ref_slot() == field.assigned_slot.ref_slot() {
                        let (prev_slot, prev_offset) =
                            PackingConstants::new(current_base.name).into_tuple();
                        gen_slot_packing_logic(
                            current_base.ty,
                            field.ty,
                            quote! { #prev_slot },
                            quote! { #prev_offset },
                        )
                    }
                    // If a new base is adopted, start from the base slot and offset 0
                    else {
                        let limbs = *base_slot.as_limbs();
                        (
                            quote! { ::alloy::primitives::U256::from_limbs([#(#limbs),*]) },
                            quote! { 0 },
                        )
                    }
                }
                // First field always starts at slot 0 and offset 0
                else {
                    (quote! { ::alloy::primitives::U256::ZERO }, quote! { 0 })
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
pub(crate) fn get_neighbor_slot_refs<T, F>(
    idx: usize,
    fields: &[T],
    packing: &Ident,
    get_name: F,
) -> (Option<TokenStream>, Option<TokenStream>)
where
    F: Fn(&T) -> &Ident,
{
    let prev_slot_ref = if idx > 0 {
        let prev_name = get_name(&fields[idx - 1]);
        let prev_slot = PackingConstants::new(prev_name).location();
        Some(quote! { #packing::#prev_slot.offset_slots })
    } else {
        None
    };

    let next_slot_ref = if idx + 1 < fields.len() {
        let next_name = get_name(&fields[idx + 1]);
        let next_slot = PackingConstants::new(next_name).location();
        Some(quote! { #packing::#next_slot.offset_slots })
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

    // Compute packing decision at compile-time
    let can_pack_expr = quote! {
        #prev_offset_expr
            + <#prev_ty as crate::storage::StorableType>::BYTES
            + <#curr_ty as crate::storage::StorableType>::BYTES <= 32
    };

    let slot_expr = quote! {{
        if #can_pack_expr { #prev_slot_expr } else { #prev_slot_expr.checked_add(#prev_layout_slots).expect("slot overflow") }
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

// TODO(rusowsky): fully embrace `fn gen_layout_ctx_expr` to reduce gas usage.
// Note that this requires a hardfork and must be properly coordinated.

/// Generate a `LayoutCtx` expression for accessing a field.
///
/// Despite we could deterministically know if a field shares its slot with a neighbour, we
/// treat all primitive types as packable for backward-compatibility reasons.
pub(crate) fn gen_layout_ctx_expr_inefficient(
    ty: &Type,
    is_manual_slot: bool,
    _slot_const_ref: TokenStream,
    offset_const_ref: TokenStream,
    _prev_slot_const_ref: Option<TokenStream>,
    _next_slot_const_ref: Option<TokenStream>,
) -> TokenStream {
    if !is_manual_slot {
        quote! {
            if <#ty as crate::storage::StorableType>::IS_PACKABLE {
                crate::storage::LayoutCtx::packed(#offset_const_ref)
            } else {
                crate::storage::LayoutCtx::FULL
            }
        }
    } else {
        quote! { crate::storage::LayoutCtx::FULL }
    }
}

/// Generate collision detection debug assertions for a field against all other fields.
///
/// This function generates runtime checks that verify storage slots don't overlap.
/// Only manual slot assignments are checked, as auto-assigned slots are guaranteed
/// not to collide by the allocation algorithm.
pub(crate) fn gen_collision_check_fn(
    idx: usize,
    field: &LayoutField<'_>,
    all_fields: &[LayoutField<'_>],
) -> Option<(Ident, TokenStream)> {
    fn gen_slot_count_expr(ty: &Type) -> TokenStream {
        quote! { ::alloy::primitives::U256::from_limbs([<#ty as crate::storage::StorableType>::SLOTS as u64, 0, 0, 0]) }
    }

    // Only check explicit slot assignments against other fields
    if let SlotAssignment::Manual(_) = field.assigned_slot {
        let field_name = field.name;
        let check_fn_name = format_ident!("__check_collision_{}", field_name);
        let slot_const = PackingConstants::new(field.name).slot();

        let mut checks = TokenStream::new();

        // Check against all other fields
        for (other_idx, other_field) in all_fields.iter().enumerate() {
            if other_idx == idx {
                continue;
            }

            let other_slot_const = PackingConstants::new(other_field.name).slot();
            let other_name = other_field.name;

            // Generate slot count expressions
            let current_count_expr = gen_slot_count_expr(field.ty);
            let other_count_expr = gen_slot_count_expr(other_field.ty);

            // Generate runtime assertion that checks for overlap
            checks.extend(quote! {
                {
                    let slot = #slot_const;
                    let slot_end = slot + #current_count_expr;
                    let other_slot = #other_slot_const;
                    let other_end = other_slot + #other_count_expr;

                    let no_overlap = slot_end.le(&other_slot) || other_end.le(&slot);
                    debug_assert!(
                        no_overlap,
                        "Storage slot collision: field `{}` (slot {:?}) overlaps with field `{}` (slot {:?})",
                        stringify!(#field_name),
                        slot,
                        stringify!(#other_name),
                        other_slot
                    );
                }
            });
        }

        let check_fn = quote! {
            #[cfg(debug_assertions)]
            #[inline(always)]
            fn #check_fn_name() {
                #checks
            }
        };

        Some((check_fn_name, check_fn))
    } else {
        None
    }
}
