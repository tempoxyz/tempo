//! Shared code generation utilities for storage slot packing.
//!
//! This module provides common logic for computing slot and offset assignments
//! used by both the `#[derive(Storable)]` and `#[contract]` macros.

use alloy::primitives::U256;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Ident, Type};

use crate::FieldKind;

/// Configuration for slot type generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotType {
    U256,  // used by `contract` macro
    Usize, // used by `Storable` derive
}

/// Helper for generating packing constant identifiers
pub(crate) struct PackingConstants(String);

impl PackingConstants {
    /// Create packing constant helper struct
    pub(crate) fn new(name: &Ident) -> Self {
        Self(const_name(name))
    }

    pub(crate) fn ident(&self) -> Ident {
        format_ident!("{}", &self.0)
    }

    /// The `SLOT` constant identifier
    pub(crate) fn slot(&self) -> Ident {
        let span = proc_macro2::Span::call_site();
        Ident::new(&format!("{}_SLOT", self.0), span)
    }

    /// The `OFFSET` constant identifier
    pub(crate) fn offset(&self) -> Ident {
        let span = proc_macro2::Span::call_site();
        Ident::new(&format!("{}_OFFSET", self.0), span)
    }

    /// The `BYTES` constant identifier
    pub(crate) fn bytes(&self) -> Ident {
        let span = proc_macro2::Span::call_site();
        Ident::new(&format!("{}_BYTES", self.0), span)
    }

    /// Returns all three constant identifiers as a tuple
    pub(crate) fn into_tuple(self) -> (Ident, Ident, Ident) {
        (self.slot(), self.offset(), self.bytes())
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
        /// Whether this field is directly assigned to a slot (not a mapping).
        direct_alloc: bool,
    },
}

/// A single field in the storage layout with computed slot information.
#[derive(Debug)]
pub(crate) struct LayoutField<'a> {
    /// Field name
    pub name: &'a Ident,
    /// Field type
    pub ty: &'a Type,
    /// Field kind (Direct, Mapping, or NestedMapping)
    pub kind: FieldKind<'a>,
    /// The assigned storage slot for this field (or base for const-eval chain)
    pub assigned_slot: SlotAssignment,
    /// Original field index in the struct
    pub index: usize,
}

/// Helper trait to extract field information needed for layout IR construction.
///
/// This allows `allocate_slots` to work with different field types from
/// different macros (e.g., `FieldInfo` from `#[contract]`, or tuples from `#[derive(Storable)]`).
pub(crate) trait FieldInfoExt {
    fn field_name(&self) -> &Ident;
    fn field_type(&self) -> &Type;
    fn manual_slot(&self) -> Option<U256>;
    fn base_slot_attr(&self) -> Option<U256>;
}

/// Implementation for simple (name, type) tuples used by the `Storable` derive macro.
/// These fields never have manual slot assignments.
impl<'a> FieldInfoExt for (&'a Ident, &'a Type) {
    fn field_name(&self) -> &Ident {
        self.0
    }
    fn field_type(&self) -> &Type {
        self.1
    }
    fn manual_slot(&self) -> Option<U256> {
        None
    }
    fn base_slot_attr(&self) -> Option<U256> {
        None
    }
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
pub(crate) fn allocate_slots<'a, F>(fields: &'a [F]) -> syn::Result<Vec<LayoutField<'a>>>
where
    F: FieldInfoExt,
{
    let mut result = Vec::with_capacity(fields.len());
    let mut last_auto_slot = U256::ZERO;

    for (index, field) in fields.iter().enumerate() {
        let name = field.field_name();
        let ty = field.field_type();
        let manual_slot = field.manual_slot();
        let base_slot_attr = field.base_slot_attr();
        let kind = classify_field_type(ty)?;

        // Determine slot assignment
        let assigned_slot = if let Some(explicit) = manual_slot {
            // Explicit fixed slot, doesn't affect auto-assignment chain
            SlotAssignment::Manual(explicit)
        } else if let Some(base) = base_slot_attr {
            // Explicit base slot, resets auto-assignment chain
            let assignment = SlotAssignment::Manual(base);
            last_auto_slot = base + U256::ONE;
            assignment
        } else {
            // Auto-assignment with packing support
            let is_primitive = kind.is_direct();

            // Non-primitives always start a new slot
            let base_slot = if index == 0 || !is_primitive {
                let slot = last_auto_slot;
                last_auto_slot += U256::ONE;
                slot
            }
            // Otherwise, check if previous field was also primitive
            else {
                let prev: &LayoutField<'_> = &result[index - 1];

                // If previous was also a primitive, reuse base slot (becomes packing candidate)
                if let SlotAssignment::Auto {
                    base_slot,
                    direct_alloc: true,
                } = &prev.assigned_slot
                    && prev.kind.is_direct()
                {
                    *base_slot
                }
                // Otherwise, start new slot
                else {
                    let slot = last_auto_slot;
                    last_auto_slot += U256::ONE;
                    slot
                }
            };

            SlotAssignment::Auto {
                base_slot,
                direct_alloc: is_primitive,
            }
        };

        result.push(LayoutField {
            name,
            ty,
            kind,
            assigned_slot,
            index,
        });
    }

    Ok(result)
}

/// Generate packing constants from layout IR.
///
/// This function generates compile-time constants (`<FIELD>_SLOT`, `<FIELD>_OFFSET`, `<FIELD>_BYTES`)
/// for slot assignments, offsets, and byte sizes based on the layout IR using field-name-based naming.
pub(crate) fn gen_constants_from_ir(
    fields: &[LayoutField<'_>],
    slot_type: SlotType,
) -> TokenStream {
    let mut constants = TokenStream::new();

    for field in fields {
        let consts = PackingConstants::new(field.name);
        let const_name = consts.ident();
        let (slot_const, offset_const, bytes_const) = consts.into_tuple();

        // Generate byte count constants for each field
        let byte_count_expr = gen_byte_count_expr(field.ty, field.kind.is_mapping());
        constants.extend(quote! {
            pub const #bytes_const: usize = #byte_count_expr;
        });

        // Generate slot and offset constants for each field
        let (slot_expr, offset_expr) = match &field.assigned_slot {
            // Manual slot assignment always has offset 0
            SlotAssignment::Manual(manual_slot) => {
                let slot_expr = match slot_type {
                    SlotType::Usize => {
                        let value = manual_slot.to::<usize>();
                        quote! { usize = #value }
                    }
                    SlotType::U256 => {
                        let hex_value = format!("{manual_slot}_U256");
                        let slot_lit = syn::LitInt::new(&hex_value, proc_macro2::Span::call_site());
                        quote! { ::alloy::primitives::U256 = ::alloy::primitives::uint!(#slot_lit) }
                    }
                };
                (slot_expr, quote! { 0 })
            }
            // Auto-assignment computes slot/offset using const expressions
            SlotAssignment::Auto { base_slot, .. } => {
                // First field always starts at slot 0, offset 0
                if field.index == 0 {
                    let slot_expr = match slot_type {
                        SlotType::Usize => quote! { usize = 0 },
                        SlotType::U256 => {
                            quote! { ::alloy::primitives::U256 = ::alloy::primitives::U256::ZERO }
                        }
                    };
                    (slot_expr, quote! { 0 })
                }
                // Subsequent fields compute their slots based on the previous field
                else {
                    let prev_field = &fields[field.index - 1];
                    if matches!(prev_field.assigned_slot, SlotAssignment::Manual(_)) {
                        // If previous was manual and current is auto, use base slot directly
                        let slot_expr = match slot_type {
                            SlotType::Usize => {
                                let value = base_slot.to::<usize>();
                                quote! { usize = #value }
                            }
                            SlotType::U256 => {
                                let limbs = *base_slot.as_limbs();
                                quote! { ::alloy::primitives::U256 = ::alloy::primitives::U256::from_limbs([#(#limbs),*]) }
                            }
                        };
                        (slot_expr, quote! { 0 })
                    } else {
                        // If previous was also auto, use packing logic
                        let (prev_slot, prev_offset, _) =
                            PackingConstants::new(prev_field.name).into_tuple();

                        let (slot_expr_inner, offset_expr) = gen_slot_packing_logic(
                            prev_field.ty,
                            field.ty,
                            quote! { #prev_slot },
                            quote! { #prev_offset },
                            slot_type,
                            prev_field.kind.is_mapping(),
                            field.kind.is_mapping(),
                        );

                        let slot_expr = match slot_type {
                            SlotType::Usize => quote! { usize = #slot_expr_inner },
                            SlotType::U256 => {
                                quote! { ::alloy::primitives::U256 = #slot_expr_inner }
                            }
                        };

                        (slot_expr, offset_expr)
                    }
                }
            }
        };

        let slot_const_without_suffix = match slot_type {
            SlotType::U256 => quote! { pub const #const_name: #slot_expr; },
            SlotType::Usize => quote! {},
        };

        constants.extend(quote! {
            #slot_const_without_suffix
            pub const #slot_const: #slot_expr;
            pub const #offset_const: usize = #offset_expr;
        });
    }

    constants
}

/// Classify a field based on its type.
///
/// Determines if a field is a direct value, mapping, or nested mapping.
pub(crate) fn classify_field_type(ty: &Type) -> syn::Result<FieldKind<'_>> {
    use crate::utils::extract_mapping_types;

    // Check if it's a mapping (mappings have fundamentally different API)
    if let Some((key_ty, value_ty)) = extract_mapping_types(ty) {
        if let Some((key2_ty, value2_ty)) = extract_mapping_types(value_ty) {
            return Ok(FieldKind::NestedMapping {
                key1: key_ty,
                key2: key2_ty,
                value: value2_ty,
            });
        } else {
            return Ok(FieldKind::Mapping {
                key: key_ty,
                value: value_ty,
            });
        }
    }

    // All non-mapping fields use the same accessor pattern
    Ok(FieldKind::Slot(ty))
}

/// Generate byte count expression for a field type.
///
/// Returns a const expression that evaluates to the byte size of the type.
/// For mapping types, returns `32` directly to avoid type resolution issues.
pub(crate) fn gen_byte_count_expr(ty: &Type, is_mapping: bool) -> TokenStream {
    if is_mapping {
        // Mappings: hardcode 32 bytes to avoid type resolution issues
        // TODO(rusowsky): remove once `SlotId` is dropped
        quote! { 32 }
    } else {
        quote! { <#ty as crate::storage::StorableType>::LAYOUT.bytes() }
    }
}

/// Generate slot packing decision logic.
///
/// This function generates const expressions that determine whether two consecutive
/// fields can be packed into the same storage slot, and if so, calculates the
/// appropriate slot index and offset.
pub(crate) fn gen_slot_packing_logic(
    prev_ty: &Type,
    curr_ty: &Type,
    prev_slot_expr: TokenStream,
    prev_offset_expr: TokenStream,
    slot_type: SlotType,
    is_prev_mapping: bool,
    is_curr_mapping: bool,
) -> (TokenStream, TokenStream) {
    // Helper reused in several arms
    let prev_layout_slots = match slot_type {
        SlotType::Usize => quote! {  PREV_LAYOUT.slots() },
        SlotType::U256 => {
            quote! { ::alloy::primitives::U256::from_limbs([PREV_LAYOUT.slots() as u64, 0, 0, 0]) }
        }
    };

    // If previous field is a mapping, current field starts on next slot
    if is_prev_mapping {
        let slot_expr = match slot_type {
            SlotType::Usize => quote! { #prev_slot_expr + 1 },
            SlotType::U256 => {
                quote! { #prev_slot_expr.checked_add(::alloy::primitives::U256::ONE).expect("slot overflow") }
            }
        };
        return (slot_expr, quote! { 0 });
    }

    // If current field is a mapping, it must start on a new slot
    if is_curr_mapping {
        let slot_expr = match slot_type {
            SlotType::Usize => quote! {
                {
                    const PREV_LAYOUT: crate::storage::Layout = <#prev_ty as crate::storage::StorableType>::LAYOUT;
                    #prev_slot_expr + #prev_layout_slots
                }
            },
            SlotType::U256 => quote! {
                {
                    const PREV_LAYOUT: crate::storage::Layout = <#prev_ty as crate::storage::StorableType>::LAYOUT;
                    #prev_slot_expr.checked_add(#prev_layout_slots).expect("slot overflow")
                }
            },
        };
        return (slot_expr, quote! { 0 });
    }

    // Standard packing logic for non-mapping fields
    let can_pack_expr = quote! {
        const PREV_LAYOUT: crate::storage::Layout = <#prev_ty as crate::storage::StorableType>::LAYOUT;
        const CURR_LAYOUT: crate::storage::Layout = <#curr_ty as crate::storage::StorableType>::LAYOUT;

        // Compute packing decision at compile-time
        const PREV_END: usize = #prev_offset_expr + PREV_LAYOUT.bytes();
        const CAN_PACK: bool = PREV_LAYOUT.is_packable() && CURR_LAYOUT.is_packable() && PREV_END + CURR_LAYOUT.bytes() <= 32;
    };

    let slot_expr = quote! {
        {
            #can_pack_expr
            if CAN_PACK { #prev_slot_expr } else { #prev_slot_expr.checked_add(#prev_layout_slots).expect("slot overflow") }
        }
    };

    let offset_expr = quote! {
        {
            #can_pack_expr
            if CAN_PACK { PREV_END } else { 0 }
        }
    };

    (slot_expr, offset_expr)
}

/// Generate a LayoutCtx expression for accessing a field.
///
/// This helper unifies the logic for choosing between `LayoutCtx::Full` and
/// `LayoutCtx::Packed` based on whether the field is manually assigned and
/// whether it's packable.
pub(crate) fn gen_layout_ctx_expr(
    ty: &Type,
    is_manual_slot: bool,
    offset_const_ref: TokenStream,
) -> TokenStream {
    if is_manual_slot {
        quote! { crate::storage::LayoutCtx::Full }
    } else {
        quote! {
            {
                const IS_PACKABLE: bool = <#ty as crate::storage::StorableType>::LAYOUT.is_packable();
                const OFFSET: usize = #offset_const_ref;
                if IS_PACKABLE {
                    crate::storage::LayoutCtx::Packed(OFFSET)
                } else {
                    crate::storage::LayoutCtx::Full
                }
            }
        }
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
    fn gen_slot_count_expr(kind: &FieldKind<'_>, ty: &Type) -> TokenStream {
        if kind.is_mapping() {
            quote! { ::alloy::primitives::U256::ONE }
        } else {
            quote! { ::alloy::primitives::U256::from_limbs([<#ty as crate::storage::StorableType>::LAYOUT.slots() as u64, 0, 0, 0]) }
        }
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
            let current_count_expr = gen_slot_count_expr(&field.kind, field.ty);
            let other_count_expr = gen_slot_count_expr(&other_field.kind, other_field.ty);

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
