//! Shared code generation utilities for storage slot packing.
//!
//! This module provides common logic for computing slot and offset assignments
//! used by both the `#[derive(Storable)]` and `#[contract]` macros.

use alloy::primitives::U256;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Ident, Type};

use crate::FieldKind;

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

    /// The `_SLOT` suffixed constant (usize slot, used by `Storable` macro)
    pub(crate) fn slot_usize(&self) -> Ident {
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

    /// Returns all three constant identifiers as a tuple (slot, offset, bytes)
    pub(crate) fn into_tuple(self) -> (Ident, Ident, Ident) {
        (self.slot(), self.offset(), self.bytes())
    }

    /// Returns all three constant identifiers as a tuple (slot_usize, offset, bytes)
    pub(crate) fn into_tuple_usize(self) -> (Ident, Ident, Ident) {
        (self.slot_usize(), self.offset(), self.bytes())
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
            let base_slot = if index == 0 {
                let slot = last_auto_slot;
                last_auto_slot += U256::ONE;
                slot
            } else {
                let prev: &LayoutField<'_> = &result[index - 1];

                // If previous also was auto-assigned, reuse base slot (becomes packing candidate)
                if let SlotAssignment::Auto { base_slot } = &prev.assigned_slot {
                    *base_slot
                }
                // Otherwise, start new slot
                else {
                    let slot = last_auto_slot;
                    last_auto_slot += U256::ONE;
                    slot
                }
            };

            SlotAssignment::Auto { base_slot }
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
/// This function generates compile-time constants (`<FIELD>`, `<FIELD>_OFFSET`, `<FIELD>_BYTES`)
/// for slot assignments, offsets, and byte sizes based on the layout IR using field-name-based naming.
/// Slot constants (`<FIELD>`) are generated as `U256` types, while offset and bytes constants use `usize`.
pub(crate) fn gen_constants_from_ir(fields: &[LayoutField<'_>]) -> TokenStream {
    let mut constants = TokenStream::new();

    for field in fields {
        let consts = PackingConstants::new(field.name);
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
                let hex_value = format!("{manual_slot}_U256");
                let slot_lit = syn::LitInt::new(&hex_value, proc_macro2::Span::call_site());
                let slot_expr =
                    quote! { ::alloy::primitives::U256 = ::alloy::primitives::uint!(#slot_lit) };
                (slot_expr, quote! { 0 })
            }
            // Auto-assignment computes slot/offset using const expressions
            SlotAssignment::Auto { base_slot, .. } => {
                // First field always starts at slot 0, offset 0
                if field.index == 0 {
                    let slot_expr =
                        quote! { ::alloy::primitives::U256 = ::alloy::primitives::U256::ZERO };
                    (slot_expr, quote! { 0 })
                }
                // Subsequent fields compute their slots based on the previous field
                else {
                    let prev_field = &fields[field.index - 1];
                    if matches!(prev_field.assigned_slot, SlotAssignment::Manual(_)) {
                        // If previous was manual and current is auto, use base slot directly
                        let limbs = *base_slot.as_limbs();
                        let slot_expr = quote! { ::alloy::primitives::U256 = ::alloy::primitives::U256::from_limbs([#(#limbs),*]) };
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
                            prev_field.kind.is_mapping(),
                            field.kind.is_mapping(),
                        );

                        let slot_expr = quote! { ::alloy::primitives::U256 = #slot_expr_inner };

                        (slot_expr, offset_expr)
                    }
                }
            }
        };

        // Generate slot constant without suffix (U256) and offset constant (usize)
        constants.extend(quote! {
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
        quote! { <#ty as crate::storage::StorableType>::BYTES }
    }
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
    is_prev_mapping: bool,
    is_curr_mapping: bool,
) -> (TokenStream, TokenStream) {
    // Helper for converting SLOTS to U256
    let prev_layout_slots = quote! {
        ::alloy::primitives::U256::from_limbs([<#prev_ty as crate::storage::StorableType>::SLOTS as u64, 0, 0, 0])
    };

    // If previous field is a mapping, current field starts on next slot
    // TODO(rusowsky): Necessary to avoid type resolution issues. Remove once `SlotId` is dropped
    if is_prev_mapping {
        let slot_expr = quote! {
            #prev_slot_expr.checked_add(::alloy::primitives::U256::ONE).expect("slot overflow")
        };
        return (slot_expr, quote! { 0 });
    }

    // If current field is a mapping, it must start on a new slot
    // TODO(rusowsky): Necessary to avoid type resolution issues. Remove once `SlotId` is dropped
    if is_curr_mapping {
        let slot_expr = quote! {{
            #prev_slot_expr.checked_add(#prev_layout_slots).expect("slot overflow")
        }};
        return (slot_expr, quote! { 0 });
    }

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
                if <#ty as crate::storage::StorableType>::IS_PACKABLE {
                    crate::storage::LayoutCtx::Packed(#offset_const_ref)
                } else {
                    crate::storage::LayoutCtx::Full
                }
            }
        }
    }
}

/// Generate a single SlotId type definition.
///
/// This creates a marker type that implements the `SlotId` trait, which is used
/// to reference storage slots in the generated code.
pub(crate) fn gen_slot_id_type(
    slot_id_name: &str,
    field_name: &Ident,
    slot_const_name: &str,
) -> TokenStream {
    let slot_id_ident = format_ident!("{}", slot_id_name);
    let slot_const = format_ident!("{}", slot_const_name);

    quote! {
        #[doc = concat!("Storage slot for `", stringify!(#field_name), "` field")]
        pub struct #slot_id_ident;

        impl crate::storage::SlotId for #slot_id_ident {
            const SLOT: ::alloy::primitives::U256 = #slot_const;
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
    slot_id_name_fn: impl Fn(&Ident) -> String,
) -> Option<(Ident, TokenStream)> {
    fn gen_slot_count_expr(kind: &FieldKind<'_>, ty: &Type) -> TokenStream {
        if kind.is_mapping() {
            quote! { ::alloy::primitives::U256::ONE }
        } else {
            quote! { ::alloy::primitives::U256::from_limbs([<#ty as crate::storage::StorableType>::SLOTS as u64, 0, 0, 0]) }
        }
    }

    // Only check explicit slot assignments against other fields
    if let SlotAssignment::Manual(_) = field.assigned_slot {
        let slot_id = format_ident!("{}", slot_id_name_fn(field.name));
        let field_name = field.name;
        let check_fn_name = format_ident!("__check_collision_{}", field_name);

        let mut checks = TokenStream::new();

        // Check against all other fields
        for (other_idx, other_field) in all_fields.iter().enumerate() {
            if other_idx == idx {
                continue;
            }

            let other_slot_id = format_ident!("{}", slot_id_name_fn(other_field.name));
            let other_name = other_field.name;

            // Generate slot count expressions
            let current_count_expr = gen_slot_count_expr(&field.kind, field.ty);
            let other_count_expr = gen_slot_count_expr(&other_field.kind, other_field.ty);

            // Generate runtime assertion that checks for overlap
            checks.extend(quote! {
                {
                    let slot = <#slot_id as crate::storage::SlotId>::SLOT;
                    let slot_end = slot + #current_count_expr;
                    let other_slot = <#other_slot_id as crate::storage::SlotId>::SLOT;
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
