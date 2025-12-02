use crate::{
    FieldInfo, FieldKind,
    utils::{
        extract_mapping_types, is_array_type, is_custom_struct, is_dynamic_type, to_pascal_case,
    },
};
use alloy::primitives::U256;
use quote::{format_ident, quote};
use syn::{Ident, Type, Visibility};

/// A field with its allocated slot and classification
#[derive(Debug)]
pub(crate) struct AllocatedField<'a> {
    /// Reference to the original field information
    info: &'a FieldInfo,
    /// The assigned storage slot for this field (or base for const-eval chain)
    assigned_slot: SlotAssignment,
    /// Classification based on the field's type
    kind: FieldKind<'a>,
    /// Field index in packing module (used to reference packing constants)
    field_index: usize,
}

impl<'a> AllocatedField<'a> {
    /// Returns the `SlotId` type name for this field
    fn slot_id_name(&self) -> String {
        format!("{}Slot", to_pascal_case(&self.info.name.to_string()))
    }
}

/// Represents how a slot is assigned
#[derive(Debug, Clone)]
pub(crate) enum SlotAssignment {
    /// Manual slot value: `#[slot(N)]` or `#[base_slot(N)]`
    Manual(U256),
    /// Auto-assigned: stores after the latest auto-assigned field
    Auto {
        /// Base slot for packing decisions. Consecutive primitives sharing the same
        /// base_slot are candidates for packing together. The actual slot/offset is
        /// computed later during const-eval in `gen_packing_constants_for_slots_module`.
        base_slot: U256,
        /// Whether this field can participate in slot packing (primitive types only)
        is_primitive: bool,
    },
}

/// Allocate slots to fields (explicit + auto-assignment)
pub(crate) fn allocate_slots(fields: &[FieldInfo]) -> syn::Result<Vec<AllocatedField<'_>>> {
    let mut allocated_fields = Vec::new();
    let mut last_auto_slot = U256::ZERO;
    let classified_fields: Vec<FieldKind<'_>> =
        fields.iter().map(classify_field).collect::<syn::Result<_>>()?;

    for (idx, (field, kind)) in fields.iter().zip(classified_fields.into_iter()).enumerate() {
        let assigned_slot = if let Some(explicit) = field.slot {
            // Explicit fixed slot, doesn't affect auto-assignment chain
            SlotAssignment::Manual(explicit)
        } else if let Some(base) = field.base_slot {
            // Explicit base slot, resets auto-assignment chain
            let slot = SlotAssignment::Manual(base);
            last_auto_slot = base + U256::ONE;
            slot
        } else {
            // Auto-assignment with packing support
            let is_primitive = kind.is_direct();

            // For primitives: try to reuse previous primitive's base slot (packing candidates)
            // For non-primitives: always start new slot
            let base_slot = if idx == 0 || !is_primitive {
                // First field or non-primitive: start new slot
                let slot = last_auto_slot;
                last_auto_slot += U256::ONE;
                slot
            } else {
                // Subsequent primitive: check if previous field was also primitive
                let prev: &AllocatedField<'_> = &allocated_fields[idx - 1];

                // If previous was also a primitive, reuse base slot (becomes packing candidate)
                if let SlotAssignment::Auto { base_slot, is_primitive: true } = &prev.assigned_slot &&
                    prev.kind.is_direct()
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

            SlotAssignment::Auto { base_slot, is_primitive }
        };

        allocated_fields.push(AllocatedField {
            info: field,
            assigned_slot,
            kind,
            field_index: idx,
        });
    }

    Ok(allocated_fields)
}

/// Classify a field based on its type and attributes
fn classify_field(field: &FieldInfo) -> syn::Result<FieldKind<'_>> {
    let ty = &field.ty;

    // Check if it's a mapping
    if let Some((key_ty, value_ty)) = extract_mapping_types(ty) {
        if let Some((key2_ty, value2_ty)) = extract_mapping_types(value_ty) {
            return Ok(FieldKind::NestedMapping { key1: key_ty, key2: key2_ty, value: value2_ty });
        } else {
            return Ok(FieldKind::Mapping { key: key_ty, value: value_ty });
        }
    }

    // If not a mapping, check if it's a multi-slot field type (structs and fixed-size arrays)
    if is_custom_struct(ty) || is_array_type(ty) {
        Ok(FieldKind::StorageBlock(ty))
    } else {
        Ok(FieldKind::Direct)
    }
}

/// Generate the transformed struct with generic parameters and runtime fields
pub(crate) fn gen_struct(name: &Ident, vis: &Visibility) -> proc_macro2::TokenStream {
    quote! {
        #vis struct #name<'a, S: crate::storage::PrecompileStorageProvider> {
            address: ::alloy::primitives::Address,
            storage: &'a mut S,
        }
    }
}

/// Generate the constructor method
pub(crate) fn gen_constructor(name: &Ident) -> proc_macro2::TokenStream {
    quote! {
        impl<'a, S: crate::storage::PrecompileStorageProvider> #name<'a, S> {
            #[inline(always)]
            fn _new(address: ::alloy::primitives::Address, storage: &'a mut S) -> Self {
                Self {
                    address,
                    storage,
                }
            }
        }
    }
}

/// Generate the `trait ContractStorage` implementation
pub(crate) fn gen_contract_storage_impl(name: &Ident) -> proc_macro2::TokenStream {
    quote! {
        impl<'a, S: crate::storage::PrecompileStorageProvider>
            crate::storage::ContractStorage for #name<'a, S>
        {
            type Storage = S;

            #[inline(always)]
            fn address(&self) -> ::alloy::primitives::Address {
                self.address
            }

            #[inline(always)]
            fn storage(&mut self) -> &mut Self::Storage {
                self.storage
            }
        }
    }
}

/// Generate getters and setters methods for a field
pub(crate) fn gen_getters_and_setters(
    struct_name: &Ident,
    allocated: &AllocatedField<'_>,
) -> proc_macro2::TokenStream {
    let field_name = &allocated.info.name;
    let field_ty = &allocated.info.ty;

    let getter_name = format_ident!("sload_{}", field_name);
    let setter_name = format_ident!("sstore_{}", field_name);
    let cleaner_name = format_ident!("clear_{}", field_name);
    let slot_id = format_ident!("{}", allocated.slot_id_name());

    match &allocated.kind {
        FieldKind::Direct => {
            // Manual slots and dynamic types are never packed (always at offset 0)
            if matches!(allocated.assigned_slot, SlotAssignment::Manual(_)) ||
                is_dynamic_type(field_ty)
            {
                quote! {
                    impl<'a, S: crate::storage::PrecompileStorageProvider> #struct_name<'a, S> {
                        #[inline]
                        fn #getter_name(&mut self) -> crate::error::Result<#field_ty> {
                            crate::storage::Slot::<#field_ty, #slot_id>::read(self)
                        }

                        #[inline]
                        fn #cleaner_name(&mut self) -> crate::error::Result<()> {
                            crate::storage::Slot::<#field_ty, #slot_id>::delete(self)
                        }

                        #[inline]
                        fn #setter_name(&mut self, value: #field_ty) -> crate::error::Result<()> {
                            crate::storage::Slot::<#field_ty, #slot_id>::write(self, value)
                        }
                    }
                }
            }
            // Otherwise (auto-assigned + static), generate code that uses packing helpers
            else {
                let field_name_upper = field_name.to_string().to_uppercase();
                let offset_const_name = format_ident!("{}_OFFSET", field_name_upper);
                let bytes_const_name = format_ident!("{}_BYTES", field_name_upper);

                quote! {
                    impl<'a, S: crate::storage::PrecompileStorageProvider> #struct_name<'a, S> {
                        #[inline]
                        fn #getter_name(&mut self) -> crate::error::Result<#field_ty> {
                            let slot_value = self.storage.sload(
                                self.address,
                                <#slot_id as crate::storage::SlotId>::SLOT
                            )?;
                            crate::storage::packing::extract_packed_value::<#field_ty>(
                                slot_value,
                                slots::#offset_const_name,
                                slots::#bytes_const_name
                            )
                        }

                        #[inline]
                        fn #cleaner_name(&mut self) -> crate::error::Result<()> {
                            // For packed fields, clear by inserting zero value
                            let slot = <#slot_id as crate::storage::SlotId>::SLOT;
                            let current = self.storage.sload(self.address, slot)?;
                            let zero_value: #field_ty = Default::default();
                            let cleared = crate::storage::packing::insert_packed_value(
                                current,
                                &zero_value,
                                slots::#offset_const_name,
                                slots::#bytes_const_name
                            )?;
                            self.storage.sstore(self.address, slot, cleared)
                        }

                        #[inline]
                        fn #setter_name(&mut self, value: #field_ty) -> crate::error::Result<()> {
                            let slot = <#slot_id as crate::storage::SlotId>::SLOT;
                            let current = self.storage.sload(self.address, slot)?;
                            let new_value = crate::storage::packing::insert_packed_value(
                                current,
                                &value,
                                slots::#offset_const_name,
                                slots::#bytes_const_name
                            )?;
                            self.storage.sstore(self.address, slot, new_value)
                        }
                    }
                }
            }
        }
        FieldKind::Mapping { key: key_ty, value: value_ty } => {
            quote! {
                impl<'a, S: crate::storage::PrecompileStorageProvider> #struct_name<'a, S> {
                    #[inline]
                    fn #getter_name(&mut self, key: #key_ty) -> crate::error::Result<#value_ty> {
                        crate::storage::Mapping::<#key_ty, #value_ty, #slot_id>::read(
                            self,
                            key,
                        )
                    }

                    #[inline]
                    fn #cleaner_name(&mut self, key: #key_ty) -> crate::error::Result<()> {
                        crate::storage::Mapping::<#key_ty, #value_ty, #slot_id>::delete(
                            self,
                            key,
                        )
                    }

                    #[inline]
                    fn #setter_name(&mut self, key: #key_ty, value: #value_ty) -> crate::error::Result<()> {
                        crate::storage::Mapping::<#key_ty, #value_ty, #slot_id>::write(
                            self,
                            key,
                            value,
                        )
                    }
                }
            }
        }
        FieldKind::NestedMapping { key1: key1_ty, key2: key2_ty, value: value_ty } => {
            quote! {
                impl<'a, S: crate::storage::PrecompileStorageProvider> #struct_name<'a, S> {
                    #[inline]
                    fn #getter_name(
                        &mut self,
                        key1: #key1_ty,
                        key2: #key2_ty,
                    ) -> crate::error::Result<#value_ty> {
                        crate::storage::Mapping::<#key1_ty, crate::storage::Mapping<#key2_ty, #value_ty, crate::storage::DummySlot>, #slot_id>::read_nested(
                            self,
                            key1,
                            key2,
                        )
                    }

                    #[inline]
                    fn #cleaner_name(
                        &mut self,
                        key1: #key1_ty,
                        key2: #key2_ty,
                    ) -> crate::error::Result<()> {
                        crate::storage::Mapping::<#key1_ty, crate::storage::Mapping<#key2_ty, #value_ty, crate::storage::DummySlot>, #slot_id>::delete_nested(
                            self,
                            key1,
                            key2,
                        )
                    }

                    #[inline]
                    fn #setter_name(
                        &mut self,
                        key1: #key1_ty,
                        key2: #key2_ty,
                        value: #value_ty,
                    ) -> crate::error::Result<()> {
                        crate::storage::Mapping::<#key1_ty, crate::storage::Mapping<#key2_ty, #value_ty, crate::storage::DummySlot>, #slot_id>::write_nested(
                            self,
                            key1,
                            key2,
                            value,
                        )
                    }
                }
            }
        }
        FieldKind::StorageBlock(ty) => {
            quote! {
                impl<'a, S: crate::storage::PrecompileStorageProvider> #struct_name<'a, S> {
                    #[inline]
                    fn #getter_name(&mut self) -> crate::error::Result<#ty> {
                        <#ty as crate::storage::Storable<{ <#ty>::SLOT_COUNT }>>::load(
                            self,
                            <#slot_id as crate::storage::SlotId>::SLOT,
                        )
                    }

                    #[inline]
                    fn #cleaner_name(&mut self) -> crate::error::Result<()> {
                        <#ty as crate::storage::Storable<{ <#ty>::SLOT_COUNT }>>::delete(
                            self,
                            <#slot_id as crate::storage::SlotId>::SLOT,
                        )
                    }

                    #[inline]
                    fn #setter_name(&mut self, value: #ty) -> crate::error::Result<()> {
                        value.store(
                            self,
                            <#slot_id as crate::storage::SlotId>::SLOT,
                        )
                    }
                }
            }
        }
    }
}

/// Convert a field name (snake_case) to a constant name (SCREAMING_SNAKE_CASE)
fn field_name_to_const_name(name: &Ident) -> String {
    name.to_string().to_uppercase()
}

/// Generate the `slots` module with SlotId types inside it, plus constants and re-exports
///
/// Returns: (re-exports for outer scope, slots module with types and packing constants inside)
pub(crate) fn gen_slots_module_with_types(
    allocated_fields: &[AllocatedField<'_>],
) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
    // Generate packing constants and `SlotId` types
    let packing_constants = gen_packing_constants_for_slots_module(allocated_fields);
    let slot_id_types = gen_slot_id_types(allocated_fields);
    let slot_constants: Vec<_> = allocated_fields
        .iter()
        .map(|allocated| {
            let const_name = format_ident!("{}", field_name_to_const_name(&allocated.info.name));
            let slot_id = format_ident!("{}", allocated.slot_id_name());

            quote! {
                pub const #const_name: ::alloy::primitives::U256 = <#slot_id as crate::storage::SlotId>::SLOT;
            }
        })
        .collect();

    // Generate offset and byte constants for each field (referencing packing constants in same
    // module)
    let offset_and_byte_constants: Vec<_> = allocated_fields
        .iter()
        .map(|allocated| {
            let field_name_upper = field_name_to_const_name(&allocated.info.name);
            let offset_const_name = format_ident!("{}_OFFSET", field_name_upper);
            let bytes_const_name = format_ident!("{}_BYTES", field_name_upper);
            let idx = allocated.field_index;
            let packing_offset = format_ident!("FIELD_{}_OFFSET", idx);
            let packing_bytes = format_ident!("FIELD_{}_BYTES", idx);

            quote! {
                pub const #offset_const_name: usize = #packing_offset;
                pub const #bytes_const_name: usize = #packing_bytes;
            }
        })
        .collect();

    // Generate re-exports for all SlotId types
    let slot_reexports: Vec<_> = allocated_fields
        .iter()
        .map(|allocated| {
            let slot_id = format_ident!("{}", allocated.slot_id_name());
            quote! {
                pub use slots::#slot_id;
            }
        })
        .collect();

    let slots_module = quote! {
        pub mod slots {
            use super::*;

            // Packing constants directly in this module (no separate packing module needed)
            #packing_constants

            #slot_id_types
            #(#slot_constants)*
            #(#offset_and_byte_constants)*
        }
    };

    let reexports = quote! {
        #(#slot_reexports)*
    };

    (reexports, slots_module)
}

/// Generate the three constant identifiers for a field: SLOT, OFFSET, and BYTES
fn field_constants(idx: usize) -> (Ident, Ident, Ident) {
    (
        format_ident!("FIELD_{}_SLOT", idx),
        format_ident!("FIELD_{}_OFFSET", idx),
        format_ident!("FIELD_{}_BYTES", idx),
    )
}

/// Generate packing constants that will be placed directly inside the slots module
fn gen_packing_constants_for_slots_module(
    allocated_fields: &[AllocatedField<'_>],
) -> proc_macro2::TokenStream {
    let mut constants = proc_macro2::TokenStream::new();

    // Generate byte count constants for each field
    for (idx, allocated) in allocated_fields.iter().enumerate() {
        let field_ty = &allocated.info.ty;
        let bytes_const = format_ident!("FIELD_{}_BYTES", idx);

        // Mappings and dynamic types always take a full slot (32 bytes) for their base
        let byte_count_expr = match &allocated.kind {
            FieldKind::Mapping { .. } | FieldKind::NestedMapping { .. } => quote! { 32 },
            _ if is_dynamic_type(field_ty) => quote! { 32 },
            _ => quote! { <#field_ty as crate::storage::StorableType>::BYTE_COUNT },
        };

        constants.extend(quote! {
            const #bytes_const: usize = #byte_count_expr;
        });
    }

    // Generate slot and offset constants for each field
    for (idx, allocated) in allocated_fields.iter().enumerate() {
        let (slot_const, offset_const, bytes_const) = field_constants(idx);

        let (slot_expr, offset_expr) = match &allocated.assigned_slot {
            SlotAssignment::Manual(manual_slot) => {
                // Manual slot assignment (from #[slot(N)] or #[base_slot(N)])
                // These fields always have offset 0 (no packing with manual slots)
                let hex_value = format!("{manual_slot}_U256");
                let slot_lit = syn::LitInt::new(&hex_value, proc_macro2::Span::call_site());
                let slot_expr = quote! {
                    ::alloy::primitives::uint!(#slot_lit)
                };
                (slot_expr, quote! { 0 })
            }
            SlotAssignment::Auto { base_slot, is_primitive: _ } => {
                // Auto-assignment with proper slot packing
                // Generate const expressions that compute slot/offset based on previous fields
                if idx == 0 {
                    // First field always starts at slot 0, offset 0
                    (quote! { ::alloy::primitives::U256::ZERO }, quote! { 0 })
                } else {
                    // Subsequent fields: compute based on previous field
                    let prev_idx = idx - 1;
                    let prev = &allocated_fields[prev_idx];
                    let (prev_slot, prev_offset, prev_bytes) = field_constants(prev_idx);

                    if !matches!(prev.assigned_slot, SlotAssignment::Auto { .. }) {
                        // Previous was manual, current is auto - they're independent
                        let limbs = *base_slot.as_limbs();
                        let slot_expr = quote! {
                            ::alloy::primitives::U256::from_limbs([#(#limbs),*])
                        };
                        (slot_expr, quote! { 0 })
                    } else {
                        // Previous was also auto - compute based on its slot/offset/bytes
                        if prev.kind.is_mapping() || is_dynamic_type(&prev.info.ty) {
                            // Previous field occupies exactly 1 full slot
                            let slot_expr = quote! {
                                #prev_slot.saturating_add(::alloy::primitives::U256::ONE)
                            };
                            (slot_expr, quote! { 0 })
                        } else if is_custom_struct(&prev.info.ty) {
                            // Previous field is a multi-slot struct
                            let prev_ty = &prev.info.ty;
                            let slot_expr = quote! {
                                #prev_slot.saturating_add(
                                    ::alloy::primitives::U256::from_limbs([<#prev_ty>::SLOT_COUNT as u64, 0u64, 0u64, 0u64])
                                )
                            };
                            (slot_expr, quote! { 0 })
                        } else if is_array_type(&prev.info.ty) {
                            // Previous field is an array, compute slot count from BYTE_COUNT
                            let slot_expr = quote! {
                                #prev_slot.saturating_add(
                                    ::alloy::primitives::U256::from_limbs([#prev_bytes.div_ceil(32) as u64, 0u64, 0u64, 0u64])
                                )
                            };
                            (slot_expr, quote! { 0 })
                        } else {
                            // Previous field is a primitive
                            if allocated.kind.is_mapping() ||
                                is_dynamic_type(&allocated.info.ty) ||
                                is_array_type(&allocated.info.ty) ||
                                is_custom_struct(&allocated.info.ty)
                            {
                                // Current is non-primitive: must start on next slot boundary
                                let slot_expr = quote! {
                                    #prev_slot.saturating_add(::alloy::primitives::U256::ONE)
                                };
                                (slot_expr, quote! { 0 })
                            } else {
                                // Both previous and current are primitives: try to pack
                                let slot_expr = quote! {
                                    {
                                        // Check if current field fits in same slot after previous
                                        if #prev_offset + #prev_bytes + #bytes_const <= 32 {
                                            #prev_slot
                                        } else {
                                            #prev_slot.saturating_add(::alloy::primitives::U256::ONE)
                                        }
                                    }
                                };

                                let offset_expr = quote! {
                                    {
                                        // Offset depends on whether we packed or moved to new slot
                                        if #prev_offset + #prev_bytes + #bytes_const <= 32 {
                                            #prev_offset + #prev_bytes
                                        } else {
                                            0
                                        }
                                    }
                                };

                                (slot_expr, offset_expr)
                            }
                        }
                    }
                }
            }
        };

        // Generate constants - all slots are now U256
        constants.extend(quote! {
            const #slot_const: ::alloy::primitives::U256 = #slot_expr;
            const #offset_const: usize = #offset_expr;
        });
    }

    constants
}

/// Generate `SlotId` marker types for each field (inline version without path prefixes)
fn gen_slot_id_types(allocated_fields: &[AllocatedField<'_>]) -> proc_macro2::TokenStream {
    let mut generated = proc_macro2::TokenStream::new();

    // Generate all `SlotId` types (one per field, even if they pack into the same slot)
    for allocated in allocated_fields.iter() {
        let slot_id_name = format_ident!("{}", allocated.slot_id_name());
        let field_name = &allocated.info.name;
        let field_idx = allocated.field_index;
        let packing_slot = format_ident!("FIELD_{}_SLOT", field_idx);

        // Each SlotId references its field's slot constant (computed with packing logic)
        let slot_expr = quote! { #packing_slot };

        generated.extend(quote! {
            #[doc = concat!("Storage slot for `", stringify!(#field_name), "` field")]
            pub struct #slot_id_name;

            impl crate::storage::SlotId for #slot_id_name {
                const SLOT: ::alloy::primitives::U256 = #slot_expr;
            }
        });
    }

    // Generate collision detection checks after all `SlotId` types are defined
    for (idx, allocated) in allocated_fields.iter().enumerate() {
        let collision_checks = generate_collision_checks(idx, allocated, allocated_fields);
        generated.extend(collision_checks);
    }

    generated
}

/// Generate a U256 expression for the number of slots occupied by a field
fn generate_slot_count_expr(kind: &FieldKind<'_>, ty: &Type) -> proc_macro2::TokenStream {
    match kind {
        FieldKind::StorageBlock(_) => {
            quote! { ::alloy::primitives::U256::from_limbs([<#ty>::SLOT_COUNT as u64, 0u64, 0u64, 0u64]) }
        }
        _ => {
            quote! { ::alloy::primitives::U256::ONE }
        }
    }
}

/// Generate collision detection debug assertions for a field
fn generate_collision_checks(
    current_idx: usize,
    current_field: &AllocatedField<'_>,
    all_fields: &[AllocatedField<'_>],
) -> proc_macro2::TokenStream {
    let mut checks = proc_macro2::TokenStream::new();

    // Only check explicit slot assignments against other fields
    if let SlotAssignment::Manual(_) = current_field.assigned_slot {
        let current_slot_id = format_ident!("{}", current_field.slot_id_name());
        let current_field_name = &current_field.info.name;

        // Check against all other fields
        for (other_idx, other_field) in all_fields.iter().enumerate() {
            if other_idx == current_idx {
                continue;
            }

            let other_slot_id = format_ident!("{}", other_field.slot_id_name());
            let other_field_name = &other_field.info.name;

            // Generate slot count expressions
            let current_count_expr =
                generate_slot_count_expr(&current_field.kind, &current_field.info.ty);
            let other_count_expr =
                generate_slot_count_expr(&other_field.kind, &other_field.info.ty);

            // Generate a debug assertion that checks for overlap
            checks.extend(quote! {
                #[allow(clippy::eq_op)]
                const _: () = {
                    let _ = || {
                        let current_slot = <#current_slot_id as crate::storage::SlotId>::SLOT;
                        let current_end = current_slot.saturating_add(#current_count_expr);
                        let other_slot = <#other_slot_id as crate::storage::SlotId>::SLOT;
                        let other_end = other_slot.saturating_add(#other_count_expr);

                        let no_overlap = current_end.le(&other_slot) || other_end.le(&current_slot);
                        debug_assert!(
                            no_overlap,
                            "Storage slot collision: field `{}` (slot {:?}) overlaps with field `{}` (slot {:?})",
                            stringify!(#current_field_name),
                            current_slot,
                            stringify!(#other_field_name),
                            other_slot
                        );
                    };
                };
            });
        }
    }

    checks
}
