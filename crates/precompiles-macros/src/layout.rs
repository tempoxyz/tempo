use crate::{
    FieldInfo, FieldKind,
    utils::{extract_mapping_types, is_array_type, is_custom_struct},
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
    /// The computed SlotId type name (e.g., "Slot0", "Slot100")
    slot_id_name: String,
}

/// Represents how a slot is assigned
#[derive(Debug, Clone)]
pub(crate) enum SlotAssignment {
    /// Manual slot value: `#[slot(N)]` or `#[base_slot(N)]`
    Manual(U256),
    /// Auto-assigned: stores after the latest auto-assigned field
    Auto(U256),
}

/// Get the `SlotId` name for a given field
fn get_field_slot_id_name(
    assigned_slot: &SlotAssignment,
    allocated_fields: &[AllocatedField<'_>],
) -> String {
    match assigned_slot {
        SlotAssignment::Manual(slot) => format!("Slot{}", slot),
        SlotAssignment::Auto(slot) => {
            // Check if follows a `StorageBlock` field by finding the last auto-assigned field
            let prev_auto_field = allocated_fields
                .iter()
                .rev()
                .find(|f| matches!(f.assigned_slot, SlotAssignment::Auto(_)));

            if let Some(prev) = prev_auto_field {
                if matches!(prev.kind, FieldKind::StorageBlock(_)) {
                    // the multi-slot block size is not yet known at macro expansion
                    return format!("SlotAfter{}", prev.slot_id_name);
                }
            }

            // Otherwise, we can use the exact slot number
            format!("Slot{}", slot)
        }
    }
}

/// Allocate slots to fields (explicit + auto-assignment)
pub(crate) fn allocate_slots(fields: &[FieldInfo]) -> syn::Result<Vec<AllocatedField<'_>>> {
    let mut allocated_fields = Vec::new();
    let mut last_auto_slot = U256::ZERO;
    let classified_fields: Vec<FieldKind<'_>> = fields
        .iter()
        .map(|field| classify_field(&field.ty))
        .collect::<syn::Result<_>>()?;

    for (field, kind) in fields.iter().zip(classified_fields.into_iter()) {
        let assigned_slot = if let Some(explicit) = field.slot {
            // Explicit fixed slot, doesn't affect auto-assignment chain
            SlotAssignment::Manual(explicit)
        } else if let Some(base) = field.base_slot {
            // Explicit base slot, resets auto-assignment chain
            let slot = SlotAssignment::Manual(base);
            last_auto_slot = base + U256::from(1);
            slot
        } else {
            // Auto-assignment: this field gets last_auto_slot
            let slot = SlotAssignment::Auto(last_auto_slot);
            last_auto_slot = last_auto_slot + U256::from(1);
            slot
        };

        let slot_id_name = get_field_slot_id_name(&assigned_slot, &allocated_fields);
        allocated_fields.push(AllocatedField {
            info: field,
            assigned_slot,
            kind,
            slot_id_name,
        });
    }

    Ok(allocated_fields)
}

/// Classify a field based on its type
fn classify_field(ty: &Type) -> syn::Result<FieldKind<'_>> {
    // Check if it's a mapping
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

    // If not a mapping, check if it's a multi-slot `Storable` type (custom struct or array)
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
            // call ctx values, reset with every new contract call
            msg_sender: ::alloy::primitives::Address,
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
                    msg_sender: ::alloy::primitives::Address::ZERO,
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
    let slot_id = format_ident!("{}", allocated.slot_id_name);

    match &allocated.kind {
        FieldKind::Direct => {
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
        FieldKind::Mapping {
            key: key_ty,
            value: value_ty,
        } => {
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
        FieldKind::NestedMapping {
            key1: key1_ty,
            key2: key2_ty,
            value: value_ty,
        } => {
            // For nested mappings, we need to use the full Mapping type with dummy inner slot
            let dummy_slot = quote! { SlotDummy };

            quote! {
                impl<'a, S: crate::storage::PrecompileStorageProvider> #struct_name<'a, S> {
                    #[inline]
                    fn #getter_name(
                        &mut self,
                        key1: #key1_ty,
                        key2: #key2_ty,
                    ) -> crate::error::Result<#value_ty> {
                        crate::storage::Mapping::<#key1_ty, crate::storage::Mapping<#key2_ty, #value_ty, #dummy_slot>, #slot_id>::read_nested(
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
                        crate::storage::Mapping::<#key1_ty, crate::storage::Mapping<#key2_ty, #value_ty, #dummy_slot>, #slot_id>::delete_nested(
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
                        crate::storage::Mapping::<#key1_ty, crate::storage::Mapping<#key2_ty, #value_ty, #dummy_slot>, #slot_id>::write_nested(
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
/// Returns: (re-exports for outer scope, slots module with types inside)
pub(crate) fn gen_slots_module_with_types(
    allocated_fields: &[AllocatedField<'_>],
) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
    let slot_id_types = gen_slot_id_types(allocated_fields);

    let slot_constants: Vec<_> = allocated_fields
        .iter()
        .map(|allocated| {
            let const_name = format_ident!("{}", field_name_to_const_name(&allocated.info.name));
            let slot_id = format_ident!("{}", allocated.slot_id_name);

            quote! {
                pub const #const_name: ::alloy::primitives::U256 = <#slot_id as tempo_precompiles::storage::SlotId>::SLOT;
            }
        })
        .collect();

    let slot_reexports: Vec<_> = allocated_fields
        .iter()
        .map(|allocated| {
            let slot_id = format_ident!("{}", allocated.slot_id_name);
            quote! {
                pub use slots::#slot_id;
            }
        })
        .collect();

    let slots_module = quote! {
        pub mod slots {
            use super::*;
            #slot_id_types
            #(#slot_constants)*
        }
    };

    let reexports = quote! {
        #(#slot_reexports)*
        pub use slots::SlotDummy;
    };

    (reexports, slots_module)
}

/// Generate `SlotId` marker types for each field with const-eval chaining
pub(crate) fn gen_slot_id_types(
    allocated_fields: &[AllocatedField<'_>],
) -> proc_macro2::TokenStream {
    let mut generated = proc_macro2::TokenStream::new();

    // Generate all `SlotId` types
    for (idx, allocated) in allocated_fields.iter().enumerate() {
        let slot_id_name = format_ident!("{}", allocated.slot_id_name);
        let field_name = &allocated.info.name;

        let slot_expr = match &allocated.assigned_slot {
            SlotAssignment::Manual(slot_value) => {
                // Fixed slots are always known exactly
                let slot_literal = syn::LitInt::new(
                    &format!("{}_U256", slot_value),
                    proc_macro2::Span::call_site(),
                );
                quote! {
                    ::alloy::primitives::uint!(#slot_literal)
                }
            }
            SlotAssignment::Auto(slot_value) => {
                // For auto slots, check if previous auto field is a StorageBlock
                let prev_auto_field = allocated_fields[..idx]
                    .iter()
                    .rev()
                    .find(|f| matches!(f.assigned_slot, SlotAssignment::Auto(_)));

                let prev_is_storage_block = prev_auto_field
                    .map(|f| matches!(f.kind, FieldKind::StorageBlock(_)))
                    .unwrap_or(false);

                if prev_is_storage_block {
                    // Previous auto field is StorageBlock, defer to const-eval
                    let prev = prev_auto_field.unwrap();
                    let prev_slot_id = format_ident!("{}", prev.slot_id_name);
                    let prev_field_ty = &prev.info.ty;
                    quote! {
                        {
                            const PREV_SLOT: ::alloy::primitives::U256 = <#prev_slot_id as crate::storage::SlotId>::SLOT;
                            const PREV_COUNT: usize = <#prev_field_ty>::SLOT_COUNT;
                            const OFFSET: ::alloy::primitives::U256 = ::alloy::primitives::U256::from_limbs([PREV_COUNT as u64, 0, 0, 0]);
                            PREV_SLOT.saturating_add(OFFSET)
                        }
                    }
                } else {
                    // Use exact slot value (known at macro time)
                    let slot_literal = syn::LitInt::new(
                        &format!("{}_U256", slot_value),
                        proc_macro2::Span::call_site(),
                    );
                    quote! {
                        ::alloy::primitives::uint!(#slot_literal)
                    }
                }
            }
        };

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

    // Always generate `SlotDummy` for nested mappings
    generated.extend(quote! {
        #[doc = "Dummy slot ID for nested mapping inner types (never accessed at runtime)"]
        pub struct SlotDummy;

        impl crate::storage::SlotId for SlotDummy {
            const SLOT: ::alloy::primitives::U256 = ::alloy::primitives::U256::ZERO;
        }
    });

    generated
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
        let current_slot_id = format_ident!("{}", current_field.slot_id_name);
        let current_field_name = &current_field.info.name;

        // Check against all other fields
        for (other_idx, other_field) in all_fields.iter().enumerate() {
            if other_idx == current_idx {
                continue;
            }

            let other_slot_id = format_ident!("{}", other_field.slot_id_name);
            let other_field_name = &other_field.info.name;

            // Generate slot count expressions
            let (current_count_expr, other_count_expr) = match (
                &current_field.kind,
                &other_field.kind,
            ) {
                (FieldKind::StorageBlock(_), FieldKind::StorageBlock(_)) => {
                    let current_ty = &current_field.info.ty;
                    let other_ty = &other_field.info.ty;
                    (
                        quote! { ::alloy::primitives::U256::from_limbs([<#current_ty>::SLOT_COUNT as u64, 0, 0, 0]) },
                        quote! { ::alloy::primitives::U256::from_limbs([<#other_ty>::SLOT_COUNT as u64, 0, 0, 0]) },
                    )
                }
                (FieldKind::StorageBlock(_), _) => {
                    let current_ty = &current_field.info.ty;
                    (
                        quote! { ::alloy::primitives::U256::from_limbs([<#current_ty>::SLOT_COUNT as u64, 0, 0, 0]) },
                        quote! { ::alloy::primitives::U256::from_limbs([1, 0, 0, 0]) },
                    )
                }
                (_, FieldKind::StorageBlock(_)) => {
                    let other_ty = &other_field.info.ty;
                    (
                        quote! { ::alloy::primitives::U256::from_limbs([1, 0, 0, 0]) },
                        quote! { ::alloy::primitives::U256::from_limbs([<#other_ty>::SLOT_COUNT as u64, 0, 0, 0]) },
                    )
                }
                _ => (
                    quote! { ::alloy::primitives::U256::from_limbs([1, 0, 0, 0]) },
                    quote! { ::alloy::primitives::U256::from_limbs([1, 0, 0, 0]) },
                ),
            };

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
