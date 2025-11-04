use crate::{
    FieldInfo, FieldKind,
    utils::{extract_mapping_types, is_custom_struct},
};
use alloy::primitives::U256;
use quote::{format_ident, quote};
use syn::{Ident, Type, Visibility};

/// A field with its allocated slot and classification
#[derive(Debug)]
pub(crate) struct AllocatedField<'a> {
    /// Reference to the original field information
    info: &'a FieldInfo,
    /// The assigned storage slot for this field
    assigned_slot: U256,
    /// Classification based on the field's type
    kind: FieldKind<'a>,
}

/// Allocate slots to fields (explicit + auto-assignment)
pub(crate) fn allocate_slots(fields: &[FieldInfo]) -> syn::Result<Vec<AllocatedField<'_>>> {
    let (mut used, mut next) = (std::collections::HashSet::new(), U256::ZERO);

    // First pass: classify fields, collect custom slots, and validate no duplicates
    let mut classified_fields: Vec<(FieldKind<'_>, usize)> = Vec::new();
    for field in fields.iter() {
        let kind = classify_field(&field.ty)?;

        // Determine how many slots this field occupies
        let slot_count = match &kind {
            FieldKind::StorageBlock(_) => {
                field.slot_count.ok_or_else(|| {
                    syn::Error::new_spanned(
                        &field.name,
                        "custom structs fields that derive `Storable` require `#[slot_count(N)]` attribute to specify how many slots they need",
                    )
                })?
            }
            _ => 1, // `Direct`, `Mapping`, and `NestedMapping` all use 1 slot for the base (no slot collision)
        };

        classified_fields.push((kind, slot_count));

        // Validate explicit slot assignments and reserve all slots
        if let Some(slot) = field.slot {
            for i in 0..slot_count {
                let slot_i = slot.saturating_add(U256::from(i));
                if !used.insert(slot_i) {
                    return Err(syn::Error::new_spanned(
                        &field.name,
                        format!("duplicate slot assignment: slot `{slot_i}` is already used"),
                    ));
                }
            }
        }
        if let Some(base_slot) = field.base_slot {
            for i in 0..slot_count {
                let slot_i = base_slot.saturating_add(U256::from(i));
                if !used.insert(slot_i) {
                    return Err(syn::Error::new_spanned(
                        &field.name,
                        format!("duplicate slot assignment: slot `{slot_i}` is already used"),
                    ));
                }
            }
        }
    }

    // Second pass: allocate slots for auto-assigned fields
    fields
        .iter()
        .zip(classified_fields)
        .map(|(field, (kind, slot_count))| {
            let assigned_slot = if let Some(explicit) = field.slot {
                // #[slot(N)] assigns to slot N without changing next counter
                explicit
            } else if let Some(base) = field.base_slot {
                // #[base_slot(N)] assigns to slot N and resets next counter to N+slot_count
                next = base.saturating_add(U256::from(slot_count));
                base
            } else {
                // Auto-assign from current next counter, ensuring slot_count consecutive slots are available
                loop {
                    let mut all_available = true;
                    for i in 0..slot_count {
                        if used.contains(&next.saturating_add(U256::from(i))) {
                            all_available = false;
                            break;
                        }
                    }
                    if all_available {
                        break;
                    }
                    next = next.saturating_add(U256::from(1));
                }

                let slot = next;
                // Mark all slots as used
                for i in 0..slot_count {
                    used.insert(slot.saturating_add(U256::from(i)));
                }
                next = next.saturating_add(U256::from(slot_count));
                slot
            };

            Ok(AllocatedField {
                info: field,
                assigned_slot,
                kind,
            })
        })
        .collect()
}

/// Classify a field based on its type
fn classify_field(ty: &Type) -> syn::Result<FieldKind<'_>> {
    // First check if it's a Mapping type
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

    // If not a mapping, check if it's a multi-slot `Storable` type (user-defined struct).
    if is_custom_struct(ty) {
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

    match &allocated.kind {
        FieldKind::Direct => {
            let slot_id = slot_to_marker_type(allocated.assigned_slot);

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
            let slot_id = slot_to_marker_type(allocated.assigned_slot);

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
            let slot_id = slot_to_marker_type(allocated.assigned_slot);
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
            let slot_id = slot_to_marker_type(allocated.assigned_slot);
            // Get the slot_count from the attribute (guaranteed to exist by allocate_slots)
            let expected_slot_count = allocated
                .info
                .slot_count
                .expect("custom structs fields must impl `trait Storable`");

            // Generate a unique const name for the validation
            let validation_const = format_ident!(
                "_VALIDATE_SLOT_COUNT_{}",
                field_name.to_string().to_uppercase()
            );

            quote! {
                impl<'a, S: crate::storage::PrecompileStorageProvider> #struct_name<'a, S> {
                    // Compile-time validation: ensure slot_count attribute matches Storable::SLOT_COUNT
                    const #validation_const: () = {
                        const EXPECTED: usize = #expected_slot_count;
                        const ACTUAL: usize = <#ty>::SLOT_COUNT;

                        // This will fail at compile time if they don't match
                        if EXPECTED != ACTUAL {
                            panic!(
                                concat!(
                                    "`slot_count` mismatch for field `",
                                    stringify!(#field_name),
                                    "`: attribute specifies `",
                                    stringify!(#expected_slot_count),
                                    "` but type implements a different `SLOT_COUNT`"
                                )
                            );
                        }
                    };

                    #[inline]
                    fn #getter_name(&mut self) -> crate::error::Result<#ty> {
                        // Reference the validation const to ensure it's evaluated
                        let _ = Self::#validation_const;

                        <#ty as crate::storage::Storable<{ <#ty>::SLOT_COUNT }>>::load(
                            self,
                            <#slot_id as crate::storage::SlotId>::SLOT,
                        )
                    }

                    #[inline]
                    fn #cleaner_name(&mut self) -> crate::error::Result<()> {
                        // Reference the validation const to ensure it's evaluated
                        let _ = Self::#validation_const;

                        <#ty as crate::storage::Storable<{ <#ty>::SLOT_COUNT }>>::delete(
                            self,
                            <#slot_id as crate::storage::SlotId>::SLOT,
                        )
                    }

                    #[inline]
                    fn #setter_name(&mut self, value: #ty) -> crate::error::Result<()> {
                        // Reference the validation const to ensure it's evaluated
                        let _ = Self::#validation_const;

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

/// Convert a slot number to a marker type identifier
fn slot_to_marker_type(slot: U256) -> Ident {
    format_ident!("Slot{}", slot.to_string())
}

/// Convert a field name (snake_case) to a constant name (SCREAMING_SNAKE_CASE)
fn field_name_to_const_name(name: &Ident) -> String {
    name.to_string().to_uppercase()
}

/// Generate the `slots` module with constants for each field's storage slot
pub(crate) fn gen_slots_module(
    allocated_fields: &[AllocatedField<'_>],
) -> proc_macro2::TokenStream {
    let slot_constants: Vec<proc_macro2::TokenStream> = allocated_fields
        .iter()
        .map(|allocated| {
            let slot = allocated.assigned_slot;

            // Generate constant name in SCREAMING_SNAKE_CASE
            let const_name = format_ident!("{}", field_name_to_const_name(&allocated.info.name));

            // Create a literal token for the slot value with _U256 suffix
            let slot_literal = syn::LitInt::new(
                &format!("{slot}_U256"),
                proc_macro2::Span::call_site(),
            );

            quote! {
                pub const #const_name: ::alloy::primitives::U256 = ::alloy::primitives::uint!(#slot_literal);
            }
        })
        .collect();

    quote! {
        pub mod slots {
            #(#slot_constants)*
        }
    }
}

/// Generate `SlotId` marker types for each unique storage slot
pub(crate) fn gen_slot_id_types(
    allocated_fields: &[AllocatedField<'_>],
) -> proc_macro2::TokenStream {
    let mut generated = proc_macro2::TokenStream::new();
    let mut seen_slots = std::collections::HashSet::new();

    // Generate a `SlotN` type for each unique slot number
    for allocated in allocated_fields {
        let slot_number = allocated.assigned_slot;

        // Only generate once per unique slot number (multiple fields may share a slot)
        if seen_slots.insert(slot_number) {
            let slot_id_name = slot_to_marker_type(slot_number);
            let field_name = &allocated.info.name;
            let slot_number_str = slot_number.to_string();

            // Create a literal token for the slot value with _U256 suffix
            let slot_literal = syn::LitInt::new(
                &format!("{slot_number}_U256"),
                proc_macro2::Span::call_site(),
            );

            generated.extend(quote! {
                #[doc = concat!(
                    "Storage slot ", #slot_number_str,
                    " (used by `", stringify!(#field_name), "` field)"
                )]
                pub struct #slot_id_name;

                impl crate::storage::SlotId for #slot_id_name {
                    const SLOT: ::alloy::primitives::U256 = ::alloy::primitives::uint!(#slot_literal);
                }
            });
        }
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
