use crate::{FieldInfo, FieldKind, utils::extract_mapping_types};
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

    // First pass: collect custom slots and validate no duplicates
    for field in fields.iter() {
        if let Some(slot) = field.slot
            && !used.insert(slot)
        {
            return Err(syn::Error::new_spanned(
                &field.name,
                format!("Duplicate slot assignment: slot {slot} is already used"),
            ));
        }
    }

    // Second pass: allocate slots and classify fields
    fields
        .iter()
        .map(|field| {
            let assigned_slot = if let Some(explicit) = field.slot {
                explicit
            } else {
                while used.contains(&next) {
                    next = next.saturating_add(U256::from(1));
                }
                let slot = next;
                used.insert(slot);
                next = next.saturating_add(U256::from(1));
                slot
            };
            let kind = classify_field(&field.ty)?;
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
    if let Some((key_ty, value_ty)) = extract_mapping_types(ty) {
        if let Some((key2_ty, value2_ty)) = extract_mapping_types(value_ty) {
            Ok(FieldKind::NestedMapping {
                key1: key_ty,
                key2: key2_ty,
                value: value2_ty,
            })
        } else {
            Ok(FieldKind::Mapping {
                key: key_ty,
                value: value_ty,
            })
        }
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

    let getter_name = format_ident!("_get_{}", field_name);
    let setter_name = format_ident!("_set_{}", field_name);

    match &allocated.kind {
        FieldKind::Direct => {
            let slot_limbs = slot_to_limbs(allocated.assigned_slot);

            quote! {
                impl<'a, S: crate::storage::PrecompileStorageProvider> #struct_name<'a, S> {
                    #[inline]
                    fn #getter_name(&mut self) -> crate::error::Result<#field_ty> {
                        crate::storage::Slot::<#field_ty, {#slot_limbs}>::read(self)
                    }

                    #[inline]
                    fn #setter_name(&mut self, value: #field_ty) -> crate::error::Result<()> {
                        crate::storage::Slot::<#field_ty, {#slot_limbs}>::write(self, value)
                    }
                }
            }
        }
        FieldKind::Mapping {
            key: key_ty,
            value: value_ty,
        } => {
            let slot_limbs = slot_to_limbs(allocated.assigned_slot);

            quote! {
                impl<'a, S: crate::storage::PrecompileStorageProvider> #struct_name<'a, S> {
                    #[inline]
                    fn #getter_name(&mut self, key: #key_ty) -> crate::error::Result<#value_ty> {
                        crate::storage::Mapping::<#key_ty, #value_ty, {#slot_limbs}>::read(
                            self,
                            key,
                        )
                    }

                    #[inline]
                    fn #setter_name(&mut self, key: #key_ty, value: #value_ty) -> crate::error::Result<()> {
                        crate::storage::Mapping::<#key_ty, #value_ty, {#slot_limbs}>::write(
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
            let slot_limbs = slot_to_limbs(allocated.assigned_slot);
            // For nested mappings, we need to use the full Mapping type with dummy inner slot
            let dummy_slot = quote! { [0, 0, 0, 0] };

            quote! {
                impl<'a, S: crate::storage::PrecompileStorageProvider> #struct_name<'a, S> {
                    #[inline]
                    fn #getter_name(
                        &mut self,
                        key1: #key1_ty,
                        key2: #key2_ty,
                    ) -> crate::error::Result<#value_ty> {
                        crate::storage::Mapping::<#key1_ty, crate::storage::Mapping<#key2_ty, #value_ty, {#dummy_slot}>, {#slot_limbs}>::read_nested(
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
                        crate::storage::Mapping::<#key1_ty, crate::storage::Mapping<#key2_ty, #value_ty, {#dummy_slot}>, {#slot_limbs}>::write_nested(
                            self,
                            key1,
                            key2,
                            value,
                        )
                    }
                }
            }
        }
    }
}

/// Convert a slot number to [u64; 4] limbs representation
fn slot_to_limbs(slot: U256) -> proc_macro2::TokenStream {
    let limbs = slot.as_limbs();
    let [l0, l1, l2, l3] = limbs;
    quote! { [#l0, #l1, #l2, #l3] }
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
