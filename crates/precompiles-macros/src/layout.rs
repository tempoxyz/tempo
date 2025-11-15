use crate::{
    FieldKind,
    packing::{self, LayoutField, PackingConstants, SlotAssignment},
    utils,
};
use quote::{format_ident, quote};
use syn::{Ident, Visibility};

/// Returns the `SlotId` type name for a field
fn slot_id_name(field_name: &Ident) -> String {
    format!("{}Slot", utils::to_pascal_case(&field_name.to_string()))
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
                // Run collision detection checks in debug builds
                #[cfg(debug_assertions)]
                {
                    slots::__check_all_collisions();
                }

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
    allocated: &LayoutField<'_>,
    prev_field: Option<&LayoutField<'_>>,
    next_field: Option<&LayoutField<'_>>,
) -> proc_macro2::TokenStream {
    let field_name = allocated.name;

    let getter_name = format_ident!("sload_{}", field_name);
    let setter_name = format_ident!("sstore_{}", field_name);
    let cleaner_name = format_ident!("clear_{}", field_name);
    let slot_id = format_ident!("{}", slot_id_name(field_name));

    match &allocated.kind {
        FieldKind::Slot(ty) => {
            // Generate `LayoutCtx` expression using shared helper
            let consts = PackingConstants::new(field_name);
            let slot_const = consts.slot();
            let offset_const = consts.offset();

            let prev_slot_const_ref = prev_field.map(|prev| {
                let prev_slot = PackingConstants::new(prev.name).slot();
                quote! { slots::#prev_slot }
            });

            let next_slot_const_ref = next_field.map(|next| {
                let next_slot = PackingConstants::new(next.name).slot();
                quote! { slots::#next_slot }
            });

            let layout_ctx = packing::gen_layout_ctx_expr(
                allocated.ty,
                matches!(allocated.assigned_slot, SlotAssignment::Manual(_)),
                quote! { slots::#slot_const },
                quote! { slots::#offset_const },
                prev_slot_const_ref,
                next_slot_const_ref,
            );

            quote! {
                impl<'a, S: crate::storage::PrecompileStorageProvider> #struct_name<'a, S> {
                    #[inline]
                    fn #getter_name(&mut self) -> crate::error::Result<#ty> {
                        <#ty as crate::storage::Storable<{ <#ty as crate::storage::StorableType>::SLOTS }>>::load(
                            self, <#slot_id as crate::storage::SlotId>::SLOT, #layout_ctx
                        )
                    }

                    #[inline]
                    fn #cleaner_name(&mut self) -> crate::error::Result<()> {
                        <#ty as crate::storage::Storable<{ <#ty as crate::storage::StorableType>::SLOTS }>>::delete(
                            self, <#slot_id as crate::storage::SlotId>::SLOT, #layout_ctx
                        )
                    }

                    #[inline]
                    fn #setter_name(&mut self, value: #ty) -> crate::error::Result<()> {
                        <#ty as crate::storage::Storable<{ <#ty as crate::storage::StorableType>::SLOTS }>>::store(
                            &value, self, <#slot_id as crate::storage::SlotId>::SLOT, #layout_ctx
                        )
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
                            self, key,
                        )
                    }

                    #[inline]
                    fn #cleaner_name(&mut self, key: #key_ty) -> crate::error::Result<()> {
                        crate::storage::Mapping::<#key_ty, #value_ty, #slot_id>::delete(
                            self, key,
                        )
                    }

                    #[inline]
                    fn #setter_name(&mut self, key: #key_ty, value: #value_ty) -> crate::error::Result<()> {
                        crate::storage::Mapping::<#key_ty, #value_ty, #slot_id>::write(
                            self, key, value,
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
            quote! {
                impl<'a, S: crate::storage::PrecompileStorageProvider> #struct_name<'a, S> {
                    #[inline]
                    fn #getter_name(&mut self, key1: #key1_ty, key2: #key2_ty) -> crate::error::Result<#value_ty> {
                        crate::storage::Mapping::<#key1_ty, crate::storage::Mapping<#key2_ty, #value_ty, crate::storage::DummySlot>, #slot_id>::read_nested(
                            self, key1, key2,
                        )
                    }

                    #[inline]
                    fn #cleaner_name(&mut self, key1: #key1_ty, key2: #key2_ty) -> crate::error::Result<()> {
                        crate::storage::Mapping::<#key1_ty, crate::storage::Mapping<#key2_ty, #value_ty, crate::storage::DummySlot>, #slot_id>::delete_nested(
                            self, key1, key2,
                        )
                    }

                    #[inline]
                    fn #setter_name(&mut self, key1: #key1_ty, key2: #key2_ty, value: #value_ty) -> crate::error::Result<()> {
                        crate::storage::Mapping::<#key1_ty, crate::storage::Mapping<#key2_ty, #value_ty, crate::storage::DummySlot>, #slot_id>::write_nested(
                            self, key1, key2, value,
                        )
                    }
                }
            }
        }
    }
}

/// Generate the `slots` module with SlotId types inside it, plus constants and re-exports
///
/// Returns: (re-exports for outer scope, slots module with types and packing constants inside)
pub(crate) fn gen_slots_module_with_types(
    allocated_fields: &[LayoutField<'_>],
) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
    // Generate constants and `SlotId` types that reference them.
    let constants = packing::gen_constants_from_ir(allocated_fields);
    let slot_id_types = gen_slot_id_types(allocated_fields);
    let slots_module = quote! {
        pub mod slots {
            use super::*;

            #constants
            #slot_id_types
        }
    };

    // Generate re-exports for all `SlotId` types
    let slot_reexports: Vec<_> = allocated_fields
        .iter()
        .map(|allocated| {
            let slot_id = format_ident!("{}", slot_id_name(allocated.name));
            quote! {
                pub use slots::#slot_id;
            }
        })
        .collect();

    let reexports = quote! {
        #(#slot_reexports)*
    };

    (reexports, slots_module)
}

/// Generate `SlotId` marker types for each field (inline version without path prefixes)
fn gen_slot_id_types(allocated_fields: &[LayoutField<'_>]) -> proc_macro2::TokenStream {
    let mut generated = proc_macro2::TokenStream::new();
    let mut check_fn_calls = Vec::new();

    // Generate all `SlotId` types (one per field, even if they pack into the same slot)
    for allocated in allocated_fields.iter() {
        let slot_id_type = packing::gen_slot_id_type(
            &slot_id_name(allocated.name),
            allocated.name,
            &PackingConstants::new(allocated.name).slot().to_string(),
        );
        generated.extend(slot_id_type);
    }

    // Generate collision detection check functions after all `SlotId` types are defined
    for (idx, allocated) in allocated_fields.iter().enumerate() {
        if let Some((check_fn_name, check_fn)) =
            packing::gen_collision_check_fn(idx, allocated, allocated_fields, slot_id_name)
        {
            generated.extend(check_fn);
            check_fn_calls.push(check_fn_name);
        }
    }

    // Generate a module initializer that calls all check functions
    // Always generate the function, even if empty, so the constructor can call it
    generated.extend(quote! {
        #[cfg(debug_assertions)]
        #[inline(always)]
        pub(super) fn __check_all_collisions() {
            #(#check_fn_calls();)*
        }
    });

    generated
}
