use crate::{
    FieldKind,
    packing::{self, LayoutField, PackingConstants, SlotAssignment},
};
use quote::{format_ident, quote};
use syn::{Ident, Visibility};

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

    let consts = PackingConstants::new(field_name);
    let slot_const = consts.slot();
    let offset_const = consts.offset();

    match &allocated.kind {
        FieldKind::Slot(ty) => {
            // Generate `LayoutCtx` expression using shared helper
            let prev_slot_const_ref = prev_field.map(|prev| {
                let prev_slot = PackingConstants::new(prev.name).slot();
                quote! { slots::#prev_slot }
            });

            let next_slot_const_ref = next_field.map(|next| {
                let next_slot = PackingConstants::new(next.name).slot();
                quote! { slots::#next_slot }
            });

            let layout_ctx = packing::gen_layout_ctx_expr_inefficient(
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
                            self, slots::#slot_const, #layout_ctx
                        )
                    }

                    #[inline]
                    fn #cleaner_name(&mut self) -> crate::error::Result<()> {
                        <#ty as crate::storage::Storable<{ <#ty as crate::storage::StorableType>::SLOTS }>>::delete(
                            self, slots::#slot_const, #layout_ctx
                        )
                    }

                    #[inline]
                    fn #setter_name(&mut self, value: #ty) -> crate::error::Result<()> {
                        <#ty as crate::storage::Storable<{ <#ty as crate::storage::StorableType>::SLOTS }>>::store(
                            &value, self, slots::#slot_const, #layout_ctx
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
                        crate::storage::Mapping::<#key_ty, #value_ty>::new(slots::#slot_const).at(key).read(self)
                    }

                    #[inline]
                    fn #cleaner_name(&mut self, key: #key_ty) -> crate::error::Result<()> {
                        crate::storage::Mapping::<#key_ty, #value_ty>::new(slots::#slot_const).at(key).delete(self)
                    }

                    #[inline]
                    fn #setter_name(&mut self, key: #key_ty, value: #value_ty) -> crate::error::Result<()> {
                        crate::storage::Mapping::<#key_ty, #value_ty>::new(slots::#slot_const).at(key).write(self, value)
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
                        crate::storage::NestedMapping::<#key1_ty, #key2_ty, #value_ty>::new(slots::#slot_const).at(key1).at(key2).read(self)
                    }

                    #[inline]
                    fn #cleaner_name(&mut self, key1: #key1_ty, key2: #key2_ty) -> crate::error::Result<()> {
                        crate::storage::NestedMapping::<#key1_ty, #key2_ty, #value_ty>::new(slots::#slot_const).at(key1).at(key2).delete(self)
                    }

                    #[inline]
                    fn #setter_name(&mut self, key1: #key1_ty, key2: #key2_ty, value: #value_ty) -> crate::error::Result<()> {
                        crate::storage::NestedMapping::<#key1_ty, #key2_ty, #value_ty>::new(slots::#slot_const).at(key1).at(key2).write(self, value)
                    }
                }
            }
        }
    }
}

/// Generate the `slots` module with constants and collision checks
///
/// Returns the slots module containing only constants and collision detection functions
pub(crate) fn gen_slots_module(allocated_fields: &[LayoutField<'_>]) -> proc_macro2::TokenStream {
    // Generate constants and collision check functions
    let constants = packing::gen_constants_from_ir(allocated_fields, false);
    let collision_checks = gen_collision_checks(allocated_fields);

    quote! {
        pub mod slots {
            use super::*;

            #constants
            #collision_checks
        }
    }
}

/// Generate collision check functions for all fields
fn gen_collision_checks(allocated_fields: &[LayoutField<'_>]) -> proc_macro2::TokenStream {
    let mut generated = proc_macro2::TokenStream::new();
    let mut check_fn_calls = Vec::new();

    // Generate collision detection check functions
    for (idx, allocated) in allocated_fields.iter().enumerate() {
        if let Some((check_fn_name, check_fn)) =
            packing::gen_collision_check_fn(idx, allocated, allocated_fields)
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
