//! Implementation of the `#[derive(Storable)]` macro.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, Ident, Type};

use crate::{
    FieldInfo,
    packing::{self, LayoutField, PackingConstants},
    storable_primitives::gen_struct_arrays,
    utils::{extract_mapping_types, extract_storable_array_sizes, to_snake_case},
};

/// Implements the `Storable` derive macro for structs.
///
/// Packs fields into storage slots based on their byte sizes.
/// Fields are placed sequentially in slots, moving to a new slot when
/// the current slot cannot fit the next field (no spanning across slots).
pub(crate) fn derive_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    // Extract struct name, generics
    let strukt = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Parse struct fields
    let fields = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields_named) => &fields_named.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    &input.ident,
                    "`Storable` can only be derived for structs with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "`Storable` can only be derived for structs",
            ));
        }
    };

    if fields.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`Storable` cannot be derived for empty structs",
        ));
    }

    // Extract field names and types into `FieldInfo` structs
    let field_infos: Vec<_> = fields
        .iter()
        .map(|f| FieldInfo {
            name: f.ident.as_ref().unwrap().clone(),
            ty: f.ty.clone(),
            slot: None,
            base_slot: None,
        })
        .collect();

    // Build layout IR using the unified function
    let layout_fields = packing::allocate_slots(&field_infos)?;

    // Generate helper module with packing layout calculations
    let mod_ident = format_ident!("__packing_{}", to_snake_case(&strukt.to_string()));
    let packing_module = gen_packing_module_from_ir(&layout_fields, &mod_ident);

    // Classify fields to figure out which impl `Storable`
    let len = fields.len();
    let (direct_fields, direct_names, mapping_names) = field_infos.iter().fold(
        (Vec::with_capacity(len), Vec::with_capacity(len), Vec::new()),
        |mut out, field_info| {
            if extract_mapping_types(&field_info.ty).is_none() {
                // fields with direct slot allocation
                out.0.push((&field_info.name, &field_info.ty));
                out.1.push(&field_info.name);
            } else {
                // fields with indirect slot allocation (mappings)
                out.2.push(&field_info.name);
            }
            out
        },
    );

    // Generate load/store implementations for scalar fields only
    let load_impl = gen_storage_op_impl(&direct_fields, &mod_ident, true);
    let store_impl = gen_storage_op_impl(&direct_fields, &mod_ident, false);
    let to_evm_words_impl = gen_to_evm_words_impl(&direct_fields, &mod_ident);
    let from_evm_words_impl = gen_from_evm_words_impl(&direct_fields, &mod_ident);

    let expanded = quote! {
        #packing_module

        // impl `StorableType` for layout information
        impl #impl_generics crate::storage::StorableType for #strukt #ty_generics #where_clause {
            // Structs cannot be packed, so they must take full slots
            const LAYOUT: crate::storage::Layout = crate::storage::Layout::Slots(#mod_ident::SLOT_COUNT);
        }

        // `Storable` implementation: loads/stores only directly accessible fields, skips mappings
        impl #impl_generics crate::storage::Storable<{ #mod_ident::SLOT_COUNT }> for #strukt #ty_generics #where_clause {
            fn load<S: crate::storage::StorageOps>(
                storage: &mut S, base_slot: ::alloy::primitives::U256, ctx: crate::storage::LayoutCtx
            ) -> crate::error::Result<Self> {
                use crate::storage::Storable;
                debug_assert_eq!(ctx, crate::storage::LayoutCtx::FULL, "Struct types can only be loaded with LayoutCtx::FULL");

                #load_impl

                Ok(Self {
                    #(#direct_names),*,
                    #(#mapping_names: Default::default()),*
                })
            }

            fn store<S: crate::storage::StorageOps>(
                &self, storage: &mut S, base_slot: ::alloy::primitives::U256, ctx: crate::storage::LayoutCtx
            ) -> crate::error::Result<()> {
                use crate::storage::Storable;
                debug_assert_eq!(ctx, crate::storage::LayoutCtx::FULL, "Struct types can only be stored with LayoutCtx::FULL");

                #store_impl

                Ok(())
            }

            fn to_evm_words(&self) -> crate::error::Result<[::alloy::primitives::U256; { #mod_ident::SLOT_COUNT }]> {
                use crate::storage::Storable;

                #to_evm_words_impl
            }

            fn from_evm_words(words: [::alloy::primitives::U256; { #mod_ident::SLOT_COUNT }]) -> crate::error::Result<Self> {
                use crate::storage::Storable;

                #from_evm_words_impl

                Ok(Self {
                    #(#direct_names),*,
                    #(#mapping_names: Default::default()),*
                })
            }
        }
    };

    // Generate array implementations if requested
    let array_impls = if let Some(sizes) = extract_storable_array_sizes(&input.attrs)? {
        // Generate the struct type path for array generation
        let struct_type = quote! { #strukt #ty_generics };
        gen_struct_arrays(struct_type, &sizes)
    } else {
        quote! {}
    };

    // Combine struct implementation with array implementations
    let combined = quote! {
        #expanded
        #array_impls
    };

    Ok(combined)
}

/// Generate a compile-time module that calculates the packing layout from IR.
fn gen_packing_module_from_ir(fields: &[LayoutField<'_>], mod_ident: &Ident) -> TokenStream {
    // Generate constants using the unified IR-based function (generates <FIELD>: U256)
    let last_field = &fields[fields.len() - 1];
    let last_slot_const = PackingConstants::new(last_field.name).slot();
    let packing_constants = packing::gen_constants_from_ir(fields, true);

    quote! {
        pub mod #mod_ident {
            use super::*;

            #packing_constants
            pub const SLOT_COUNT: usize = (#last_slot_const.saturating_add(::alloy::primitives::U256::ONE)).as_limbs()[0] as usize;
        }
    }
}

/// Helper to compute prev and next slot constant references for a field at a given index.
fn get_neighbor_slot_refs(
    idx: usize,
    fields: &[(&Ident, &Type)],
    packing: &Ident,
) -> (Option<TokenStream>, Option<TokenStream>) {
    let prev_slot_ref = if idx > 0 {
        let prev_name = fields[idx - 1].0;
        let prev_slot = PackingConstants::new(prev_name).location();
        Some(quote! { #packing::#prev_slot.offset_slots })
    } else {
        None
    };

    let next_slot_ref = if idx + 1 < fields.len() {
        let next_name = fields[idx + 1].0;
        let next_slot = PackingConstants::new(next_name).location();
        Some(quote! { #packing::#next_slot.offset_slots })
    } else {
        None
    };

    (prev_slot_ref, next_slot_ref)
}

/// Generate either `fn load()` or `fn store()` implementation.
///
/// If `is_load` is true, generates load implementation with unpacking logic.
/// If `is_load` is false, generates store implementation with packing logic.
fn gen_storage_op_impl(fields: &[(&Ident, &Type)], packing: &Ident, is_load: bool) -> TokenStream {
    let field_ops = fields
        .iter()
        .enumerate()
        .map(|(idx, (name, ty))| {
            let (prev_slot_const_ref, next_slot_const_ref) =
                get_neighbor_slot_refs(idx, fields, packing);

            let loc_const = PackingConstants::new(name).location();
            let layout_ctx = packing::gen_layout_ctx_expr(
                ty,
                false,
                quote! { #packing::#loc_const.offset_slots },
                quote! { #packing::#loc_const.offset_bytes },
                prev_slot_const_ref,
                next_slot_const_ref,
            );

            if is_load {
                quote! {
                    let #name = <#ty>::load(
                        storage,
                        base_slot + ::alloy::primitives::U256::from(#packing::#loc_const.offset_slots),
                        #layout_ctx
                    )?;
                }
            } else {
                quote! {{
                    let target_slot = base_slot + ::alloy::primitives::U256::from(#packing::#loc_const.offset_slots);
                    self.#name.store(storage, target_slot, #layout_ctx)?;
                }}
            }
        });

    quote! {
        #(#field_ops)*
    }
}

/// Generate the `fn to_evm_words()` implementation that packs fields into an array of words.
fn gen_to_evm_words_impl(fields: &[(&Ident, &Type)], packing: &Ident) -> TokenStream {
    let pack_fields = fields.iter().map(|(name, ty)| {
        let loc_const = PackingConstants::new(name).location();

        quote! {{
            const SLOT_COUNT: usize = <#ty as crate::storage::StorableType>::SLOTS;
            if <#ty as crate::storage::StorableType>::IS_PACKABLE {
                // Packable primitive: use packing module (handles both packed and unpacked)
                result[#packing::#loc_const.offset_slots] = crate::storage::packing::insert_packed_value::<SLOT_COUNT, #ty>(
                    result[#packing::#loc_const.offset_slots],
                    &self.#name,
                    #packing::#loc_const.offset_bytes,
                    #packing::#loc_const.size
                )?;
            } else {
                let nested_words = self.#name.to_evm_words()?;
                for (i, word) in nested_words.iter().enumerate() {
                    result[#packing::#loc_const.offset_slots + i] = *word;
                }
            }
        }}
    });

    quote! {
        let mut result = [::alloy::primitives::U256::ZERO; #packing::SLOT_COUNT];
        #(#pack_fields)*
        Ok(result)
    }
}

/// Generate the `fn from_evm_words()` implementation that unpacks fields from an array of words.
fn gen_from_evm_words_impl(fields: &[(&Ident, &Type)], packing: &Ident) -> TokenStream {
    let decode_fields = fields.iter().map(|(name, ty)| {
        let loc_const = PackingConstants::new(name).location();

        quote! {
            let #name = {
                const SLOT_COUNT: usize = <#ty as crate::storage::StorableType>::SLOTS;
                if <#ty as crate::storage::StorableType>::IS_PACKABLE {
                    // Packable primitive: use packing module (handles both packed and unpacked)
                    let word = words[#packing::#loc_const.offset_slots];
                    crate::storage::packing::extract_packed_value::<SLOT_COUNT, #ty>(
                        word,
                        #packing::#loc_const.offset_bytes,
                        #packing::#loc_const.size
                    )?
                } else {
                    // Non-packable (structs, multi-slot types): use from_evm_words()
                    let start = #packing::#loc_const.offset_slots;
                    let nested_words = ::std::array::from_fn::<_, SLOT_COUNT, _>(|i| {
                        words[start + i]
                    });
                    <#ty>::from_evm_words(nested_words)?
                }
            };
        }
    });

    quote! {
        #(#decode_fields)*
    }
}
