//! Implementation of the `#[derive(Storable)]` macro.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, Ident, Type};

use crate::{
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

    // Extract field names and types
    let field_infos: Vec<_> = fields
        .iter()
        .map(|f| (f.ident.as_ref().unwrap(), &f.ty))
        .collect();

    // Build layout IR using the unified function
    let layout_fields = packing::allocate_slots(&field_infos)?;

    // Generate helper module with packing layout calculations
    let mod_ident = format_ident!("__packing_{}", to_snake_case(&strukt.to_string()));
    let packing_module = gen_packing_module_from_ir(&layout_fields, &mod_ident);

    // Classify fields to figure out which impl `Storable`
    let len = fields.len();
    let (direct_fields, direct_names, mapping_names) = field_infos.iter().enumerate().fold(
        (Vec::with_capacity(len), Vec::with_capacity(len), Vec::new()),
        |mut out, (idx, (name, ty))| {
            if extract_mapping_types(ty).is_none() {
                // fields with direct slot allocation
                out.0.push((idx, *name, *ty));
                out.1.push(*name);
            } else {
                // fields with indirect slot allocation (mappings)
                out.2.push(*name);
            }
            out
        },
    );

    // Generate load/store implementations for scalar fields only
    let load_impl = gen_load_impl(&direct_fields, &mod_ident);
    let store_impl = gen_store_impl(&direct_fields, &mod_ident);
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
                debug_assert_eq!(ctx, crate::storage::LayoutCtx::Full, "Struct types can only be loaded with LayoutCtx::Full");

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
                debug_assert_eq!(ctx, crate::storage::LayoutCtx::Full, "Struct types can only be stored with LayoutCtx::Full");

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
    let packing_constants = packing::gen_constants_from_ir(fields);

    // Generate Storable-specific usize version of the slot constants
    let slot_usize_constants = fields.iter().map(|field| {
        let consts = PackingConstants::new(field.name);
        let (slot_u256, slot_usize) = (consts.slot(), consts.slot_usize());
        quote! {
            pub const #slot_usize: usize = #slot_u256.as_limbs()[0] as usize;
        }
    });

    let last_field = &fields[fields.len() - 1];
    let last_slot_const = PackingConstants::new(last_field.name).slot();

    quote! {
        pub mod #mod_ident {
            use super::*;

            #packing_constants
            #(#slot_usize_constants)*

            pub const SLOT_COUNT: usize = (#last_slot_const.saturating_add(::alloy::primitives::U256::ONE)).as_limbs()[0] as usize;
        }
    }
}

/// Helper to compute prev and next slot constant references for a field at a given index.
fn get_neighbor_slot_refs(
    idx: usize,
    indexed_fields: &[(usize, &Ident, &Type)],
    packing: &Ident,
) -> (Option<TokenStream>, Option<TokenStream>) {
    let prev_slot_ref = if idx > 0 {
        let prev_name = indexed_fields[idx - 1].1;
        let prev_slot = PackingConstants::new(prev_name).slot_usize();
        Some(quote! { #packing::#prev_slot })
    } else {
        None
    };

    let next_slot_ref = if idx + 1 < indexed_fields.len() {
        let next_name = indexed_fields[idx + 1].1;
        let next_slot = PackingConstants::new(next_name).slot_usize();
        Some(quote! { #packing::#next_slot })
    } else {
        None
    };

    (prev_slot_ref, next_slot_ref)
}

/// Generate the `fn load()` implementation with unpacking logic.
/// Accepts indexed fields where the usize is the original field index in the struct.
fn gen_load_impl(indexed_fields: &[(usize, &Ident, &Type)], packing: &Ident) -> TokenStream {
    let load_fields = indexed_fields
        .iter()
        .enumerate()
        .map(|(idx, (_orig_idx, name, ty))| {
            let consts = PackingConstants::new(name);
            let (slot_const, offset_const, _) = consts.into_tuple_usize();

            let (prev_slot_const_ref, next_slot_const_ref) =
                get_neighbor_slot_refs(idx, indexed_fields, packing);

            let layout_ctx = packing::gen_layout_ctx_expr(
                ty,
                false,
                quote! { #packing::#slot_const },
                quote! { #packing::#offset_const },
                prev_slot_const_ref,
                next_slot_const_ref,
            );

            quote! {
                let #name = <#ty>::load(
                    storage,
                    base_slot + ::alloy::primitives::U256::from(#packing::#slot_const),
                    #layout_ctx
                )?;
            }
        });

    quote! {
        #(#load_fields)*
    }
}

/// Generate the `fn store()` implementation with packing logic.
/// Accepts indexed fields where the usize is the original field index in the struct.
fn gen_store_impl(indexed_fields: &[(usize, &Ident, &Type)], packing: &Ident) -> TokenStream {
    let store_fields = indexed_fields.iter().enumerate().map(|(idx, (_orig_idx, name, ty))| {
        let consts = PackingConstants::new(name);
        let (slot_const, offset_const, _) = consts.into_tuple_usize();

        let (prev_slot_const_ref, next_slot_const_ref) =
            get_neighbor_slot_refs(idx, indexed_fields, packing);

        let layout_ctx = packing::gen_layout_ctx_expr(
            ty,
            false,
            quote! { #packing::#slot_const },
            quote! { #packing::#offset_const },
            prev_slot_const_ref,
            next_slot_const_ref,
        );

        quote! {
            {
                let target_slot = base_slot + ::alloy::primitives::U256::from(#packing::#slot_const);
                self.#name.store(storage, target_slot, #layout_ctx)?;
            }
        }
    });

    quote! {
        #(#store_fields)*
    }
}

/// Generate the `fn to_evm_words()` implementation that packs fields into an array of words.
/// Accepts indexed fields where the usize is the original field index in the struct.
fn gen_to_evm_words_impl(
    indexed_fields: &[(usize, &Ident, &Type)],
    packing: &Ident,
) -> TokenStream {
    let pack_fields = indexed_fields.iter().map(|(_orig_idx, name, ty)| {
        let (slot_const, offset_const, bytes_const) = PackingConstants::new(name).into_tuple_usize();

        quote! {
            {
                const SLOT_COUNT: usize = <#ty as crate::storage::StorableType>::SLOTS;
                const IS_PACKABLE: bool = <#ty as crate::storage::StorableType>::IS_PACKABLE;

                if IS_PACKABLE {
                    // Packable primitive: use packing module (handles both packed and unpacked)
                    result[#packing::#slot_const] = crate::storage::packing::insert_packed_value::<SLOT_COUNT, #ty>(
                        result[#packing::#slot_const],
                        &self.#name,
                        #packing::#offset_const,
                        #packing::#bytes_const
                    )?;
                } else {
                    let nested_words = self.#name.to_evm_words()?;
                    for (i, word) in nested_words.iter().enumerate() {
                        result[#packing::#slot_const + i] = *word;
                    }
                }
            }
        }
    });

    quote! {
        let mut result = [::alloy::primitives::U256::ZERO; #packing::SLOT_COUNT];
        #(#pack_fields)*
        Ok(result)
    }
}

/// Generate the `fn from_evm_words()` implementation that unpacks fields from an array of words.
/// Accepts indexed fields where the usize is the original field index in the struct.
fn gen_from_evm_words_impl(
    indexed_fields: &[(usize, &Ident, &Type)],
    packing: &Ident,
) -> TokenStream {
    let decode_fields = indexed_fields.iter().map(|(_orig_idx, name, ty)| {
        let (slot_const, offset_const, bytes_const) =
            PackingConstants::new(name).into_tuple_usize();

        quote! {
            let #name = {
                const SLOT_COUNT: usize = <#ty as crate::storage::StorableType>::SLOTS;
                const IS_PACKABLE: bool = <#ty as crate::storage::StorableType>::IS_PACKABLE;

                if IS_PACKABLE {
                    // Packable primitive: use packing module (handles both packed and unpacked)
                    let word = words[#packing::#slot_const];
                    crate::storage::packing::extract_packed_value::<SLOT_COUNT, #ty>(
                        word,
                        #packing::#offset_const,
                        #packing::#bytes_const
                    )?
                } else {
                    // Non-packable (structs, multi-slot types): use from_evm_words()
                    let start = #packing::#slot_const;
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
