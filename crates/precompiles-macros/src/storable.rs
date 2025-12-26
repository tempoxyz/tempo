//! Implementation of the `#[derive(Storable)]` and `#[derive(StorableInSpace)]` macros.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, Ident, Type};

use crate::{
    FieldInfo,
    layout::{gen_handler_field_decl, gen_handler_field_init},
    packing::{self, LayoutField, PackingConstants},
    storable_primitives::gen_struct_arrays,
    utils::{extract_mapping_types, extract_storable_array_sizes, to_snake_case},
};

/// Parsed struct information shared between Storable and StorableInSpace derives.
struct ParsedStruct<'a> {
    strukt: &'a Ident,
    impl_generics: syn::ImplGenerics<'a>,
    ty_generics: syn::TypeGenerics<'a>,
    where_clause: Option<&'a syn::WhereClause>,
    layout_fields: Vec<LayoutField<'a>>,
    mod_ident: Ident,
    direct_fields: Vec<(&'a Ident, &'a Type)>,
    direct_names: Vec<&'a Ident>,
    mapping_names: Vec<&'a Ident>,
    direct_tys: Vec<&'a Type>,
    attrs: &'a [syn::Attribute],
}

/// Parse and validate struct for derive macros.
fn parse_struct(
    input: &DeriveInput,
) -> syn::Result<(
    Vec<FieldInfo>,
    &syn::punctuated::Punctuated<syn::Field, syn::token::Comma>,
)> {
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

    Ok((field_infos, fields))
}

/// Common setup for both Storable and StorableInSpace derives.
fn setup_derive<'a>(
    input: &'a DeriveInput,
    field_infos: &'a [FieldInfo],
) -> syn::Result<ParsedStruct<'a>> {
    let strukt = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Build layout IR
    let layout_fields = packing::allocate_slots(field_infos)?;
    let mod_ident = format_ident!("__packing_{}", to_snake_case(&strukt.to_string()));

    // Classify fields: direct (storable) vs indirect (mappings)
    let len = field_infos.len();
    let (direct_fields, direct_names, mapping_names) = field_infos.iter().fold(
        (Vec::with_capacity(len), Vec::with_capacity(len), Vec::new()),
        |mut out, field_info| {
            if extract_mapping_types(&field_info.ty).is_none() {
                out.0.push((&field_info.name, &field_info.ty));
                out.1.push(&field_info.name);
            } else {
                out.2.push(&field_info.name);
            }
            out
        },
    );

    let direct_tys: Vec<_> = direct_fields.iter().map(|(_, ty)| *ty).collect();

    Ok(ParsedStruct {
        strukt,
        impl_generics,
        ty_generics,
        where_clause,
        layout_fields,
        mod_ident,
        direct_fields,
        direct_names,
        mapping_names,
        direct_tys,
        attrs: &input.attrs,
    })
}

/// Implements the `Storable` derive macro for structs.
pub(crate) fn derive_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    let (field_infos, _) = parse_struct(&input)?;
    let parsed = setup_derive(&input, &field_infos)?;

    let ParsedStruct {
        strukt,
        impl_generics,
        ty_generics,
        where_clause,
        layout_fields,
        mod_ident,
        direct_fields,
        direct_names,
        mapping_names,
        direct_tys,
        attrs,
    } = parsed;

    // Generate helper module with packing layout calculations
    let packing_module = gen_packing_module_from_ir(&layout_fields, &mod_ident);

    // Generate load/store/delete implementations for scalar fields only
    let load_impl = gen_load_store_impl(&direct_fields, &mod_ident, true);
    let store_impl = gen_load_store_impl(&direct_fields, &mod_ident, false);
    let delete_impl = gen_delete_impl(&direct_fields, &mod_ident);

    // Generate handler struct for field access
    let handler_struct = gen_handler_struct(strukt, &layout_fields, &mod_ident);
    let handler_name = format_ident!("{}Handler", strukt);

    let expanded = quote! {
        #packing_module
        #handler_struct

        // impl `StorableType` for layout information
        impl #impl_generics crate::storage::StorableType for #strukt #ty_generics #where_clause {
            // Structs cannot be packed, so they must take full slots
            const LAYOUT: crate::storage::Layout = crate::storage::Layout::Slots(#mod_ident::SLOT_COUNT);

            // A struct is dynamic if any of its fields is dynamic
            const IS_DYNAMIC: bool = #(
                <#direct_tys as crate::storage::StorableType>::IS_DYNAMIC
            )||*;

            type Handler = #handler_name;

            fn handle(slot: ::alloy::primitives::U256, _ctx: crate::storage::LayoutCtx, address: ::alloy::primitives::Address) -> Self::Handler {
                #handler_name::new(slot, address)
            }
        }

        // `Storable` implementation: storage I/O with full logic
        impl #impl_generics crate::storage::Storable for #strukt #ty_generics #where_clause {
            fn load<S: crate::storage::StorageOps>(
                storage: &S,
                base_slot: ::alloy::primitives::U256,
                ctx: crate::storage::LayoutCtx
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
                &self,
                storage: &mut S,
                base_slot: ::alloy::primitives::U256,
                ctx: crate::storage::LayoutCtx
            ) -> crate::error::Result<()> {
                use crate::storage::Storable;
                debug_assert_eq!(ctx, crate::storage::LayoutCtx::FULL, "Struct types can only be stored with LayoutCtx::FULL");

                #store_impl

                Ok(())
            }

            fn delete<S: crate::storage::StorageOps>(
                storage: &mut S,
                base_slot: ::alloy::primitives::U256,
                ctx: crate::storage::LayoutCtx
            ) -> crate::error::Result<()> {
                use crate::storage::Storable;
                debug_assert_eq!(ctx, crate::storage::LayoutCtx::FULL, "Struct types can only be deleted with LayoutCtx::FULL");

                #delete_impl

                Ok(())
            }
        }
    };

    // Generate array implementations if requested
    let array_impls = if let Some(sizes) = extract_storable_array_sizes(attrs)? {
        let struct_type = quote! { #strukt #ty_generics };
        gen_struct_arrays(struct_type, &sizes)
    } else {
        quote! {}
    };

    Ok(quote! {
        #expanded
        #array_impls
    })
}

/// Derives the `StorableInSpace` trait for structs used in `AddressMapping<T>`.
///
/// This is an ADD-ON to `#[derive(Storable)]`, which must also be derived.
pub(crate) fn derive_space_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    let (field_infos, _) = parse_struct(&input)?;

    let strukt = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Build layout IR (same as Storable - we need it for SpaceHandler field generation)
    let layout_fields = packing::allocate_slots(&field_infos)?;

    // Reference the packing module generated by Storable
    let mod_ident = format_ident!("__packing_{}", to_snake_case(&strukt.to_string()));

    // Generate space handler struct for DirectAddressMap access
    let space_handler_struct = gen_space_handler_struct(strukt, &layout_fields, &mod_ident);
    let space_handler_name = format_ident!("{}SpaceHandler", strukt);

    Ok(quote! {
        // Compile-time check: verify Storable was also derived by referencing its packing module
        const _: () = {
            // This will fail to compile if #[derive(Storable)] was not also applied
            let _ = #mod_ident::SLOT_COUNT;
        };

        #space_handler_struct

        // impl `StorableInSpace` for AddressMapping access
        impl #impl_generics crate::storage::StorableInSpace for #strukt #ty_generics #where_clause {
            type SpaceHandler = #space_handler_name;

            fn handle_in_space(
                space: u8,
                key: ::alloy::primitives::Address,
                _ctx: crate::storage::LayoutCtx,
                address: ::alloy::primitives::Address
            ) -> Self::SpaceHandler {
                #space_handler_name::new(space, key, address)
            }
        }
    })
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

/// Generate a handler struct for the storable type.
///
/// The handler provides type-safe access to both the full struct and individual fields.
fn gen_handler_struct(
    struct_name: &Ident,
    fields: &[LayoutField<'_>],
    mod_ident: &Ident,
) -> TokenStream {
    let handler_name = format_ident!("{}Handler", struct_name);

    // Generate public handler fields
    let handler_fields = fields.iter().map(gen_handler_field_decl);

    // Generate field initializations for constructor using the shared helper
    let field_inits = fields
        .iter()
        .enumerate()
        .map(|(idx, field)| gen_handler_field_init(field, idx, fields, Some(mod_ident)));

    quote! {
        /// Type-safe handler for accessing `#struct_name` in storage.
        ///
        /// Provides individual field access via public fields and whole-struct operations.
        #[derive(Debug, Clone)]
        pub struct #handler_name {
            address: ::alloy::primitives::Address,
            base_slot: ::alloy::primitives::U256,
            #(#handler_fields,)*
        }

        impl #handler_name {
            /// Creates a new handler for the struct at the given base slot.
            #[inline]
            pub fn new(base_slot: ::alloy::primitives::U256, address: ::alloy::primitives::Address) -> Self {
                Self {
                    base_slot,
                    #(#field_inits,)*
                    address,
                }
            }

            /// Returns the base storage slot where this struct's data is stored.
            ///
            /// Single-slot structs pack all fields into this slot.
            /// Multi-slot structs use consecutive slots starting from this base.
            #[inline]
            pub fn base_slot(&self) -> ::alloy::primitives::U256 {
                self.base_slot
            }

            /// Returns a `Slot<T>` for whole-struct storage operations.
            #[inline]
            fn as_slot(&self) -> crate::storage::Slot<#struct_name> {
                crate::storage::Slot::<#struct_name>::new(
                    self.base_slot,
                    self.address
                )
            }
        }

        impl crate::storage::Handler<#struct_name> for #handler_name {
            #[inline]
            fn read(&self) -> crate::error::Result<#struct_name> {
                self.as_slot().read()
            }

            #[inline]
            fn write(&mut self, value: #struct_name) -> crate::error::Result<()> {
                self.as_slot().write(value)
            }

            #[inline]
            fn delete(&mut self) -> crate::error::Result<()> {
                self.as_slot().delete()
            }

            /// Reads the struct from transient storage.
            #[inline]
            fn t_read(&self) -> crate::error::Result<#struct_name> {
                self.as_slot().t_read()
            }

            /// Writes the struct to transient storage.
            #[inline]
            fn t_write(&mut self, value: #struct_name) -> crate::error::Result<()> {
                self.as_slot().t_write(value)
            }

            /// Deletes the struct from transient storage.
            #[inline]
            fn t_delete(&mut self) -> crate::error::Result<()> {
                self.as_slot().t_delete()
            }
        }
    }
}

/// Generate a space handler struct for DirectAddressMap access.
///
/// This handler pre-computes slots using `[SPACE + offset][key][zeros]` format,
/// enabling efficient storage access without hashing.
fn gen_space_handler_struct(
    struct_name: &Ident,
    fields: &[LayoutField<'_>],
    mod_ident: &Ident,
) -> TokenStream {
    let space_handler_name = format_ident!("{}SpaceHandler", struct_name);

    // Generate public handler fields (same types as regular handler)
    let handler_fields = fields.iter().map(gen_handler_field_decl);

    // Generate field initializations using compute_direct_slot
    let field_inits = fields.iter().enumerate().map(|(idx, field)| {
        let field_name = field.name;
        let ty = field.ty;
        let loc_const = PackingConstants::new(field_name).location();

        // Calculate neighbor slot references for packing detection
        let (prev_slot_const_ref, next_slot_const_ref) =
            packing::get_neighbor_slot_refs(idx, fields, mod_ident, |f| f.name);

        // Calculate LayoutCtx for proper packing (same as regular handler)
        let layout_ctx = packing::gen_layout_ctx_expr(
            ty,
            false, // storable fields are always auto-allocated
            quote! { #mod_ident::#loc_const.offset_slots },
            quote! { #mod_ident::#loc_const.offset_bytes },
            prev_slot_const_ref,
            next_slot_const_ref,
        );

        // For DirectAddressMap, we compute slot as [base_space + slot_offset][key][zeros]
        // The slot_offset comes from the packing layout (same as regular handler)
        quote! {
            #field_name: <#ty as crate::storage::StorableType>::handle(
                crate::storage::compute_direct_slot(
                    base_space.checked_add(#mod_ident::#loc_const.offset_slots as u8)
                        .expect("SPACE overflow: struct requires too many slots"),
                    key
                ),
                #layout_ctx,
                address
            )
        }
    });

    quote! {
        /// Space-aware handler for accessing `#struct_name` in DirectAddressMap storage.
        ///
        /// Each field's slot is computed as `[base_space + field_offset][key][zeros]`,
        /// enabling O(1) address-based lookups without hashing.
        #[derive(Debug, Clone)]
        pub struct #space_handler_name {
            address: ::alloy::primitives::Address,
            base_space: u8,
            key: ::alloy::primitives::Address,
            #(#handler_fields,)*
        }

        impl #space_handler_name {
            /// Creates a new space handler for the struct.
            ///
            /// Each field gets a pre-computed slot: `[base_space + field_offset][key][zeros]`
            #[inline]
            pub fn new(base_space: u8, key: ::alloy::primitives::Address, address: ::alloy::primitives::Address) -> Self {
                Self {
                    base_space,
                    key,
                    #(#field_inits,)*
                    address,
                }
            }

            /// Returns the base storage space for this struct.
            #[inline]
            pub fn base_space(&self) -> u8 {
                self.base_space
            }

            /// Returns the key address used for slot computation.
            #[inline]
            pub fn key(&self) -> ::alloy::primitives::Address {
                self.key
            }
        }

        impl crate::storage::Handler<#struct_name> for #space_handler_name {
            #[inline]
            fn read(&self) -> crate::error::Result<#struct_name> {
                // SpaceHandler doesn't support whole-struct read/write
                // Individual fields should be accessed directly
                unimplemented!("SpaceHandler does not support whole-struct read; access fields directly")
            }

            #[inline]
            fn write(&mut self, _value: #struct_name) -> crate::error::Result<()> {
                unimplemented!("SpaceHandler does not support whole-struct write; access fields directly")
            }

            #[inline]
            fn delete(&mut self) -> crate::error::Result<()> {
                unimplemented!("SpaceHandler does not support whole-struct delete; access fields directly")
            }

            #[inline]
            fn t_read(&self) -> crate::error::Result<#struct_name> {
                unimplemented!("SpaceHandler does not support whole-struct t_read; access fields directly")
            }

            #[inline]
            fn t_write(&mut self, _value: #struct_name) -> crate::error::Result<()> {
                unimplemented!("SpaceHandler does not support whole-struct t_write; access fields directly")
            }

            #[inline]
            fn t_delete(&mut self) -> crate::error::Result<()> {
                unimplemented!("SpaceHandler does not support whole-struct t_delete; access fields directly")
            }
        }
    }
}

/// Generate `fn load()` or `fn store()` implementation.
fn gen_load_store_impl(fields: &[(&Ident, &Type)], packing: &Ident, is_load: bool) -> TokenStream {
    let field_ops = fields.iter().enumerate().map(|(idx, (name, ty))| {
        let (prev_slot_const_ref, next_slot_const_ref) =
            packing::get_neighbor_slot_refs(idx, fields, packing, |(name, _ty)| name);

        // Generate `LayoutCtx` expression with compile-time packing detection
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
                let #name = <#ty as crate::storage::Storable>::load(
                    storage,
                    base_slot + ::alloy::primitives::U256::from(#packing::#loc_const.offset_slots),
                    #layout_ctx
                )?;
            }
        } else {
            quote! {{
                let target_slot = base_slot + ::alloy::primitives::U256::from(#packing::#loc_const.offset_slots);
                <#ty as crate::storage::Storable>::store(&self.#name, storage, target_slot, #layout_ctx)?;
            }}
        }
    });

    quote! {
        #(#field_ops)*
    }
}

/// Generate `fn delete()` implementation.
fn gen_delete_impl(fields: &[(&Ident, &Type)], packing: &Ident) -> TokenStream {
    // Delete dynamic fields using their `Storable` impl so that they handle their own cleanup
    let dynamic_deletes = fields.iter().map(|(name, ty)| {
        let loc_const = PackingConstants::new(name).location();
        quote! {
            if <#ty as crate::storage::StorableType>::IS_DYNAMIC {
                <#ty as crate::storage::Storable>::delete(
                    storage,
                    base_slot + ::alloy::primitives::U256::from(#packing::#loc_const.offset_slots),
                    crate::storage::LayoutCtx::FULL
                )?;
            }
        }
    });

    // Bulk clear static slots - only zero slots that contain non-dynamic fields
    let is_static_slot = fields.iter().map(|(name, ty)| {
        let loc_const = PackingConstants::new(name).location();
        quote! {
            ((#packing::#loc_const.offset_slots..#packing::#loc_const.offset_slots + <#ty as crate::storage::StorableType>::SLOTS)
                .contains(&slot_offset) &&
             !<#ty as crate::storage::StorableType>::IS_DYNAMIC)
        }
    });

    quote! {
        #(#dynamic_deletes)*

        for slot_offset in 0..#packing::SLOT_COUNT {
            // Only zero this slot if a static field occupies it
            if #(#is_static_slot)||* {
                storage.store(
                    base_slot + ::alloy::primitives::U256::from(slot_offset),
                    ::alloy::primitives::U256::ZERO
                )?;
            }
        }
    }
}
