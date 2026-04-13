//! Implementation of the `#[derive(Storable)]` macro.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Attribute, Data, DataEnum, DataStruct, DeriveInput, Fields, Ident, Type};

use crate::{
    FieldInfo,
    layout::{gen_handler_field_decl, gen_handler_field_init},
    packing::{self, LayoutField, PackingConstants},
    storable_primitives::gen_struct_arrays,
    utils::{extract_mapping_types, extract_storable_array_sizes, to_snake_case},
};

/// Implements the `Storable` derive macro for structs and `#[repr(u8)]` unit enums.
///
/// Packs fields into storage slots based on their byte sizes.
/// Fields are placed sequentially in slots, moving to a new slot when
/// the current slot cannot fit the next field (no spanning across slots).
pub(crate) fn derive_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    match &input.data {
        Data::Struct(data_struct) => derive_struct_impl(&input, data_struct),
        Data::Enum(data_enum) => derive_unit_enum_impl(&input, data_enum),
        _ => Err(syn::Error::new_spanned(
            &input.ident,
            "`Storable` can only be derived for structs with named fields or unit enums",
        )),
    }
}

fn derive_struct_impl(input: &DeriveInput, data_struct: &DataStruct) -> syn::Result<TokenStream> {
    // Extract struct name, generics
    let strukt = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Parse struct fields
    let fields = match &data_struct.fields {
        Fields::Named(fields_named) => &fields_named.named,
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "`Storable` can only be derived for structs with named fields",
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

    // Classify fields: direct (storable) vs indirect (mappings)
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

    // Extract just the types for IS_DYNAMIC calculation
    let direct_tys: Vec<_> = direct_fields.iter().map(|(_, ty)| *ty).collect();

    // Generate load/store/delete implementations for scalar fields only
    let load_impl = gen_load_impl(&direct_fields, &mod_ident);
    let store_impl = gen_store_impl(&direct_fields, &mod_ident);
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

fn derive_unit_enum_impl(input: &DeriveInput, data_enum: &DataEnum) -> syn::Result<TokenStream> {
    if extract_storable_array_sizes(&input.attrs)?.is_some() {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`storable_arrays` is only supported for structs",
        ));
    }

    if !has_repr_u8(&input.attrs)? {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`Storable` unit enums must be annotated with `#[repr(u8)]`",
        ));
    }

    if data_enum.variants.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`Storable` cannot be derived for empty enums",
        ));
    }

    for variant in &data_enum.variants {
        if !matches!(variant.fields, Fields::Unit) {
            return Err(syn::Error::new_spanned(
                variant,
                "`Storable` enums must use unit variants only",
            ));
        }
    }

    validate_sequential_discriminants(data_enum)?;

    let enum_name = &input.ident;
    let variant_names: Vec<_> = data_enum
        .variants
        .iter()
        .map(|variant| &variant.ident)
        .collect();
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics crate::storage::StorableType for #enum_name #ty_generics #where_clause {
            const LAYOUT: crate::storage::Layout = crate::storage::Layout::Bytes(1);

            type Handler = crate::storage::Slot<Self>;

            fn handle(slot: ::alloy::primitives::U256, ctx: crate::storage::LayoutCtx, address: ::alloy::primitives::Address) -> Self::Handler {
                crate::storage::Slot::new_with_ctx(slot, ctx, address)
            }
        }

        impl #impl_generics crate::storage::Storable for #enum_name #ty_generics #where_clause {
            #[inline]
            fn load<S: crate::storage::StorageOps>(
                storage: &S,
                slot: ::alloy::primitives::U256,
                ctx: crate::storage::LayoutCtx
            ) -> crate::error::Result<Self> {
                let value = <u8 as crate::storage::Storable>::load(storage, slot, ctx)?;
                match value {
                    #(discriminant if discriminant == Self::#variant_names as u8 => Ok(Self::#variant_names),)*
                    _ => Err(crate::error::TempoPrecompileError::enum_conversion_error()),
                }
            }

            #[inline]
            fn store<S: crate::storage::StorageOps>(
                &self,
                storage: &mut S,
                slot: ::alloy::primitives::U256,
                ctx: crate::storage::LayoutCtx
            ) -> crate::error::Result<()> {
                let value = match self {
                    #(Self::#variant_names => Self::#variant_names as u8,)*
                };

                <u8 as crate::storage::Storable>::store(&value, storage, slot, ctx)
            }
        }
    })
}

fn has_repr_u8(attrs: &[Attribute]) -> syn::Result<bool> {
    let mut repr_u8 = false;

    for attr in attrs {
        if !attr.path().is_ident("repr") {
            continue;
        }

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("u8") {
                repr_u8 = true;
            }
            Ok(())
        })?;
    }

    Ok(repr_u8)
}

fn validate_sequential_discriminants(data_enum: &DataEnum) -> syn::Result<()> {
    if data_enum.variants.len() > usize::from(u8::MAX) + 1 {
        return Err(syn::Error::new_spanned(
            &data_enum.variants,
            "`Storable` unit enums must have at most 256 variants to fit in `u8`",
        ));
    }

    for variant in &data_enum.variants {
        if variant.discriminant.is_some() {
            return Err(syn::Error::new_spanned(
                variant,
                "`Storable` unit enums must not use explicit discriminants; \
                 variants are assigned sequential values starting from 0, matching Solidity enum semantics",
            ));
        }
    }

    Ok(())
}

/// Generate a compile-time module that calculates the packing layout from IR.
fn gen_packing_module_from_ir(fields: &[LayoutField<'_>], mod_ident: &Ident) -> TokenStream {
    // Generate constants using the unified IR-based function (generates <FIELD>: U256)
    let last_field = &fields[fields.len() - 1];
    let last_slot_const = PackingConstants::new(last_field.name).slot();
    let packing_constants = packing::gen_constants_from_ir(fields, true);
    let last_type = &last_field.ty;

    quote! {
        pub mod #mod_ident {
            use super::*;

            #packing_constants
            pub const SLOT_COUNT: usize = (#last_slot_const.saturating_add(
                ::alloy::primitives::U256::from_limbs([<#last_type as crate::storage::StorableType>::SLOTS as u64, 0, 0, 0])
            )).as_limbs()[0] as usize;
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

/// Generate `fn load()` implementation.
///
/// For consecutive packable fields sharing a slot, loads the slot once and extracts
/// all fields via `PackedSlot`, avoiding redundant SLOADs.
fn gen_load_impl(fields: &[(&Ident, &Type)], packing: &Ident) -> TokenStream {
    if fields.is_empty() {
        return quote! {};
    }

    let field_loads = fields.iter().enumerate().map(|(idx, (name, ty))| {
        let loc_const = PackingConstants::new(name).location();

        let (prev_slot_ref, _) =
            packing::get_neighbor_slot_refs(idx, fields, packing, |(name, _)| name, false);

        let slot_addr = quote! { base_slot + ::alloy::primitives::U256::from(#packing::#loc_const.offset_slots) };
        let packed_ctx = quote! { crate::storage::LayoutCtx::packed(#packing::#loc_const.offset_bytes) };

        if let Some(prev_slot_ref) = prev_slot_ref {
            quote! {
                let #name = {
                    let curr_offset = #packing::#loc_const.offset_slots;
                    let prev_offset = #prev_slot_ref;

                    if <#ty as crate::storage::StorableType>::IS_PACKABLE && curr_offset == prev_offset {
                        // Same slot as previous packable field - reuse cached value
                        let packed = crate::storage::packing::PackedSlot(cached_slot);
                        <#ty as crate::storage::Storable>::load(&packed, ::alloy::primitives::U256::ZERO, #packed_ctx)?
                    } else if <#ty as crate::storage::StorableType>::IS_PACKABLE {
                        // New slot, but packable - load and cache for potential reuse
                        cached_slot = storage.load(#slot_addr)?;
                        let packed = crate::storage::packing::PackedSlot(cached_slot);
                        <#ty as crate::storage::Storable>::load(&packed, ::alloy::primitives::U256::ZERO, #packed_ctx)?
                    } else {
                        // Non-packable - direct load
                        <#ty as crate::storage::Storable>::load(storage, #slot_addr, crate::storage::LayoutCtx::FULL)?
                    }
                };
            }
        } else {
            // First field
            quote! {
                let #name = if <#ty as crate::storage::StorableType>::IS_PACKABLE {
                    cached_slot = storage.load(#slot_addr)?;
                    let packed = crate::storage::packing::PackedSlot(cached_slot);
                    <#ty as crate::storage::Storable>::load(&packed, ::alloy::primitives::U256::ZERO, #packed_ctx)?
                } else {
                    <#ty as crate::storage::Storable>::load(storage, #slot_addr, crate::storage::LayoutCtx::FULL)?
                };
            }
        }
    });

    quote! {
        let mut cached_slot = ::alloy::primitives::U256::ZERO;
        #(#field_loads)*
    }
}

/// Generate `fn store()` implementation.
///
/// For consecutive packable fields sharing a slot, accumulates changes in memory
/// and writes once, avoiding redundant SLOAD + SSTORE pairs.
fn gen_store_impl(fields: &[(&Ident, &Type)], packing: &Ident) -> TokenStream {
    if fields.is_empty() {
        return quote! {};
    }

    let field_stores = fields.iter().enumerate().map(|(idx, (name, ty))| {
        let loc_const = PackingConstants::new(name).location();
        let next_ty = fields.get(idx + 1).map(|(_, ty)| *ty);

        let (prev_slot_ref, next_slot_ref) =
            packing::get_neighbor_slot_refs(idx, fields, packing, |(name, _)| name, false);

        let slot_addr = quote! { base_slot + ::alloy::primitives::U256::from(#packing::#loc_const.offset_slots) };
        let packed_ctx = quote! { crate::storage::LayoutCtx::packed(#packing::#loc_const.offset_bytes) };

        // Determine if we need to store after this field
        let should_store = match (&next_slot_ref, next_ty) {
            (Some(next_slot), Some(next_ty)) => {
                // Store if next field is in different slot OR next field is not packable
                quote! {
                    #packing::#loc_const.offset_slots != #next_slot
                        || !<#next_ty as crate::storage::StorableType>::IS_PACKABLE
                }
            }
            _ => quote! { true }, // Always store last field
        };

        if let Some(prev_slot_ref) = prev_slot_ref {
            quote! {{
                let curr_offset = #packing::#loc_const.offset_slots;
                let prev_offset = #prev_slot_ref;

                if <#ty as crate::storage::StorableType>::IS_PACKABLE && curr_offset == prev_offset {
                    // Same slot as previous packable field - accumulate in pending slot
                    let mut packed = crate::storage::packing::PackedSlot(pending_val);
                    <#ty as crate::storage::Storable>::store(&self.#name, &mut packed, ::alloy::primitives::U256::ZERO, #packed_ctx)?;
                    pending_val = packed.0;
                } else if <#ty as crate::storage::StorableType>::IS_PACKABLE {
                    // New slot, but packable - commit previous and start new batch
                    if let Some(offset) = pending_offset {
                        storage.store(base_slot + ::alloy::primitives::U256::from(offset), pending_val)?;
                    }
                    pending_val = storage.load(#slot_addr)?;
                    pending_offset = Some(curr_offset);
                    let mut packed = crate::storage::packing::PackedSlot(pending_val);
                    <#ty as crate::storage::Storable>::store(&self.#name, &mut packed, ::alloy::primitives::U256::ZERO, #packed_ctx)?;
                    pending_val = packed.0;
                } else {
                    // Non-packable - commit pending and do direct store
                    if let Some(offset) = pending_offset {
                        storage.store(base_slot + ::alloy::primitives::U256::from(offset), pending_val)?;
                        pending_offset = None;
                    }
                    <#ty as crate::storage::Storable>::store(&self.#name, storage, #slot_addr, crate::storage::LayoutCtx::FULL)?;
                }

                // Store if this is the last field in the current slot group
                if let Some(offset) = pending_offset && (#should_store) {
                    storage.store(base_slot + ::alloy::primitives::U256::from(offset), pending_val)?;
                    pending_offset = None;
                }
            }}
        } else {
            // First field
            quote! {{
                if <#ty as crate::storage::StorableType>::IS_PACKABLE {
                    pending_val = storage.load(#slot_addr)?;
                    pending_offset = Some(#packing::#loc_const.offset_slots);
                    let mut packed = crate::storage::packing::PackedSlot(pending_val);
                    <#ty as crate::storage::Storable>::store(&self.#name, &mut packed, ::alloy::primitives::U256::ZERO, #packed_ctx)?;
                    pending_val = packed.0;

                    // Store if this is the last field in the current slot group
                    if #should_store {
                        storage.store(#slot_addr, pending_val)?;
                        pending_offset = None;
                    }
                } else {
                    <#ty as crate::storage::Storable>::store(&self.#name, storage, #slot_addr, crate::storage::LayoutCtx::FULL)?;
                }
            }}
        }
    });

    quote! {
        let mut pending_val = ::alloy::primitives::U256::ZERO;
        let mut pending_offset: Option<usize> = None;
        #(#field_stores)*
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

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    fn parse_enum(input: DeriveInput) -> DataEnum {
        match input.data {
            Data::Enum(data_enum) => data_enum,
            _ => panic!("expected enum input"),
        }
    }

    #[test]
    fn validate_sequential_discriminants_accepts_implicit_variants() {
        let data_enum = parse_enum(parse_quote! {
            enum PackedStatus {
                Pending,
                Active,
                Frozen,
            }
        });

        validate_sequential_discriminants(&data_enum).unwrap();
    }

    #[test]
    fn validate_sequential_discriminants_rejects_explicit_discriminants() {
        let data_enum = parse_enum(parse_quote! {
            enum PackedStatus {
                Pending = 0,
                Active = 1,
                Frozen = 2,
            }
        });

        let err = validate_sequential_discriminants(&data_enum).unwrap_err();
        assert!(err.to_string().contains("explicit discriminants"));
    }

    #[test]
    fn validate_sequential_discriminants_rejects_gaps() {
        let data_enum = parse_enum(parse_quote! {
            enum PackedStatus {
                Pending = 0,
                Active = 5,
            }
        });

        let err = validate_sequential_discriminants(&data_enum).unwrap_err();
        assert!(err.to_string().contains("explicit discriminants"));
    }
}
