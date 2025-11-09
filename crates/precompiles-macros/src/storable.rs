//! Implementation of the `#[derive(Storable)]` macro.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, Ident, Type};

use crate::{
    storable_primitives::gen_struct_arrays,
    utils::{
        extract_storable_array_sizes, is_array_type, is_custom_struct, is_dynamic_type,
        normalize_to_snake_case,
    },
};

/// Implements the `Storable` derive macro for structs.
///
/// Packs fields into storage slots based on their byte sizes.
/// Fields are placed sequentially in slots, moving to a new slot when
/// the current slot cannot fit the next field (no spanning across slots).
pub(crate) fn derive_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    derive_struct_impl(input)
}

/// Implements the `Storable` derive macro for a struct with slot packing.
fn derive_struct_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    // Extract struct name and generics
    let strukt = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Extract array sizes from #[storable_arrays(...)] attribute
    let array_sizes = extract_storable_array_sizes(&input.attrs)?;

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

    // Generate unique module name based on struct name
    let mod_ident = format_ident!("__packing_{}", normalize_to_snake_case(&strukt.to_string()));

    // Generate helper module with packing layout calculations
    let packing_module = gen_packing_module(&field_infos, &mod_ident);

    // Generate load and store implementations
    let load_impl = gen_load_impl(&field_infos, &mod_ident);
    let store_impl = gen_store_impl(&field_infos, &mod_ident);
    let to_evm_words_impl = gen_to_evm_words_impl(&field_infos, &mod_ident);
    let from_evm_words_impl = gen_from_evm_words_impl(&field_infos, &mod_ident);

    let field_names: Vec<_> = field_infos.iter().map(|(name, _)| name).collect();

    // Generate the trait implementations
    let expanded = quote! {
        #packing_module

        // impl `StorableType` for byte count access
        impl #impl_generics crate::storage::StorableType for #strukt #ty_generics #where_clause {
            // Enforce BYTE_COUNT = SLOT_COUNT * 32 for derived structs (required for packing logic)
            const BYTE_COUNT: usize = #mod_ident::SLOT_COUNT * 32;
        }

        // Add SLOT_COUNT as an inherent const for use in const generic contexts
        impl #impl_generics #strukt #ty_generics #where_clause {
            pub const SLOT_COUNT: usize = #mod_ident::SLOT_COUNT;
        }

        // impl `Storable` with const generic for slot count
        impl #impl_generics crate::storage::Storable<{ #mod_ident::SLOT_COUNT }> for #strukt #ty_generics #where_clause {
                const SLOT_COUNT: usize = #mod_ident::SLOT_COUNT;

                fn load<S>(
                    storage: &mut S,
                    base_slot: ::alloy::primitives::U256,
                ) -> crate::error::Result<Self>
                where
                    S: crate::storage::StorageOps,
                {
                    use crate::storage::Storable;

                    #load_impl

                    Ok(Self {
                        #(#field_names),*
                    })
                }

                fn store<S>(
                    &self,
                    storage: &mut S,
                    base_slot: ::alloy::primitives::U256,
                ) -> crate::error::Result<()>
                where
                    S: crate::storage::StorageOps,
                {
                    use crate::storage::Storable;

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
                        #(#field_names),*
                    })
                }
            }
    };

    // Generate array implementations if requested
    let array_impls = if let Some(sizes) = array_sizes {
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

/// Generate a compile-time module that calculates the packing layout.
fn gen_packing_module(fields: &[(&Ident, &Type)], mod_ident: &Ident) -> TokenStream {
    let field_byte_sizes = fields.iter().enumerate().map(|(idx, (_, ty))| {
        let const_name = Ident::new(
            &format!("FIELD_{idx}_BYTES"),
            proc_macro2::Span::call_site(),
        );
        quote! {
            pub const #const_name: usize = <#ty as crate::storage::StorableType>::BYTE_COUNT;
        }
    });

    let field_layouts = fields.iter().enumerate().map(|(idx, (_, ty))| {
        let slot_const = Ident::new(&format!("FIELD_{idx}_SLOT"), proc_macro2::Span::call_site());
        let offset_const = Ident::new(
            &format!("FIELD_{idx}_OFFSET"),
            proc_macro2::Span::call_site(),
        );
        let bytes_const = Ident::new(
            &format!("FIELD_{idx}_BYTES"),
            proc_macro2::Span::call_site(),
        );

        let prev_calculations = if idx == 0 {
            quote! {
                const PREV_SLOT: usize = 0;
                const PREV_OFFSET: usize = 0;
            }
        } else {
            let prev_idx = idx - 1;
            let (_, prev_ty) = &fields[prev_idx];
            let prev_is_struct = is_custom_struct(prev_ty);
            let prev_is_dynamic = is_dynamic_type(prev_ty);
            let prev_is_array = is_array_type(prev_ty);

            let prev_slot = Ident::new(
                &format!("FIELD_{prev_idx}_SLOT"),
                proc_macro2::Span::call_site(),
            );
            let prev_offset = Ident::new(
                &format!("FIELD_{prev_idx}_OFFSET"),
                proc_macro2::Span::call_site(),
            );
            let prev_bytes = Ident::new(
                &format!("FIELD_{prev_idx}_BYTES"),
                proc_macro2::Span::call_site(),
            );

            if prev_is_struct {
                // Previous field was a struct - advance by its SLOT_COUNT and reset offset
                quote! {
                    const PREV_SLOT: usize = #prev_slot + <#prev_ty>::SLOT_COUNT;
                    const PREV_OFFSET: usize = 0;
                }
            } else if prev_is_dynamic {
                // Previous field was a dynamic type (String/Bytes) - advance by 1 slot and reset offset
                quote! {
                    const PREV_SLOT: usize = #prev_slot + 1;
                    const PREV_OFFSET: usize = 0;
                }
            } else if prev_is_array {
                // Previous field was an array - advance by array's SLOT_COUNT and reset offset
                // Arrays satisfy BYTE_COUNT = SLOT_COUNT * 32, so div_ceil recovers SLOT_COUNT
                quote! {
                    const PREV_SLOT: usize = #prev_slot + #prev_bytes.div_ceil(32);
                    const PREV_OFFSET: usize = 0;
                }
            } else {
                // Previous field was primitive - continue from its end position
                quote! {
                    const PREV_SLOT: usize = #prev_slot;
                    const PREV_OFFSET: usize = #prev_offset + #prev_bytes;
                }
            }
        };

        if is_array_type(ty) || is_dynamic_type(ty) || is_custom_struct(ty) {
            // Structs, dynamic types, and arrays must start on a new slot if PREV_OFFSET != 0
            quote! {
                pub const #slot_const: usize = {
                    #prev_calculations
                    if PREV_OFFSET == 0 {
                        PREV_SLOT
                    } else {
                        PREV_SLOT + 1
                    }
                };

                pub const #offset_const: usize = 0;
            }
        } else {
            // Primitive fields use standard packing logic
            quote! {
                pub const #slot_const: usize = {
                    #prev_calculations
                    if PREV_OFFSET + #bytes_const <= 32 {
                        PREV_SLOT
                    } else {
                        PREV_SLOT + 1
                    }
                };

                pub const #offset_const: usize = {
                    #prev_calculations
                    if PREV_OFFSET + #bytes_const <= 32 {
                        PREV_OFFSET
                    } else {
                        0
                    }
                };
            }
        }
    });

    let last_field_idx = fields.len() - 1;
    let last_slot_const = Ident::new(
        &format!("FIELD_{last_field_idx}_SLOT"),
        proc_macro2::Span::call_site(),
    );

    quote! {
        mod #mod_ident {
            use super::*;

            #(#field_byte_sizes)*
            #(#field_layouts)*

            pub const SLOT_COUNT: usize = #last_slot_const + 1;
        }
    }
}

/// Generate the `fn load()` implementation with unpacking logic.
fn gen_load_impl(fields: &[(&Ident, &Type)], packing: &Ident) -> TokenStream {
    let load_fields = fields.iter().enumerate().map(|(idx, (name, ty))| {
        let slot_const = Ident::new(&format!("FIELD_{idx}_SLOT"), proc_macro2::Span::call_site());
        let offset_const = Ident::new(&format!("FIELD_{idx}_OFFSET"), proc_macro2::Span::call_site());
        let bytes_const = Ident::new(&format!("FIELD_{idx}_BYTES"), proc_macro2::Span::call_site());

        // Struct, dynamic type, and array fields always use `load()` directly (never packed)
        if is_array_type(ty) || is_dynamic_type(ty) || is_custom_struct(ty) {
            return quote! {
                let #name = <#ty>::load(
                    storage,
                    base_slot + ::alloy::primitives::U256::from(#packing::#slot_const)
                )?;
            };
        }

        // For primitives, check if this field shares the slot with any other field
        let next_idx = idx + 1;
        let prev_idx = if idx > 0 { Some(idx - 1) } else { None };

        let shares_slot_check = if let Some(prev) = prev_idx {
            let prev_slot = Ident::new(&format!("FIELD_{prev}_SLOT"), proc_macro2::Span::call_site());
            if next_idx < fields.len() {
                let next_slot = Ident::new(&format!("FIELD_{next_idx}_SLOT"), proc_macro2::Span::call_site());
                quote! {
                    #packing::#prev_slot == #packing::#slot_const || #packing::#next_slot == #packing::#slot_const
                }
            } else {
                quote! {
                    #packing::#prev_slot == #packing::#slot_const
                }
            }
        } else if next_idx < fields.len() {
            let next_slot = Ident::new(&format!("FIELD_{next_idx}_SLOT"), proc_macro2::Span::call_site());
            quote! {
                #packing::#next_slot == #packing::#slot_const
            }
        } else {
            quote! { false }
        };

        quote! {
            let #name = {
                let shares_slot = #shares_slot_check;

                if !shares_slot {
                    // If the field is alone in its slot, we can use `field.load()` directly
                    <#ty>::load(
                        storage,
                        base_slot + ::alloy::primitives::U256::from(#packing::#slot_const)
                    )?
                }
                // Otherwise, it is packed with others
                else {
                    // Use packing module to extract packed value
                    let slot_value = storage.sload(
                        base_slot + ::alloy::primitives::U256::from(#packing::#slot_const)
                    )?;
                    crate::storage::packing::extract_packed_value::<#ty>(
                        slot_value,
                        #packing::#offset_const,
                        #packing::#bytes_const
                    )?
                }
            };
        }
    });

    quote! {
        #(#load_fields)*
    }
}

/// Generate the `fn store()` implementation with packing logic.
fn gen_store_impl(fields: &[(&Ident, &Type)], packing: &Ident) -> TokenStream {
    let store_fields = fields.iter().enumerate().map(|(idx, (name, ty))| {
        let slot_const = Ident::new(&format!("FIELD_{idx}_SLOT"), proc_macro2::Span::call_site());
        let offset_const = Ident::new(&format!("FIELD_{idx}_OFFSET"), proc_macro2::Span::call_site());
        let bytes_const = Ident::new(&format!("FIELD_{idx}_BYTES"), proc_macro2::Span::call_site());

        // Struct, dynamic type, and array fields always use store() directly (never packed)
        if is_array_type(ty) || is_dynamic_type(ty) || is_custom_struct(ty) {
            return quote! {
                self.#name.store(
                    storage,
                    base_slot + ::alloy::primitives::U256::from(#packing::#slot_const)
                )?;
            };
        }

        // For primitives, check if this field shares the slot with any other field
        let next_idx = idx + 1;
        let prev_idx = if idx > 0 { Some(idx - 1) } else { None };

        let shares_slot_check = if let Some(prev) = prev_idx {
            let prev_slot = Ident::new(&format!("FIELD_{prev}_SLOT"), proc_macro2::Span::call_site());
            if next_idx < fields.len() {
                let next_slot = Ident::new(&format!("FIELD_{next_idx}_SLOT"), proc_macro2::Span::call_site());
                quote! {
                    #packing::#prev_slot == #packing::#slot_const || #packing::#next_slot == #packing::#slot_const
                }
            } else {
                quote! {
                    #packing::#prev_slot == #packing::#slot_const
                }
            }
        } else if next_idx < fields.len() {
            let next_slot = Ident::new(&format!("FIELD_{next_idx}_SLOT"), proc_macro2::Span::call_site());
            quote! {
                #packing::#next_slot == #packing::#slot_const
            }
        } else {
            quote! { false }
        };

        quote! {
            {
                let target_slot = base_slot + ::alloy::primitives::U256::from(#packing::#slot_const);
                let shares_slot = #shares_slot_check;

                // If the field is alone in its slot, we can use `field.store()` directly
                if !shares_slot {
                    self.#name.store(storage, target_slot)?;
                }
                // Otherwise, it is packed with others
                else {
                    // Use packing module to insert packed value
                    let current = storage.sload(target_slot)?;
                    let new_value = crate::storage::packing::insert_packed_value(
                        current,
                        &self.#name,
                        #packing::#offset_const,
                        #packing::#bytes_const
                    )?;
                    storage.sstore(target_slot, new_value)?;
                }
            }
        }
    });

    quote! {
        #(#store_fields)*
    }
}

/// Generate the `fn to_evm_words()` implementation that packs fields into an array of words.
fn gen_to_evm_words_impl(fields: &[(&Ident, &Type)], packing: &Ident) -> TokenStream {
    let pack_fields = fields.iter().enumerate().map(|(idx, (name, ty))| {
        let slot_const = Ident::new(&format!("FIELD_{idx}_SLOT"), proc_macro2::Span::call_site());
        let offset_const = Ident::new(
            &format!("FIELD_{idx}_OFFSET"),
            proc_macro2::Span::call_site(),
        );
        let bytes_const = Ident::new(
            &format!("FIELD_{idx}_BYTES"),
            proc_macro2::Span::call_site(),
        );

        let is_struct = is_custom_struct(ty);
        let is_dynamic = is_dynamic_type(ty);
        let is_array = is_array_type(ty);

        if is_struct {
            // Nested struct: copy all its words into consecutive slots
            quote! {
                {
                    let nested_words = self.#name.to_evm_words()?;
                    for (i, word) in nested_words.iter().enumerate() {
                        result[#packing::#slot_const + i] = *word;
                    }
                }
            }
        } else if is_dynamic {
            // Dynamic type: copy its single word into the appropriate slot
            quote! {
                {
                    let dynamic_words = self.#name.to_evm_words()?;
                    result[#packing::#slot_const] = dynamic_words[0];
                }
            }
        } else if is_array {
            // Array: copy all its words into consecutive slots
            quote! {
                {
                    let array_words = self.#name.to_evm_words()?;
                    for (i, word) in array_words.iter().enumerate() {
                        result[#packing::#slot_const + i] = *word;
                    }
                }
            }
        } else {
            // Primitive: pack into slot using packing module
            quote! {
                {
                    // Use packing module to insert packed value
                    result[#packing::#slot_const] = crate::storage::packing::insert_packed_value(
                        result[#packing::#slot_const],
                        &self.#name,
                        #packing::#offset_const,
                        #packing::#bytes_const
                    )?;
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
fn gen_from_evm_words_impl(fields: &[(&Ident, &Type)], packing: &Ident) -> TokenStream {
    let decode_fields = fields.iter().enumerate().map(|(idx, (name, ty))| {
        let slot_const = Ident::new(&format!("FIELD_{idx}_SLOT"), proc_macro2::Span::call_site());
        let offset_const = Ident::new(
            &format!("FIELD_{idx}_OFFSET"),
            proc_macro2::Span::call_site(),
        );
        let bytes_const = Ident::new(
            &format!("FIELD_{idx}_BYTES"),
            proc_macro2::Span::call_site(),
        );

        let is_struct = is_custom_struct(ty);
        let is_dynamic = is_dynamic_type(ty);
        let is_array = is_array_type(ty);

        if is_struct {
            // Nested struct: extract consecutive words and convert to array
            quote! {
                let #name = {
                    // Extract slice and convert to fixed-size array using std::array::from_fn
                    let start = #packing::#slot_const;
                    let nested_words = ::std::array::from_fn::<_, {<#ty>::SLOT_COUNT}, _>(|i| {
                        words[start + i]
                    });
                    <#ty>::from_evm_words(nested_words)?
                };
            }
        } else if is_dynamic {
            // Dynamic type: extract its single word
            quote! {
                let #name = {
                    let word = words[#packing::#slot_const];
                    <#ty>::from_evm_words([word])?
                };
            }
        } else if is_array {
            // Array: extract consecutive words and convert to array
            quote! {
                let #name = {
                    // Extract slice and convert to fixed-size array using std::array::from_fn
                    // The slot count is computed from the array's BYTE_COUNT
                    let start = #packing::#slot_const;
                    let array_slot_count = #packing::#bytes_const.div_ceil(32);
                    let array_words = ::std::array::from_fn(|i| {
                        if i < array_slot_count {
                            words[start + i]
                        } else {
                            ::alloy::primitives::U256::ZERO
                        }
                    });
                    <#ty>::from_evm_words(array_words)?
                };
            }
        } else {
            // Primitive: extract from packed position using packing module
            quote! {
                let #name = {
                    // Use packing module to extract packed value
                    let word = words[#packing::#slot_const];
                    crate::storage::packing::extract_packed_value::<#ty>(
                        word,
                        #packing::#offset_const,
                        #packing::#bytes_const
                    )?
                };
            }
        }
    });

    quote! {
        #(#decode_fields)*
    }
}
