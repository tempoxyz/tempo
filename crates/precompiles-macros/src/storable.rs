//! Implementation of the `#[derive(Storable)]` macro.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, Ident, Type};

use crate::utils::{is_custom_struct, normalize_to_snake_case};

/// Implements the `Storable` derive macro for a struct with slot packing.
///
/// This macro packs fields into storage slots based on their byte sizes.
/// Fields are placed sequentially in slots, moving to a new slot when
/// the current slot cannot fit the next field (no spanning across slots).
pub(crate) fn derive_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    // Extract struct name and generics
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

    // Calculate last field index for BYTE_COUNT calculation
    let last_field_idx = field_infos.len() - 1;
    let last_field_offset = Ident::new(
        &format!("FIELD_{last_field_idx}_OFFSET"),
        proc_macro2::Span::call_site(),
    );
    let last_field_bytes = Ident::new(
        &format!("FIELD_{last_field_idx}_BYTES"),
        proc_macro2::Span::call_site(),
    );

    // Generate the trait implementations
    let expanded = quote! {
        #packing_module

        // impl `StorableType` for byte count access
        impl #impl_generics crate::storage::StorableType for #strukt #ty_generics #where_clause {
            const BYTE_COUNT: usize = 32 * (#mod_ident::SLOT_COUNT - 1) + #mod_ident::#last_field_offset + #mod_ident::#last_field_bytes;
        }

        // add SLOT_COUNT as an associated const for convenient access
        impl #impl_generics #strukt #ty_generics #where_clause {
            pub const SLOT_COUNT: usize = #mod_ident::SLOT_COUNT;
        }

        // impl `Storable` with const generic for slot count
        impl #impl_generics crate::storage::Storable<{ #mod_ident::SLOT_COUNT }> for #strukt #ty_generics #where_clause {
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

    Ok(expanded)
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
            } else {
                // Previous field was primitive - continue from its end position
                quote! {
                    const PREV_SLOT: usize = #prev_slot;
                    const PREV_OFFSET: usize = #prev_offset + #prev_bytes;
                }
            }
        };

        // Check if current field is a struct (Solidity rule: structs always start new slots)
        let is_struct = is_custom_struct(ty);

        if is_struct {
            // Struct field: must start on a new slot if PREV_OFFSET != 0
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
            // Primitive field: use standard packing logic
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

        let is_struct = is_custom_struct(ty);

        // Struct fields always use load() directly (never packed)
        if is_struct {
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
                    // Extract bytes
                    let slot_value = storage.sload(
                        base_slot + ::alloy::primitives::U256::from(#packing::#slot_const)
                    )?;
                    let shift_bits = (32 - #packing::#offset_const - #packing::#bytes_const) * 8;
                    let mask = if #packing::#bytes_const == 32 {
                        ::alloy::primitives::U256::MAX
                    } else {
                        (::alloy::primitives::U256::from(1) << (#packing::#bytes_const * 8))
                            - ::alloy::primitives::U256::from(1)
                    };
                    let extracted = (slot_value >> shift_bits) & mask;

                    // Decode from the extracted right-aligned value
                    <#ty>::from_evm_words([extracted])?
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

        let is_struct = is_custom_struct(ty);

        // Struct fields always use store() directly (never packed)
        if is_struct {
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
                    // Encode field to its canonical right-aligned U256 representation
                    let field_value = self.#name.to_evm_words()?[0];
                    let shift_bits = (32 - #packing::#offset_const - #packing::#bytes_const) * 8;
                    let mask = if #packing::#bytes_const == 32 {
                        ::alloy::primitives::U256::MAX
                    } else {
                        (::alloy::primitives::U256::from(1) << (#packing::#bytes_const * 8))
                            - ::alloy::primitives::U256::from(1)
                    };

                    // Read current slot value
                    let current = storage.sload(target_slot)?;

                    // Clear the bits for this field
                    let clear_mask = !(mask << shift_bits);
                    let cleared = current & clear_mask;

                    // Insert new value
                    let positioned = (field_value & mask) << shift_bits;
                    let new_value = cleared | positioned;

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
        } else {
            // Primitive: pack into slot with shifting/masking
            quote! {
                {
                    // Encode field to its canonical right-aligned U256 representation
                    let field_value = self.#name.to_evm_words()?[0];

                    let shift_bits = (32 - #packing::#offset_const - #packing::#bytes_const) * 8;
                    let mask = if #packing::#bytes_const == 32 {
                        ::alloy::primitives::U256::MAX
                    } else {
                        (::alloy::primitives::U256::from(1) << (#packing::#bytes_const * 8))
                            - ::alloy::primitives::U256::from(1)
                    };

                    // Position the field value and accumulate into the appropriate slot
                    let positioned = (field_value & mask) << shift_bits;
                    result[#packing::#slot_const] |= positioned;
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
        } else {
            // Primitive: extract from packed position
            quote! {
                let #name = {
                    // Get the word for this field's slot
                    let word = words[#packing::#slot_const];

                    // Extract the field from the word using bit shifting and masking
                    let shift_bits = (32 - #packing::#offset_const - #packing::#bytes_const) * 8;
                    let mask = if #packing::#bytes_const == 32 {
                        ::alloy::primitives::U256::MAX
                    } else {
                        (::alloy::primitives::U256::from(1) << (#packing::#bytes_const * 8))
                            - ::alloy::primitives::U256::from(1)
                    };
                    let extracted = (word >> shift_bits) & mask;

                    // Decode from the extracted right-aligned value
                    <#ty>::from_evm_words([extracted])?
                };
            }
        }
    });

    quote! {
        #(#decode_fields)*
    }
}
