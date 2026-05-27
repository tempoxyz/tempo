use crate::{
    FieldKind,
    packing::{self, LayoutField, PackingConstants, SlotAssignment},
};
use alloy::primitives::{U256, keccak256};
use proc_macro2::Span;
use quote::{format_ident, quote};
use std::{fs, path::PathBuf};
use syn::{Expr, Ident, LitStr, Visibility};

/// Generates a public handler field declaration for a storage field
pub(crate) fn gen_handler_field_decl(field: &LayoutField<'_>) -> proc_macro2::TokenStream {
    let field_name = field.name;
    let ty = field.ty;
    let handler_type = match &field.kind {
        FieldKind::Direct(ty) => {
            quote! { <#ty as crate::storage::StorableType>::Handler }
        }
        FieldKind::Mapping { .. } => {
            quote! { <#ty as crate::storage::StorableType>::Handler }
        }
    };

    quote! {
        pub #field_name: #handler_type
    }
}

/// Generates handler field initialization expression
///
/// # Parameters
/// - `field`: the field to initialize
/// - `field_idx`: the field's index in the allocated fields array
/// - `all_fields`: all allocated fields (for neighbor slot detection)
/// - `packing_mod`: optional packing module identifier
///   - `None` = contract storage (uses `slots` module)
///   - `Some(mod_ident)` = storable struct (uses packing module, offsets from `base_slot`)
pub(crate) fn gen_handler_field_init(
    field: &LayoutField<'_>,
    field_idx: usize,
    all_fields: &[LayoutField<'_>],
    packing_mod: Option<&Ident>,
) -> proc_macro2::TokenStream {
    let field_name = field.name;
    let ty = field.ty;
    let consts = PackingConstants::new(field_name);
    let (loc_const, (slot_const, offset_const)) = (consts.location(), consts.into_tuple());

    let is_contract = packing_mod.is_none();

    // Create slots_module identifier based on context
    let slots_mod = format_ident!("slots");
    let const_mod = packing_mod.unwrap_or(&slots_mod);

    // Calculate `Slot` based on context
    let slot_expr = if is_contract {
        quote! { #const_mod::#slot_const }
    } else {
        quote! { base_slot.saturating_add(::alloy::primitives::U256::from_limbs([#const_mod::#loc_const.offset_slots as u64, 0, 0, 0])) }
    };

    match &field.kind {
        FieldKind::Direct(ty) => {
            // Calculate neighbor slot references for packing detection
            let (prev_slot_const_ref, next_slot_const_ref) = packing::get_neighbor_slot_refs(
                field_idx,
                all_fields,
                const_mod,
                |f| f.name,
                is_contract,
            );

            // Calculate `LayoutCtx` based on context
            let layout_ctx = if is_contract {
                packing::gen_layout_ctx_expr(
                    ty,
                    matches!(field.assigned_slot, SlotAssignment::Manual(_)),
                    quote! { #const_mod::#slot_const },
                    quote! { #const_mod::#offset_const },
                    prev_slot_const_ref,
                    next_slot_const_ref,
                )
            } else {
                packing::gen_layout_ctx_expr(
                    ty,
                    false, // storable fields are always auto-allocated
                    quote! { #const_mod::#loc_const.offset_slots },
                    quote! { #const_mod::#loc_const.offset_bytes },
                    prev_slot_const_ref,
                    next_slot_const_ref,
                )
            };

            quote! {
                #field_name: <#ty as crate::storage::StorableType>::handle(
                    #slot_expr, #layout_ctx, address
                )
            }
        }
        FieldKind::Mapping {
            key,
            precomputed_range,
            ..
        } => {
            if let Some(precomputed_range) = precomputed_range
                && is_contract
            {
                let precomputed_slots = precomputed_slots_ident(field_name);
                let key_to_index = precomputed_key_index_ident(field_name);
                let min = precomputed_range.min as usize;

                quote! {
                    #field_name: <#ty>::new_with_precomputed_slots(
                        #slot_expr,
                        address,
                        crate::storage::PrecomputedMappingSlots::<#key>::new(
                            #min,
                            &slots::#precomputed_slots,
                            slots::#key_to_index,
                        ),
                    )
                }
            } else {
                quote! {
                    #field_name: <#ty as crate::storage::StorableType>::handle(
                        #slot_expr, crate::storage::LayoutCtx::FULL, address
                    )
                }
            }
        }
    }
}

/// Generate the transformed struct with handler fields
pub(crate) fn gen_struct(
    name: &Ident,
    vis: &Visibility,
    allocated_fields: &[LayoutField<'_>],
) -> proc_macro2::TokenStream {
    // Generate handler field for each storage variable
    let handler_fields = allocated_fields.iter().map(gen_handler_field_decl);

    quote! {
        #vis struct #name {
            #(#handler_fields,)*
            address: ::alloy::primitives::Address,
            storage: crate::storage::StorageCtx,
        }
    }
}

/// Generate the constructor method
pub(crate) fn gen_constructor(
    name: &Ident,
    allocated_fields: &[LayoutField<'_>],
    address: Option<&Expr>,
) -> proc_macro2::TokenStream {
    // Generate handler initializations for each field using the shared helper
    let field_inits = allocated_fields
        .iter()
        .enumerate()
        .map(|(idx, field)| gen_handler_field_init(field, idx, allocated_fields, None));

    // Generate `pub fn new()` when address is provided
    let new_fn = address.map(|addr| {
        quote! {
            /// Creates an instance of the precompile.
            ///
            /// Caution: This does not initialize the account, see [`Self::initialize`].
            pub fn new() -> Self {
                Self::__new(#addr)
            }
        }
    });

    quote! {
        impl #name {
            #new_fn

            #[inline(always)]
            fn __new(address: ::alloy::primitives::Address) -> Self {
                // Run collision detection checks in debug builds
                #[cfg(debug_assertions)]
                {
                    slots::__check_all_collisions();
                }

                Self {
                    #(#field_inits,)*
                    address,
                    storage: crate::storage::StorageCtx::default(),
                }
            }

            #[inline(always)]
            fn __initialize(&mut self) -> crate::error::Result<()> {
                let bytecode = ::revm::state::Bytecode::new_legacy(::alloy::primitives::Bytes::from_static(&[0xef]));
                self.storage.set_code(self.address, bytecode)?;

                Ok(())
            }

            #[inline(always)]
            fn emit_event(&mut self, event: impl ::alloy::primitives::IntoLogData) -> crate::error::Result<()> {
                self.storage.emit_event(self.address, event.into_log_data())
            }

            #[cfg(any(test, feature = "test-utils"))]
            pub fn emitted_events(&self) -> &Vec<::alloy::primitives::LogData> {
                self.storage.get_events(self.address)
            }

            #[cfg(any(test, feature = "test-utils"))]
            pub fn clear_emitted_events(&mut self) {
                self.storage.clear_events(self.address);
            }

            #[cfg(any(test, feature = "test-utils"))]
            pub fn assert_emitted_events(&self, expected: Vec<impl ::alloy::primitives::IntoLogData>) {
                let emitted = self.storage.get_events(self.address);
                assert_eq!(emitted.len(), expected.len());

                for (i, event) in expected.into_iter().enumerate() {
                    assert_eq!(emitted[i], event.into_log_data());
                }
            }
        }
    }
}

/// Generate the `trait ContractStorage` implementation
pub(crate) fn gen_contract_storage_impl(name: &Ident) -> proc_macro2::TokenStream {
    quote! {
        impl crate::storage::ContractStorage for #name {
            #[inline(always)]
            fn address(&self) -> ::alloy::primitives::Address {
                self.address
            }

            #[inline(always)]
            fn storage(&self) -> &crate::storage::StorageCtx {
                &self.storage
            }

            #[inline(always)]
            fn storage_mut(&mut self) -> &mut crate::storage::StorageCtx {
                &mut self.storage
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
    let precomputed_mapping_slots = gen_precomputed_mapping_slots(allocated_fields);
    let collision_checks = gen_collision_checks(allocated_fields);

    quote! {
        pub mod slots {
            use super::*;

            #constants
            #precomputed_mapping_slots
            #collision_checks
        }
    }
}

fn precomputed_slots_ident(field_name: &Ident) -> Ident {
    format_ident!("__{}_PRECOMPUTED_SLOTS", packing::const_name(field_name))
}

fn precomputed_key_index_ident(field_name: &Ident) -> Ident {
    format_ident!("__{}_precomputed_key_index", field_name)
}

fn gen_precomputed_mapping_slots(allocated_fields: &[LayoutField<'_>]) -> proc_macro2::TokenStream {
    let mut generated = proc_macro2::TokenStream::new();

    for field in allocated_fields {
        let FieldKind::Mapping {
            key,
            precomputed_range: Some(precomputed_range),
            ..
        } = &field.kind
        else {
            continue;
        };

        let slots_ident = precomputed_slots_ident(field.name);
        let key_to_index_ident = precomputed_key_index_ident(field.name);
        let path_lit = match write_precomputed_mapping_slots(field, *precomputed_range) {
            Ok(path_lit) => path_lit,
            Err(err) => {
                generated.extend(err.to_compile_error());
                continue;
            }
        };

        generated.extend(quote! {
            pub(super) static #slots_ident: &[u8] = include_bytes!(#path_lit);

            #[inline(always)]
            pub(super) fn #key_to_index_ident(key: &#key) -> Option<usize> {
                usize::try_from(*key).ok()
            }
        });
    }

    generated
}

fn write_precomputed_mapping_slots(
    field: &LayoutField<'_>,
    range: crate::utils::PrecomputedKeyRange,
) -> syn::Result<LitStr> {
    let SlotAssignment::Manual(base_slot) = &field.assigned_slot else {
        return Err(syn::Error::new_spanned(
            field.name,
            "precomputed Mapping ranges require an explicit `#[slot(N)]` so the macro can embed the final mapping slots",
        ));
    };

    let out_dir = precomputed_output_dir()?;
    fs::create_dir_all(&out_dir).map_err(|err| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to create precomputed Mapping output directory: {err}"),
        )
    })?;

    let file_name = precomputed_slots_file_name(field.name, range, *base_slot);
    let path = out_dir.join(file_name);
    let bytes = precompute_u32_mapping_slot_bytes(*base_slot, range);
    fs::write(&path, bytes).map_err(|err| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to write precomputed Mapping slots: {err}"),
        )
    })?;

    let path = path.to_str().ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "precomputed Mapping slots path is not valid UTF-8",
        )
    })?;

    Ok(LitStr::new(path, Span::call_site()))
}

fn precomputed_output_dir() -> syn::Result<PathBuf> {
    if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return Ok(PathBuf::from(target_dir).join("tempo-precomputed-mapping-slots"));
    }

    if let Ok(current_dir) = std::env::current_dir() {
        return Ok(current_dir
            .join("target")
            .join("tempo-precomputed-mapping-slots"));
    }

    if let Some(manifest_dir) = std::env::var_os("CARGO_MANIFEST_DIR") {
        return Ok(PathBuf::from(manifest_dir)
            .join("target")
            .join("tempo-precomputed-mapping-slots"));
    }

    Ok(std::env::temp_dir().join("tempo-precomputed-mapping-slots"))
}

fn precomputed_slots_file_name(
    field_name: &Ident,
    range: crate::utils::PrecomputedKeyRange,
    base_slot: U256,
) -> String {
    let limbs = base_slot.as_limbs();
    format!(
        "tempo_precomputed_mapping_slots_{}_{}_{}_{}_{}_{}_{}.bin",
        field_name, range.min, range.max, limbs[0], limbs[1], limbs[2], limbs[3],
    )
}

fn precompute_u32_mapping_slot_bytes(
    base_slot: U256,
    range: crate::utils::PrecomputedKeyRange,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(range.len() * 32);
    let base_slot = base_slot.to_be_bytes::<32>();

    for key in range.min..range.max {
        let mut input = [0u8; 64];
        input[28..32].copy_from_slice(&key.to_be_bytes());
        input[32..].copy_from_slice(&base_slot);
        bytes.extend_from_slice(keccak256(input).as_slice());
    }

    bytes
}

/// Generate collision check functions for all fields
fn gen_collision_checks(allocated_fields: &[LayoutField<'_>]) -> proc_macro2::TokenStream {
    let mut generated = proc_macro2::TokenStream::new();
    let mut check_fn_calls = Vec::new();

    // Generate collision detection check functions for all fields
    for (idx, allocated) in allocated_fields.iter().enumerate() {
        let (check_fn_name, check_fn) =
            packing::gen_collision_check_fn(idx, allocated, allocated_fields);
        generated.extend(check_fn);
        check_fn_calls.push(check_fn_name);
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

/// Generate a `Default` implementation that calls `Self::new()`.
///
/// This is used when `#[contract(Default)]` is specified.
pub(crate) fn gen_default_impl(name: &Ident) -> proc_macro2::TokenStream {
    quote! {
        impl ::core::default::Default for #name {
            fn default() -> Self {
                Self::new()
            }
        }
    }
}
