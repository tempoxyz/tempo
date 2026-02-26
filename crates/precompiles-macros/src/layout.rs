use crate::{
    FieldKind,
    packing::{self, LayoutField, PackingConstants, SlotAssignment},
};
use quote::{format_ident, quote};
use syn::{Expr, Ident, Visibility};

/// Generates a public handler field declaration for a storage field
pub(crate) fn gen_handler_field_decl(field: &LayoutField<'_>) -> proc_macro2::TokenStream {
    let field_name = field.name;
    let handler_type = match (&field.kind, field.transient) {
        (FieldKind::Direct(ty), false) => {
            quote! { <#ty as crate::storage::StorableType>::Handler }
        }
        (FieldKind::Direct(ty), true) => {
            quote! { crate::storage::Slot<#ty, crate::storage::Transient> }
        }
        (FieldKind::Mapping { key, value }, false) => {
            quote! { <crate::storage::Mapping<#key, #value> as crate::storage::StorableType>::Handler }
        }
        (FieldKind::Mapping { key, value }, true) => {
            quote! { crate::storage::Mapping<#key, #value, crate::storage::Transient> }
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
    let consts = PackingConstants::new(field_name);
    let (loc_const, (slot_const, offset_const)) = (consts.location(), consts.into_tuple());

    let is_contract = packing_mod.is_none();

    // For contract-level fields, transient fields reference transient_slots:: module
    let slots_mod = if field.transient {
        format_ident!("transient_slots")
    } else {
        format_ident!("slots")
    };
    let const_mod = packing_mod.unwrap_or(&slots_mod);

    // Calculate `Slot` based on context
    let slot_expr = if is_contract {
        quote! { #const_mod::#slot_const }
    } else {
        quote! { base_slot.saturating_add(::alloy::primitives::U256::from_limbs([#const_mod::#loc_const.offset_slots as u64, 0, 0, 0])) }
    };

    // For transient fields at contract level, use direct construction
    if field.transient && is_contract {
        return match &field.kind {
            FieldKind::Direct(ty) => {
                let (prev_slot_const_ref, next_slot_const_ref) = packing::get_neighbor_slot_refs(
                    field_idx,
                    all_fields,
                    const_mod,
                    |f| f.name,
                    is_contract,
                );

                let layout_ctx = packing::gen_layout_ctx_expr(
                    ty,
                    matches!(field.assigned_slot, SlotAssignment::Manual(_)),
                    quote! { #const_mod::#slot_const },
                    quote! { #const_mod::#offset_const },
                    prev_slot_const_ref,
                    next_slot_const_ref,
                );

                quote! {
                    #field_name: crate::storage::Slot::new_with_ctx(
                        #slot_expr, #layout_ctx, address
                    )
                }
            }
            FieldKind::Mapping { key, value } => {
                quote! {
                    #field_name: crate::storage::Mapping::<#key, #value, crate::storage::Transient>::new(
                        #slot_expr, address
                    )
                }
            }
        };
    }

    // Persistent field (existing logic)
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
        FieldKind::Mapping { key, value } => {
            quote! {
                #field_name: <crate::storage::Mapping<#key, #value> as crate::storage::StorableType>::handle(
                    #slot_expr, crate::storage::LayoutCtx::FULL, address
                )
            }
        }
    }
}

/// Generate the transformed struct with handler fields
pub(crate) fn gen_struct(
    name: &Ident,
    vis: &Visibility,
    persistent_fields: &[LayoutField<'_>],
    transient_fields: &[LayoutField<'_>],
) -> proc_macro2::TokenStream {
    let handler_fields = persistent_fields.iter().map(gen_handler_field_decl);
    let transient_handler_fields = transient_fields.iter().map(gen_handler_field_decl);

    quote! {
        #vis struct #name {
            #(#handler_fields,)*
            #(#transient_handler_fields,)*
            address: ::alloy::primitives::Address,
            storage: crate::storage::StorageCtx,
        }
    }
}

/// Generate the constructor method
pub(crate) fn gen_constructor(
    name: &Ident,
    persistent_fields: &[LayoutField<'_>],
    transient_fields: &[LayoutField<'_>],
    address: Option<&Expr>,
) -> proc_macro2::TokenStream {
    // Generate handler initializations for each field using the shared helper
    let persistent_field_inits = persistent_fields
        .iter()
        .enumerate()
        .map(|(idx, field)| gen_handler_field_init(field, idx, persistent_fields, None));

    let transient_field_inits = transient_fields
        .iter()
        .enumerate()
        .map(|(idx, field)| gen_handler_field_init(field, idx, transient_fields, None));

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

    // Only generate collision check calls for non-empty modules
    let persistent_check = if !persistent_fields.is_empty() {
        quote! { slots::__check_all_collisions(); }
    } else {
        quote! {}
    };
    let transient_check = if !transient_fields.is_empty() {
        quote! { transient_slots::__check_all_collisions(); }
    } else {
        quote! {}
    };

    quote! {
        impl #name {
            #new_fn

            #[inline(always)]
            fn __new(address: ::alloy::primitives::Address) -> Self {
                // Run collision detection checks in debug builds
                #[cfg(debug_assertions)]
                {
                    #persistent_check
                    #transient_check
                }

                Self {
                    #(#persistent_field_inits,)*
                    #(#transient_field_inits,)*
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

/// Generate the `slots` and `transient_slots` modules with constants and collision checks
pub(crate) fn gen_slots_modules(
    persistent_fields: &[LayoutField<'_>],
    transient_fields: &[LayoutField<'_>],
) -> proc_macro2::TokenStream {
    // Generate persistent slots module
    let persistent_constants = if !persistent_fields.is_empty() {
        packing::gen_constants_from_ir(persistent_fields, false)
    } else {
        proc_macro2::TokenStream::new()
    };
    let persistent_collision_checks = if !persistent_fields.is_empty() {
        gen_collision_checks(persistent_fields)
    } else {
        quote! {
            #[cfg(debug_assertions)]
            #[inline(always)]
            pub(super) fn __check_all_collisions() {}
        }
    };

    // Generate transient slots module
    let transient_constants = if !transient_fields.is_empty() {
        packing::gen_constants_from_ir(transient_fields, false)
    } else {
        proc_macro2::TokenStream::new()
    };
    let transient_collision_checks = if !transient_fields.is_empty() {
        gen_collision_checks(transient_fields)
    } else {
        quote! {
            #[cfg(debug_assertions)]
            #[inline(always)]
            pub(super) fn __check_all_collisions() {}
        }
    };

    quote! {
        pub mod slots {
            use super::*;
            #persistent_constants
            #persistent_collision_checks
        }

        pub mod transient_slots {
            use super::*;
            #transient_constants
            #transient_collision_checks
        }
    }
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
