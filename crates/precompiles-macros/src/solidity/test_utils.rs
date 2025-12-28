//! Shared test utilities for the solidity module.

use proc_macro2::Span;
use quote::format_ident;
use syn::{Type, Visibility};

use super::parser::{FieldDef, SolStructDef, SolidityModule, UnitEnumDef};

pub(super) fn make_field(name: &str, ty: Type) -> FieldDef {
    FieldDef {
        name: format_ident!("{}", name),
        ty,
        indexed: false,
        vis: Visibility::Public(syn::token::Pub {
            span: Span::call_site(),
        }),
    }
}

pub(super) fn make_struct(name: &str, fields: Vec<FieldDef>) -> SolStructDef {
    SolStructDef {
        name: format_ident!("{}", name),
        fields,
        derives: vec![],
        attrs: vec![],
        vis: Visibility::Public(syn::token::Pub {
            span: Span::call_site(),
        }),
    }
}

pub(super) fn make_unit_enum(name: &str, variants: Vec<&str>) -> UnitEnumDef {
    UnitEnumDef {
        name: format_ident!("{}", name),
        variants: variants.iter().map(|v| format_ident!("{}", v)).collect(),
        attrs: vec![],
        vis: Visibility::Public(syn::token::Pub {
            span: Span::call_site(),
        }),
    }
}

pub(super) fn empty_module() -> SolidityModule {
    SolidityModule {
        name: format_ident!("test"),
        vis: Visibility::Public(syn::token::Pub {
            span: Span::call_site(),
        }),
        imports: vec![],
        structs: vec![],
        unit_enums: vec![],
        error: None,
        event: None,
        interface: None,
        other_items: vec![],
    }
}
