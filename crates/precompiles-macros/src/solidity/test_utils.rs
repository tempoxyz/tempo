//! Shared test utilities for the solidity module.

use proc_macro2::{Ident, Span};
use quote::format_ident;
use syn::{Type, Visibility};

use super::parser::{
    EnumVariantDef, FieldDef, InterfaceDef, MethodDef, SolEnumDef, SolStructDef, SolidityModule,
    UnitEnumDef,
};

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
        interfaces: vec![],
        other_items: vec![],
    }
}

pub(super) fn make_method(name: &str, params: Vec<(Ident, Type)>) -> MethodDef {
    MethodDef {
        name: format_ident!("{}", name),
        sol_name: name.to_string(),
        params,
        return_type: None,
        is_mutable: false,
    }
}

pub(super) fn make_error_enum(variants: Vec<EnumVariantDef>) -> SolEnumDef {
    SolEnumDef {
        name: format_ident!("Error"),
        variants,
        attrs: vec![],
        vis: Visibility::Public(syn::token::Pub {
            span: Span::call_site(),
        }),
    }
}

pub(super) fn make_variant(name: &str, fields: Vec<FieldDef>) -> EnumVariantDef {
    EnumVariantDef {
        name: format_ident!("{}", name),
        fields,
    }
}

pub(super) fn make_interface(name: &str, methods: Vec<MethodDef>) -> InterfaceDef {
    InterfaceDef {
        name: format_ident!("{}", name),
        methods,
        attrs: vec![],
        vis: Visibility::Public(syn::token::Pub {
            span: Span::call_site(),
        }),
    }
}
