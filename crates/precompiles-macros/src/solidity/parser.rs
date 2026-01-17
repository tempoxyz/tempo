//! Parser for `#[abi]` module macro.
//!
//! Parses a Rust module decorated with `#[abi]` into a structured intermediate
//! representation (IR) suitable for code generation.
//!
//! # Naming Conventions
//!
//! - Structs generate `SolStruct`, `SolType`, `SolValue`, `EventTopic`.
//! - Trait `Interface` generates `SolCall` structs + `SolInterface` enum.
//! - Enum `Error` generates `SolError` structs + `SolInterface` enum.
//! - Enum `Event` generates `SolEvent` structs + `IntoLogData` enum.
//! - Other enums, which must be unit enums, are encoded as u8.

use crate::utils::to_camel_case;
use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{
    Attribute, Expr, Fields, FnArg, GenericArgument, Item, ItemConst, ItemEnum, ItemMod,
    ItemStatic, ItemStruct, ItemTrait, ItemUse, Meta, MetaList, Pat, Path, PathArguments,
    ReturnType, Signature, Token, TraitItem, Type, Visibility, punctuated::Punctuated,
};

/// Trait for types that expose a list of (name, type) pairs.
pub(super) trait FieldAccessors {
    /// Returns an iterator over (name, type) pairs.
    fn fields(&self) -> impl Iterator<Item = (&Ident, &Type)>;

    /// Returns the identifier of the type.
    fn name(&self) -> &Ident;

    /// Extract field/param names as a Vec of Idents.
    fn field_names(&self) -> Vec<Ident> {
        self.fields().map(|(n, _)| n.clone()).collect()
    }

    /// Extract raw syn Types.
    fn field_raw_types(&self) -> Vec<Type> {
        self.fields().map(|(_, ty)| ty.clone()).collect()
    }

    /// Extract field/param types as quoted TokenStreams.
    fn field_types(&self) -> Vec<TokenStream> {
        self.fields().map(|(_, ty)| quote! { #ty }).collect()
    }

    /// Generate comma-separated Solidity params: "type1 name1, type2 name2"
    fn as_solidity_params(&self) -> syn::Result<String> {
        self.fields()
            .map(|(name, ty)| {
                let sol_name = super::common::SynSolType::parse(ty)?.sol_name();
                Ok(format!("{sol_name} {name}"))
            })
            .collect::<syn::Result<Vec<_>>>()
            .map(|v| v.join(", "))
    }

    /// Generate Solidity declaration.
    fn solidity_decl(&self, kind: &str) -> Option<String> {
        let params = self.as_solidity_params().ok()?;
        Some(format!("{} {}({});", kind, self.name(), params))
    }
}

/// Parsed content of a `#[abi]` module.
#[derive(Debug)]
pub(super) struct SolidityModule {
    /// Module name
    pub name: Ident,
    /// Module visibility
    pub vis: Visibility,
    /// Use statements to preserve
    pub imports: Vec<ItemUse>,
    /// Struct definitions
    pub structs: Vec<SolStructDef>,
    /// Unit enums (non-Error/Event enums, encoded as u8)
    pub unit_enums: Vec<UnitEnumDef>,
    /// Error enum (optional, must be named `Error`)
    pub error: Option<SolEnumDef>,
    /// Event enum (optional, must be named `Event`)
    pub event: Option<SolEnumDef>,
    /// Interface traits (any trait becomes an interface)
    pub interfaces: Vec<InterfaceDef>,
    /// Constants (const and static items, exposed as view functions)
    pub constants: Vec<ConstantDef>,
    /// Other items passed through unchanged
    pub other_items: Vec<Item>,
}

impl SolidityModule {
    /// Parse a module decorated with `#[abi]` into IR.
    pub(super) fn parse(item: ItemMod) -> syn::Result<Self> {
        let name = item.ident.clone();
        let vis = item.vis.clone();

        let content = item
            .content
            .as_ref()
            .ok_or_else(|| syn::Error::new_spanned(&item, "#[abi] requires a module with body"))?;

        let mut imports = Vec::new();
        let mut structs = Vec::new();
        let mut unit_enums = Vec::new();
        let mut error: Option<SolEnumDef> = None;
        let mut event: Option<SolEnumDef> = None;
        let mut interfaces = Vec::new();
        let mut constants = Vec::new();
        let mut other_items = Vec::new();

        for item in &content.1 {
            match item {
                Item::Use(use_item) => {
                    imports.push(use_item.clone());
                }
                Item::Struct(struct_item) => {
                    structs.push(SolStructDef::parse(struct_item)?);
                }
                Item::Enum(enum_item) => {
                    let enum_name = enum_item.ident.to_string();
                    match enum_name.as_str() {
                        "Error" => {
                            if error.is_some() {
                                return Err(syn::Error::new_spanned(
                                    enum_item,
                                    "duplicate `Error` enum",
                                ));
                            }
                            error = Some(SolEnumDef::parse(enum_item, SolEnumKind::Error)?);
                        }
                        "Event" => {
                            if event.is_some() {
                                return Err(syn::Error::new_spanned(
                                    enum_item,
                                    "duplicate `Event` enum",
                                ));
                            }
                            event = Some(SolEnumDef::parse(enum_item, SolEnumKind::Event)?);
                        }
                        _ => {
                            unit_enums.push(UnitEnumDef::parse(enum_item)?);
                        }
                    }
                }
                Item::Trait(trait_item) => {
                    interfaces.push(InterfaceDef::parse(trait_item)?);
                }
                Item::Const(const_item) => {
                    constants.push(ConstantDef::from_const(const_item)?);
                }
                Item::Static(static_item) => {
                    constants.push(ConstantDef::from_static(static_item)?);
                }
                _ => {
                    other_items.push(item.clone());
                }
            }
        }

        Ok(Self {
            name,
            vis,
            imports,
            structs,
            unit_enums,
            error,
            event,
            interfaces,
            constants,
            other_items,
        })
    }
}

/// Struct definition for SolStruct generation.
///
/// # Invariants
///
/// - Only named fields supported (no tuple or unit structs)
/// - Field types must be valid `SolType` values or registered structs/unit enums
/// - Generics are not supported
/// - The original struct is re-emitted (not passed through verbatim)
#[derive(Debug, Clone)]
pub(super) struct SolStructDef {
    /// Struct name
    pub name: Ident,
    /// Fields with their types
    pub fields: Vec<FieldDef>,
    /// Original derive attributes to preserve (with `Storable` filtered out)
    pub derives: Vec<Attribute>,
    /// Other attributes to preserve
    pub attrs: Vec<Attribute>,
    /// Visibility
    pub vis: Visibility,
    /// Whether the struct had `#[derive(Storable)]` (to emit cfg_attr gated derive)
    pub has_storable: bool,
}

impl SolStructDef {
    fn parse(item: &ItemStruct) -> syn::Result<Self> {
        check_generics(&item.generics)?;

        let Fields::Named(named) = &item.fields else {
            return Err(syn::Error::new_spanned(
                item,
                "only structs with named fields are supported in #[abi] modules",
            ));
        };

        let fields = named
            .named
            .iter()
            .map(|f| {
                let name = f
                    .ident
                    .clone()
                    .ok_or_else(|| syn::Error::new_spanned(f, "expected named field"))?;
                Ok(FieldDef {
                    name,
                    ty: f.ty.clone(),
                    indexed: false,
                    vis: f.vis.clone(),
                })
            })
            .collect::<syn::Result<Vec<_>>>()?;

        let (derives, other_attrs, has_storable) = extract_derive_attrs(&item.attrs);

        Ok(Self {
            name: item.ident.clone(),
            fields,
            derives,
            attrs: other_attrs,
            vis: item.vis.clone(),
            has_storable,
        })
    }
}

impl FieldAccessors for SolStructDef {
    fn fields(&self) -> impl Iterator<Item = (&Ident, &Type)> {
        self.fields.iter().map(|f| (&f.name, &f.ty))
    }

    fn name(&self) -> &Ident {
        &self.name
    }
}

/// Field definition.
#[derive(Debug, Clone)]
pub(super) struct FieldDef {
    /// Field name
    pub name: Ident,
    /// Field type
    pub ty: Type,
    /// Whether this field is indexed (for events)
    pub indexed: bool,
    /// Field visibility
    pub vis: Visibility,
}

/// Constant definition (const or static items exposed as view functions).
///
/// # Invariants
///
/// - Must be a `const` or `static` item
/// - For `static` items with `LazyLock<T>`, the inner type `T` is used
/// - The type must be a valid Solidity ABI type
#[derive(Debug, Clone)]
pub(super) struct ConstantDef {
    /// Original constant name (e.g., `PAUSE_ROLE`)
    pub name: Ident,
    /// The value type (for LazyLock<T>, this is T)
    pub ty: Type,
    /// The initializer expression
    pub expr: Expr,
    /// Whether this is a static (true) or const (false)
    pub is_static: bool,
    /// Whether wrapped in LazyLock
    pub is_lazy: bool,
    /// Original attributes
    pub attrs: Vec<Attribute>,
    /// Visibility
    pub vis: Visibility,
}

impl ConstantDef {
    /// Parse a `const` item into a ConstantDef.
    pub(super) fn from_const(item: &ItemConst) -> syn::Result<Self> {
        Ok(Self {
            name: item.ident.clone(),
            ty: (*item.ty).clone(),
            expr: (*item.expr).clone(),
            is_static: false,
            is_lazy: false,
            attrs: item.attrs.clone(),
            vis: item.vis.clone(),
        })
    }

    /// Parse a `static` item into a ConstantDef.
    /// Handles `LazyLock<T>` by extracting the inner type.
    pub(super) fn from_static(item: &ItemStatic) -> syn::Result<Self> {
        let (inner_ty, is_lazy) = extract_lazy_lock_inner(&item.ty);

        Ok(Self {
            name: item.ident.clone(),
            ty: inner_ty.unwrap_or_else(|| (*item.ty).clone()),
            expr: (*item.expr).clone(),
            is_static: true,
            is_lazy,
            attrs: item.attrs.clone(),
            vis: item.vis.clone(),
        })
    }

    /// Returns the Solidity function name for this constant.
    /// Constants use SCREAMING_SNAKE_CASE in Solidity too.
    pub(super) fn sol_name(&self) -> String {
        self.name.to_string()
    }
}

/// Extract the inner type from `LazyLock<T>` or similar wrapper types.
/// Returns (Some(inner_type), true) if it's a LazyLock, otherwise (None, false).
fn extract_lazy_lock_inner(ty: &Type) -> (Option<Type>, bool) {
    if let Type::Path(type_path) = ty
        && let Some(seg) = type_path.path.segments.last()
        && (seg.ident == "LazyLock" || seg.ident == "Lazy" || seg.ident == "OnceCell")
        && let PathArguments::AngleBracketed(args) = &seg.arguments
        && let Some(GenericArgument::Type(inner)) = args.args.first()
    {
        return (Some(inner.clone()), true);
    }
    (None, false)
}

/// Unit enum definition (encoded as u8).
///
/// # Invariants
///
/// - All variants must be unit variants.
/// - Must have at least one variant.
/// - Must fit in u8.
/// - Generics are not supported.
/// - Visibility is preserved from the original enum.
#[derive(Debug, Clone)]
pub(super) struct UnitEnumDef {
    /// Enum name
    pub name: Ident,
    /// Variant names (all unit variants)
    pub variants: Vec<Ident>,
    /// Original attributes to preserve
    pub attrs: Vec<Attribute>,
    /// Visibility
    pub vis: Visibility,
    /// Whether the original enum had `#[derive(Storable)]`
    pub has_storable: bool,
}

impl UnitEnumDef {
    fn parse(item: &ItemEnum) -> syn::Result<Self> {
        check_generics(&item.generics)?;

        let mut variants = Vec::new();

        for variant in &item.variants {
            if !matches!(variant.fields, Fields::Unit) {
                return Err(syn::Error::new_spanned(
                    variant,
                    "enums in `#[abi]` modules must be one of:\n\
                     - `enum Error { ... }` with named-field variants for custom errors\n\
                     - `enum Event { ... }` with named-field variants for events\n\
                     - unit-only enums (no fields) encoded as uint8",
                ));
            }
            variants.push(variant.ident.clone());
        }

        if variants.is_empty() {
            return Err(syn::Error::new_spanned(
                item,
                "unit enum must have at least one variant",
            ));
        }

        if variants.len() > 256 {
            return Err(syn::Error::new_spanned(
                item,
                "enum cannot have more than 256 variants (must fit in u8)",
            ));
        }

        let (_, other_attrs, has_storable) = extract_derive_attrs(&item.attrs);

        Ok(Self {
            name: item.ident.clone(),
            variants,
            attrs: other_attrs,
            vis: item.vis.clone(),
            has_storable,
        })
    }
}

/// Error or Event enum definition.
///
/// # Invariants
///
/// - Must be named `Error` or `Event`.
/// - Must have at least one variant.
/// - Variants must either use named fields or be unit variants (tuple variants are forbidden).
/// - Generics are not supported.
/// - For `Event`: variants can have, at most, 3 `#[indexed]` fields.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(super) struct SolEnumDef {
    /// Enum name (`Error` or `Event`)
    pub name: Ident,
    /// Variants with their fields
    pub variants: Vec<EnumVariantDef>,
    /// Original attributes to preserve
    pub attrs: Vec<Attribute>,
    /// Visibility
    pub vis: Visibility,
}

impl SolEnumDef {
    fn parse(item: &ItemEnum, kind: SolEnumKind) -> syn::Result<Self> {
        check_generics(&item.generics)?;

        let variants = item
            .variants
            .iter()
            .map(|v| EnumVariantDef::parse(v, kind))
            .collect::<syn::Result<Vec<_>>>()?;

        if variants.is_empty() {
            let kind_name = match kind {
                SolEnumKind::Error => "Error",
                SolEnumKind::Event => "Event",
            };
            return Err(syn::Error::new_spanned(
                item,
                format!("`{kind_name}` enum must have at least one variant"),
            ));
        }

        let (_, other_attrs, _) = extract_derive_attrs(&item.attrs);

        Ok(Self {
            name: item.ident.to_owned(),
            variants,
            attrs: other_attrs,
            vis: item.vis.to_owned(),
        })
    }
}

/// Enum variant definition.
///
/// # Invariants
///
/// - Only named fields or unit variants (tuple variants rejected).
/// - Field types must be valid `SolType` values or registered structs/unit enums.
/// - For `Event` variants: at most 3 fields may be marked `#[indexed]`.
#[derive(Debug, Clone)]
pub(super) struct EnumVariantDef {
    /// Variant name
    pub name: Ident,
    /// Fields (empty for unit variants)
    pub fields: Vec<FieldDef>,
}

impl EnumVariantDef {
    fn parse(variant: &syn::Variant, kind: SolEnumKind) -> syn::Result<Self> {
        let fields = match &variant.fields {
            Fields::Named(named) => named
                .named
                .iter()
                .map(|f| {
                    let name = f
                        .ident
                        .clone()
                        .ok_or_else(|| syn::Error::new_spanned(f, "expected named field"))?;
                    let indexed = kind == SolEnumKind::Event && has_indexed_attr(&f.attrs);
                    Ok(FieldDef {
                        name,
                        ty: f.ty.clone(),
                        indexed,
                        vis: f.vis.clone(),
                    })
                })
                .collect::<syn::Result<Vec<_>>>()?,
            Fields::Unit => Vec::new(),
            Fields::Unnamed(_) => {
                let kind_name = match kind {
                    SolEnumKind::Error => "Error",
                    SolEnumKind::Event => "Event",
                };
                return Err(syn::Error::new_spanned(
                    variant,
                    format!(
                        "`{kind_name}` variants must use named fields (e.g., `Variant {{ field: Type }}`) or be unit variants"
                    ),
                ));
            }
        };

        if kind == SolEnumKind::Event {
            let indexed_count = fields.iter().filter(|f| f.indexed).count();
            if indexed_count > 3 {
                return Err(syn::Error::new_spanned(
                    variant,
                    "events can have at most 3 indexed fields (plus the signature hash makes 4 topics total)",
                ));
            }
        }

        Ok(Self {
            name: variant.ident.clone(),
            fields,
        })
    }
}

impl FieldAccessors for EnumVariantDef {
    fn fields(&self) -> impl Iterator<Item = (&Ident, &Type)> {
        self.fields.iter().map(|f| (&f.name, &f.ty))
    }

    fn name(&self) -> &Ident {
        &self.name
    }

    /// Generate Solidity params with indexed support for events.
    fn as_solidity_params(&self) -> syn::Result<String> {
        self.fields
            .iter()
            .map(|f| {
                let sol_name = super::common::SynSolType::parse(&f.ty)?.sol_name();
                let indexed = if f.indexed { " indexed" } else { "" };
                Ok(format!("{}{} {}", sol_name, indexed, f.name))
            })
            .collect::<syn::Result<Vec<_>>>()
            .map(|v| v.join(", "))
    }
}

/// Interface trait definition.
///
/// # Invariants
///
/// - All methods must return `Result<T, _>`
/// - `&mut self` methods get `msg_sender: Address` auto-injected as first param
/// - Parameter named `msg_sender` is reserved and rejected
/// - Generics are not supported
#[derive(Debug, Clone)]
pub(super) struct InterfaceDef {
    /// Trait name
    pub name: Ident,
    /// Methods
    pub methods: Vec<MethodDef>,
    /// Original attributes to preserve
    pub attrs: Vec<Attribute>,
    /// Visibility
    pub vis: Visibility,
}

impl InterfaceDef {
    fn parse(item: &ItemTrait) -> syn::Result<Self> {
        check_generics(&item.generics)?;

        let methods: Vec<MethodDef> = item
            .items
            .iter()
            .filter_map(|trait_item| {
                if let TraitItem::Fn(method) = trait_item {
                    Some(method)
                } else {
                    None
                }
            })
            .map(|method| MethodDef::parse(&method.sig))
            .collect::<syn::Result<_>>()?;

        if methods.is_empty() {
            return Err(syn::Error::new_spanned(
                item,
                format!("trait `{}` must have at least one method", item.ident),
            ));
        }

        let (_, other_attrs, _) = extract_derive_attrs(&item.attrs);

        Ok(Self {
            name: item.ident.clone(),
            methods,
            attrs: other_attrs,
            vis: item.vis.clone(),
        })
    }
}

/// Method definition from trait.
///
/// # Invariants
///
/// - Must have `&self` or `&mut self` as first parameter.
/// - Must return `Result<T, E>`.
/// - Parameter patterns must be identifiers.
/// - Parameter name `msg_sender` is reserved and rejected.
/// - Method name is auto-converted from snake_case to camelCase for Solidity ABI.
#[derive(Debug, Clone)]
pub(super) struct MethodDef {
    /// Rust method name (snake_case)
    pub name: Ident,
    /// Solidity-style camelCase name
    pub sol_name: String,
    /// Parameters (excludes self and msg_sender)
    pub params: Vec<(Ident, Type)>,
    /// Return type (extracted from Result<T, _>)
    pub return_type: Option<Type>,
    /// Whether this is a mutable method (&mut self)
    pub is_mutable: bool,
}

impl MethodDef {
    fn parse(sig: &Signature) -> syn::Result<Self> {
        let sol_name = to_camel_case(&sig.ident.to_string());

        let mut is_mutable = false;
        let mut params = Vec::new();

        for (i, arg) in sig.inputs.iter().enumerate() {
            match arg {
                FnArg::Receiver(receiver) => {
                    if i != 0 {
                        return Err(syn::Error::new_spanned(
                            receiver,
                            "self must be the first parameter",
                        ));
                    }
                    is_mutable = receiver.mutability.is_some();
                }
                FnArg::Typed(pat_type) => {
                    let param_name = extract_param_name(&pat_type.pat)?;

                    if param_name == "msg_sender" {
                        return Err(syn::Error::new_spanned(
                            pat_type,
                            "`msg_sender` is a reserved name and is auto-injected for `&mut self` methods",
                        ));
                    }

                    params.push((param_name, (*pat_type.ty).clone()));
                }
            }
        }

        let return_type = extract_result_inner_type(&sig.output)?;

        Ok(Self {
            name: sig.ident.to_owned(),
            sol_name,
            params,
            return_type,
            is_mutable,
        })
    }
}

impl FieldAccessors for MethodDef {
    fn fields(&self) -> impl Iterator<Item = (&Ident, &Type)> {
        self.params.iter().map(|(n, ty)| (n, ty))
    }

    fn name(&self) -> &Ident {
        &self.name
    }
}

/// Extract #[derive(...)] attributes from other attributes.
///
/// Also filters out `Storable` from derive attributes, returning whether it was present.
/// This allows the code generator to emit `#[cfg_attr(feature = "precompile", derive(...))]`
/// for `Storable` instead of unconditionally deriving it.
fn extract_derive_attrs(attrs: &[Attribute]) -> (Vec<Attribute>, Vec<Attribute>, bool) {
    let mut derives = Vec::new();
    let mut others = Vec::new();
    let mut has_storable = false;

    for attr in attrs {
        if attr.path().is_ident("derive") {
            match filter_storable_from_derive(attr) {
                Some((filtered_attr, found_storable)) => {
                    if found_storable {
                        has_storable = true;
                    }
                    if let Some(attr) = filtered_attr {
                        derives.push(attr);
                    }
                }
                None => derives.push(attr.clone()),
            }
        } else {
            others.push(attr.clone());
        }
    }

    (derives, others, has_storable)
}

/// Filters `Storable` from a derive attribute.
///
/// Returns `Some((filtered_attr, had_storable))` where:
/// - `filtered_attr` is `None` if the derive becomes empty after removing `Storable`
/// - `had_storable` indicates whether `Storable` was found and removed
///
/// Returns `None` if the attribute couldn't be parsed (caller should keep original).
fn filter_storable_from_derive(attr: &Attribute) -> Option<(Option<Attribute>, bool)> {
    let Meta::List(list) = &attr.meta else {
        return None;
    };

    // Parse the tokens inside derive(...)
    let parser = Punctuated::<Path, Token![,]>::parse_terminated;
    let punctuated = syn::parse::Parser::parse2(parser, list.tokens.clone()).ok()?;

    let mut has_storable = false;
    let mut remaining: Vec<&Path> = Vec::new();

    for path in &punctuated {
        if path.is_ident("Storable") {
            has_storable = true;
        } else {
            remaining.push(path);
        }
    }

    if remaining.is_empty() {
        Some((None, has_storable))
    } else {
        // Reconstruct the derive attribute
        let new_tokens = quote! { #(#remaining),* };
        let new_attr = Attribute {
            pound_token: attr.pound_token,
            style: attr.style,
            bracket_token: attr.bracket_token,
            meta: Meta::List(MetaList {
                path: list.path.clone(),
                delimiter: list.delimiter.clone(),
                tokens: new_tokens,
            }),
        };
        Some((Some(new_attr), has_storable))
    }
}

/// Reject generics on solidity-annotated items.
fn check_generics(generics: &syn::Generics) -> syn::Result<()> {
    if !generics.params.is_empty() || generics.where_clause.is_some() {
        return Err(syn::Error::new_spanned(
            generics,
            "generics are not supported in `#[abi]` modules",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SolEnumKind {
    Error,
    Event,
}

fn has_indexed_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("indexed"))
}

fn extract_param_name(pat: &Pat) -> syn::Result<Ident> {
    match pat {
        Pat::Ident(pat_ident) => Ok(pat_ident.ident.clone()),
        _ => Err(syn::Error::new_spanned(
            pat,
            "expected simple identifier pattern for parameter",
        )),
    }
}

/// Extract the inner type from `Result<T, _>`.
fn extract_result_inner_type(return_type: &ReturnType) -> syn::Result<Option<Type>> {
    match return_type {
        ReturnType::Default => Err(syn::Error::new_spanned(
            return_type,
            "interface methods must return Result<T, _>",
        )),
        ReturnType::Type(_, ty) => {
            if let Type::Path(type_path) = ty.as_ref()
                && let Some(seg) = type_path.path.segments.last()
                && seg.ident == "Result"
                && let PathArguments::AngleBracketed(args) = &seg.arguments
                && let Some(GenericArgument::Type(inner)) = args.args.first()
            {
                if is_unit_type(inner) {
                    return Ok(None);
                }
                return Ok(Some(inner.clone()));
            }
            Err(syn::Error::new_spanned(
                ty,
                "interface methods must return Result<T, _>",
            ))
        }
    }
}

fn is_unit_type(ty: &Type) -> bool {
    matches!(ty, Type::Tuple(tuple) if tuple.elems.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    fn parse_module(tokens: proc_macro2::TokenStream) -> syn::Result<SolidityModule> {
        let item: ItemMod = syn::parse2(tokens)?;
        SolidityModule::parse(item)
    }

    #[test]
    fn test_parser_success_cases() -> syn::Result<()> {
        // Empty module
        let module = parse_module(quote! { pub mod test {} })?;
        assert_eq!(module.name.to_string(), "test");
        assert!(
            module.structs.is_empty() && module.error.is_none() && module.interfaces.is_empty()
        );

        // Struct with derives
        let module = parse_module(quote! {
            pub mod test {
                #[derive(Clone, Debug)]
                pub struct Transfer { pub from: Address, pub to: Address }
            }
        })?;
        assert_eq!(module.structs.len(), 1);
        assert_eq!(module.structs[0].fields.len(), 2);

        // Unit enum
        let module = parse_module(quote! {
            pub mod test { pub enum Status { Pending, Filled } }
        })?;
        assert_eq!(module.unit_enums.len(), 1);
        assert_eq!(module.unit_enums[0].variants.len(), 2);

        // Error enum with variants
        let module = parse_module(quote! {
            pub mod test { pub enum Error { Unauthorized, BadValue { val: U256 } } }
        })?;
        let error = module.error.unwrap();
        assert_eq!(error.variants.len(), 2);
        assert!(error.variants[0].fields.is_empty());
        assert_eq!(error.variants[1].fields.len(), 1);

        // Event enum with indexed fields
        let module = parse_module(quote! {
            pub mod test { pub enum Event { Transfer { #[indexed] from: Address, to: Address } } }
        })?;
        let event = module.event.unwrap();
        assert!(event.variants[0].fields[0].indexed);
        assert!(!event.variants[0].fields[1].indexed);

        // Interface trait (any trait name is accepted)
        let module = parse_module(quote! {
            pub mod test {
                pub trait MyInterface {
                    fn get(&self, id: U256) -> Result<Address>;
                    fn set(&mut self, id: U256, val: Address) -> Result<()>;
                }
            }
        })?;
        assert_eq!(module.interfaces.len(), 1);
        let interface = &module.interfaces[0];
        assert_eq!(interface.name.to_string(), "MyInterface");
        assert!(!interface.methods[0].is_mutable);
        assert!(interface.methods[1].is_mutable);
        assert_eq!(interface.methods[0].sol_name, "get");

        // Multiple interface traits
        let module = parse_module(quote! {
            pub mod test {
                pub trait Token {
                    fn transfer(&mut self, to: Address, amount: U256) -> Result<bool>;
                }
                pub trait Roles {
                    fn grant_role(&mut self, role: B256, account: Address) -> Result<()>;
                }
            }
        })?;
        assert_eq!(module.interfaces.len(), 2);
        assert_eq!(module.interfaces[0].name.to_string(), "Token");
        assert_eq!(module.interfaces[1].name.to_string(), "Roles");
        Ok(())
    }

    #[test]
    fn test_parser_error_cases() {
        // Non-unit enum (not Error/Event)
        let err = parse_module(quote! {
            pub mod test { pub enum Bad { V { f: U256 } } }
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("unit-only enums"));

        // Too many indexed fields
        let err = parse_module(quote! {
            pub mod test { pub enum Event { E { #[indexed] a: Address, #[indexed] b: Address, #[indexed] c: Address, #[indexed] d: Address } } }
        }).unwrap_err().to_string();
        assert!(err.contains("at most 3 indexed"));

        // Reserved msg_sender parameter
        let err = parse_module(quote! {
            pub mod test { pub trait Interface { fn f(&mut self, msg_sender: Address) -> Result<()>; } }
        }).unwrap_err().to_string();
        assert!(err.contains("reserved") && err.contains("msg_sender"));

        // Duplicate Error enum
        let err = parse_module(quote! {
            pub mod test { pub enum Error { A } pub enum Error { B } }
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("duplicate"));

        // Generic struct
        let err = parse_module(quote! {
            pub mod test { pub struct Bad<T> { value: T } }
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("generics"));

        // Generic enum
        let err = parse_module(quote! {
            pub mod test { pub enum Bad<T> { A, B } }
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("generics"));

        // Generic interface
        let err = parse_module(quote! {
            pub mod test { pub trait Interface<T> { fn get(&self) -> Result<T>; } }
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("generics"));
    }

    #[test]
    fn test_full_module() -> syn::Result<()> {
        let module = parse_module(quote! {
            pub mod roles_auth {
                use super::*;
                #[derive(Clone)]
                pub struct Transfer { pub from: Address, pub amount: U256 }
                pub enum PolicyType { Whitelist, Blacklist }
                pub enum Error { Unauthorized, InsufficientBalance { available: U256 } }
                pub enum Event { Updated { #[indexed] role: B256, sender: Address } }
                pub trait Interface {
                    fn has_role(&self, account: Address) -> Result<bool>;
                    fn grant_role(&mut self, role: B256) -> Result<()>;
                }
            }
        })?;

        assert_eq!(module.name.to_string(), "roles_auth");
        assert_eq!(module.imports.len(), 1);
        assert_eq!(module.structs.len(), 1);
        assert_eq!(module.unit_enums.len(), 1);
        assert!(module.error.is_some() && module.event.is_some() && !module.interfaces.is_empty());
        Ok(())
    }

    #[test]
    fn test_constants_parsing() -> syn::Result<()> {
        let module = parse_module(quote! {
            pub mod test {
                use std::sync::LazyLock;
                use alloy::primitives::{B256, keccak256};

                pub const DEFAULT_ADMIN_ROLE: B256 = B256::ZERO;
                pub static PAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"PAUSE_ROLE"));
            }
        })?;

        assert_eq!(module.constants.len(), 2);

        // First constant: const
        let const_def = &module.constants[0];
        assert_eq!(const_def.name.to_string(), "DEFAULT_ADMIN_ROLE");
        assert!(!const_def.is_static);
        assert!(!const_def.is_lazy);

        // Second constant: static with LazyLock
        let static_def = &module.constants[1];
        assert_eq!(static_def.name.to_string(), "PAUSE_ROLE");
        assert!(static_def.is_static);
        assert!(static_def.is_lazy);
        // The type should be B256 (extracted from LazyLock<B256>)
        let ty_str = quote!(#(static_def.ty)).to_string();
        assert!(ty_str.contains("B256") || static_def.ty == syn::parse_quote!(B256));

        Ok(())
    }

    #[test]
    fn test_constants_with_interface() -> syn::Result<()> {
        let module = parse_module(quote! {
            pub mod roles {
                use super::*;

                pub const DEFAULT_ADMIN_ROLE: B256 = B256::ZERO;

                pub trait Interface {
                    fn has_role(&self, account: Address, role: B256) -> Result<bool>;
                }
            }
        })?;

        assert_eq!(module.constants.len(), 1);
        assert_eq!(module.interfaces.len(), 1);
        Ok(())
    }

    #[test]
    fn test_storable_derive_extraction() -> syn::Result<()> {
        // Struct with only Storable derive - should have empty derives, has_storable = true
        let module = parse_module(quote! {
            pub mod test {
                #[derive(Storable)]
                pub struct OnlyStorable { pub value: U256 }
            }
        })?;
        assert_eq!(module.structs.len(), 1);
        assert!(module.structs[0].derives.is_empty());
        assert!(module.structs[0].has_storable);

        // Struct with Storable mixed with other derives
        let module = parse_module(quote! {
            pub mod test {
                #[derive(Debug, Clone, Storable, PartialEq)]
                pub struct MixedDerives { pub value: U256 }
            }
        })?;
        assert_eq!(module.structs.len(), 1);
        assert!(module.structs[0].has_storable);
        // Should have 3 derives remaining (Debug, Clone, PartialEq)
        assert_eq!(module.structs[0].derives.len(), 1); // One #[derive(...)] attr with 3 items

        // Struct without Storable
        let module = parse_module(quote! {
            pub mod test {
                #[derive(Debug, Clone)]
                pub struct NoStorable { pub value: U256 }
            }
        })?;
        assert_eq!(module.structs.len(), 1);
        assert!(!module.structs[0].has_storable);
        assert_eq!(module.structs[0].derives.len(), 1);

        // Struct with no derives at all
        let module = parse_module(quote! {
            pub mod test {
                pub struct NoDerives { pub value: U256 }
            }
        })?;
        assert_eq!(module.structs.len(), 1);
        assert!(!module.structs[0].has_storable);
        assert!(module.structs[0].derives.is_empty());

        Ok(())
    }
}
