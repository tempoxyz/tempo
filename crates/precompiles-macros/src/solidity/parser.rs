//! Parser for `#[solidity]` module macro.
//!
//! Parses a Rust module decorated with `#[solidity]` into a structured intermediate
//! representation (IR) suitable for code generation.
//!
//! # Naming Conventions
//!
//! - `trait Interface` → generates SolCall structs + SolInterface enum
//! - `enum Error` → generates SolError structs + SolInterface enum
//! - `enum Event` → generates SolEvent structs + IntoLogData enum
//! - Other enums → unit enums only, encoded as u8
//! - Structs → generate SolStruct, SolType, SolValue, EventTopic

use proc_macro2::Ident;
use syn::{
    Attribute, Fields, FnArg, GenericArgument, Item, ItemEnum, ItemMod, ItemStruct, ItemTrait,
    ItemUse, Pat, PathArguments, ReturnType, Signature, TraitItem, Type, Visibility,
};

// ============================================================================
// Intermediate Representation (IR) Types
// ============================================================================

/// Parsed content of a `#[solidity]` module.
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
    /// Interface trait (optional, must be named `Interface`)
    pub interface: Option<InterfaceDef>,
    /// Other items passed through unchanged
    pub other_items: Vec<Item>,
}

/// Struct definition for SolStruct generation.
#[derive(Debug, Clone)]
pub(super) struct SolStructDef {
    /// Struct name
    pub name: Ident,
    /// Fields with their types
    pub fields: Vec<FieldDef>,
    /// Original derive attributes to preserve
    pub derives: Vec<Attribute>,
    /// Other attributes to preserve
    pub attrs: Vec<Attribute>,
    /// Visibility
    pub vis: Visibility,
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

/// Unit enum definition (encoded as u8).
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
}

/// Error or Event enum definition.
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

/// Enum variant definition.
#[derive(Debug, Clone)]
pub(super) struct EnumVariantDef {
    /// Variant name
    pub name: Ident,
    /// Fields (empty for unit variants)
    pub fields: Vec<FieldDef>,
}

/// Interface trait definition.
#[derive(Debug, Clone)]
pub(super) struct InterfaceDef {
    /// Always `Interface`
    pub name: Ident,
    /// Methods
    pub methods: Vec<MethodDef>,
    /// Original attributes to preserve
    pub attrs: Vec<Attribute>,
    /// Visibility
    pub vis: Visibility,
}

/// Method definition from trait.
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

// ============================================================================
// Parser Implementation
// ============================================================================

/// Parse a module decorated with `#[solidity]` into IR.
pub(super) fn parse_solidity_module(item: ItemMod) -> syn::Result<SolidityModule> {
    let name = item.ident.clone();
    let vis = item.vis.clone();

    let content = item
        .content
        .as_ref()
        .ok_or_else(|| syn::Error::new_spanned(&item, "#[solidity] requires a module with body"))?;

    let mut imports = Vec::new();
    let mut structs = Vec::new();
    let mut unit_enums = Vec::new();
    let mut error: Option<SolEnumDef> = None;
    let mut event: Option<SolEnumDef> = None;
    let mut interface: Option<InterfaceDef> = None;
    let mut other_items = Vec::new();

    for item in &content.1 {
        match item {
            Item::Use(use_item) => {
                imports.push(use_item.clone());
            }
            Item::Struct(struct_item) => {
                structs.push(parse_struct(struct_item)?);
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
                        error = Some(parse_sol_enum(enum_item, SolEnumKind::Error)?);
                    }
                    "Event" => {
                        if event.is_some() {
                            return Err(syn::Error::new_spanned(
                                enum_item,
                                "duplicate `Event` enum",
                            ));
                        }
                        event = Some(parse_sol_enum(enum_item, SolEnumKind::Event)?);
                    }
                    _ => {
                        unit_enums.push(parse_unit_enum(enum_item)?);
                    }
                }
            }
            Item::Trait(trait_item) => {
                if trait_item.ident == "Interface" {
                    if interface.is_some() {
                        return Err(syn::Error::new_spanned(
                            trait_item,
                            "duplicate `Interface` trait",
                        ));
                    }
                    interface = Some(parse_interface(trait_item)?);
                } else {
                    return Err(syn::Error::new_spanned(
                        &trait_item.ident,
                        format!(
                            "trait must be named `Interface`, found `{}`",
                            trait_item.ident
                        ),
                    ));
                }
            }
            _ => {
                other_items.push(item.clone());
            }
        }
    }

    Ok(SolidityModule {
        name,
        vis,
        imports,
        structs,
        unit_enums,
        error,
        event,
        interface,
        other_items,
    })
}

// ============================================================================
// Struct Parsing
// ============================================================================

fn parse_struct(item: &ItemStruct) -> syn::Result<SolStructDef> {
    let fields = match &item.fields {
        Fields::Named(named) => named
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
            .collect::<syn::Result<Vec<_>>>()?,
        Fields::Unit => Vec::new(),
        Fields::Unnamed(_) => {
            return Err(syn::Error::new_spanned(
                item,
                "tuple structs are not supported in #[solidity] modules",
            ));
        }
    };

    let (derives, other_attrs) = extract_derive_attrs(&item.attrs);

    Ok(SolStructDef {
        name: item.ident.clone(),
        fields,
        derives,
        attrs: other_attrs,
        vis: item.vis.clone(),
    })
}

/// Extract #[derive(...)] attributes from other attributes.
fn extract_derive_attrs(attrs: &[Attribute]) -> (Vec<Attribute>, Vec<Attribute>) {
    let mut derives = Vec::new();
    let mut others = Vec::new();

    for attr in attrs {
        if attr.path().is_ident("derive") {
            derives.push(attr.clone());
        } else {
            others.push(attr.clone());
        }
    }

    (derives, others)
}

// ============================================================================
// Enum Parsing
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SolEnumKind {
    Error,
    Event,
}

fn parse_sol_enum(item: &ItemEnum, kind: SolEnumKind) -> syn::Result<SolEnumDef> {
    let variants = item
        .variants
        .iter()
        .map(|v| parse_enum_variant(v, kind))
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

    let (_, other_attrs) = extract_derive_attrs(&item.attrs);

    Ok(SolEnumDef {
        name: item.ident.clone(),
        variants,
        attrs: other_attrs,
        vis: item.vis.clone(),
    })
}

fn parse_enum_variant(variant: &syn::Variant, kind: SolEnumKind) -> syn::Result<EnumVariantDef> {
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

    Ok(EnumVariantDef {
        name: variant.ident.clone(),
        fields,
    })
}

fn parse_unit_enum(item: &ItemEnum) -> syn::Result<UnitEnumDef> {
    let mut variants = Vec::new();

    for variant in &item.variants {
        if !matches!(variant.fields, Fields::Unit) {
            return Err(syn::Error::new_spanned(
                variant,
                "non-Error/Event enums must have unit variants only (encoded as u8)",
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

    let (_, other_attrs) = extract_derive_attrs(&item.attrs);

    Ok(UnitEnumDef {
        name: item.ident.clone(),
        variants,
        attrs: other_attrs,
        vis: item.vis.clone(),
    })
}

fn has_indexed_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("indexed"))
}

// ============================================================================
// Interface Parsing
// ============================================================================

fn parse_interface(item: &ItemTrait) -> syn::Result<InterfaceDef> {
    if item.ident != "Interface" {
        return Err(syn::Error::new_spanned(
            &item.ident,
            "interface trait must be named `Interface`",
        ));
    }

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
        .map(|method| parse_method(&method.sig))
        .collect::<syn::Result<_>>()?;

    if methods.is_empty() {
        return Err(syn::Error::new_spanned(
            item,
            "`Interface` trait must have at least one method",
        ));
    }

    let (_, other_attrs) = extract_derive_attrs(&item.attrs);

    Ok(InterfaceDef {
        name: item.ident.clone(),
        methods,
        attrs: other_attrs,
        vis: item.vis.clone(),
    })
}

fn parse_method(sig: &Signature) -> syn::Result<MethodDef> {
    let name = sig.ident.clone();
    let sol_name = to_camel_case(&name.to_string());

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

    Ok(MethodDef {
        name,
        sol_name,
        params,
        return_type,
        is_mutable,
    })
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
            if let Type::Path(type_path) = ty.as_ref() {
                if let Some(seg) = type_path.path.segments.last() {
                    if seg.ident == "Result" {
                        if let PathArguments::AngleBracketed(args) = &seg.arguments {
                            if let Some(GenericArgument::Type(inner)) = args.args.first() {
                                if is_unit_type(inner) {
                                    return Ok(None);
                                }
                                return Ok(Some(inner.clone()));
                            }
                        }
                    }
                }
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

/// Converts snake_case to camelCase.
fn to_camel_case(s: &str) -> String {
    let mut result = String::new();
    let mut first_word = true;

    for word in s.split('_') {
        if word.is_empty() {
            continue;
        }

        if first_word {
            result.push_str(word);
            first_word = false;
        } else {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                result.push_str(&first.to_uppercase().collect::<String>());
                result.push_str(chars.as_str());
            }
        }
    }
    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    fn parse_module(tokens: proc_macro2::TokenStream) -> syn::Result<SolidityModule> {
        let item: ItemMod = syn::parse2(tokens)?;
        parse_solidity_module(item)
    }

    #[test]
    fn test_parse_empty_module() {
        let result = parse_module(quote! {
            pub mod test {}
        });
        assert!(result.is_ok());
        let module = result.unwrap();
        assert_eq!(module.name.to_string(), "test");
        assert!(module.structs.is_empty());
        assert!(module.error.is_none());
        assert!(module.event.is_none());
        assert!(module.interface.is_none());
    }

    #[test]
    fn test_parse_struct() {
        let result = parse_module(quote! {
            pub mod test {
                #[derive(Clone, Debug)]
                pub struct Transfer {
                    pub from: Address,
                    pub to: Address,
                    pub amount: U256,
                }
            }
        });
        assert!(result.is_ok());
        let module = result.unwrap();
        assert_eq!(module.structs.len(), 1);
        assert_eq!(module.structs[0].name.to_string(), "Transfer");
        assert_eq!(module.structs[0].fields.len(), 3);
    }

    #[test]
    fn test_parse_unit_enum() {
        let result = parse_module(quote! {
            pub mod test {
                pub enum OrderStatus {
                    Pending,
                    Filled,
                    Cancelled,
                }
            }
        });
        assert!(result.is_ok());
        let module = result.unwrap();
        assert_eq!(module.unit_enums.len(), 1);
        assert_eq!(module.unit_enums[0].name.to_string(), "OrderStatus");
        assert_eq!(module.unit_enums[0].variants.len(), 3);
    }

    #[test]
    fn test_reject_non_unit_enum() {
        let result = parse_module(quote! {
            pub mod test {
                pub enum BadEnum {
                    Variant { field: U256 },
                }
            }
        });
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unit variants only"));
    }

    #[test]
    fn test_parse_error_enum() {
        let result = parse_module(quote! {
            pub mod test {
                pub enum Error {
                    Unauthorized,
                    InsufficientBalance { available: U256, required: U256 },
                }
            }
        });
        assert!(result.is_ok());
        let module = result.unwrap();
        assert!(module.error.is_some());
        let error = module.error.unwrap();
        assert_eq!(error.variants.len(), 2);
        assert_eq!(error.variants[0].name.to_string(), "Unauthorized");
        assert!(error.variants[0].fields.is_empty());
        assert_eq!(error.variants[1].fields.len(), 2);
    }

    #[test]
    fn test_parse_event_enum_with_indexed() {
        let result = parse_module(quote! {
            pub mod test {
                pub enum Event {
                    Transfer {
                        #[indexed]
                        from: Address,
                        #[indexed]
                        to: Address,
                        amount: U256,
                    },
                }
            }
        });
        assert!(result.is_ok());
        let module = result.unwrap();
        assert!(module.event.is_some());
        let event = module.event.unwrap();
        assert_eq!(event.variants.len(), 1);
        let variant = &event.variants[0];
        assert_eq!(variant.fields.len(), 3);
        assert!(variant.fields[0].indexed);
        assert!(variant.fields[1].indexed);
        assert!(!variant.fields[2].indexed);
    }

    #[test]
    fn test_reject_too_many_indexed_fields() {
        let result = parse_module(quote! {
            pub mod test {
                pub enum Event {
                    BadEvent {
                        #[indexed]
                        a: Address,
                        #[indexed]
                        b: Address,
                        #[indexed]
                        c: Address,
                        #[indexed]
                        d: Address,
                    },
                }
            }
        });
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("at most 3 indexed fields"));
    }

    #[test]
    fn test_parse_interface() {
        let result = parse_module(quote! {
            pub mod test {
                pub trait Interface {
                    fn balance_of(&self, account: Address) -> Result<U256>;
                    fn transfer(&mut self, to: Address, amount: U256) -> Result<()>;
                }
            }
        });
        assert!(result.is_ok());
        let module = result.unwrap();
        assert!(module.interface.is_some());
        let interface = module.interface.unwrap();
        assert_eq!(interface.methods.len(), 2);

        let balance_of = &interface.methods[0];
        assert_eq!(balance_of.name.to_string(), "balance_of");
        assert_eq!(balance_of.sol_name, "balanceOf");
        assert!(!balance_of.is_mutable);
        assert_eq!(balance_of.params.len(), 1);

        let transfer = &interface.methods[1];
        assert_eq!(transfer.name.to_string(), "transfer");
        assert_eq!(transfer.sol_name, "transfer");
        assert!(transfer.is_mutable);
        assert_eq!(transfer.params.len(), 2);
        assert!(transfer.return_type.is_none());
    }

    #[test]
    fn test_reject_msg_sender_param() {
        let result = parse_module(quote! {
            pub mod test {
                pub trait Interface {
                    fn bad_method(&mut self, msg_sender: Address, value: U256) -> Result<()>;
                }
            }
        });
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("reserved name"));
        assert!(err.contains("msg_sender"));
    }

    #[test]
    fn test_reject_non_interface_trait() {
        let result = parse_module(quote! {
            pub mod test {
                pub trait SomethingElse {
                    fn method(&self) -> Result<()>;
                }
            }
        });
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must be named `Interface`"));
    }

    #[test]
    fn test_reject_duplicate_error() {
        let result = parse_module(quote! {
            pub mod test {
                pub enum Error { A }
                pub enum Error { B }
            }
        });
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("duplicate"));
    }

    #[test]
    fn test_full_module() {
        let result = parse_module(quote! {
            pub mod roles_auth {
                use super::*;

                #[derive(Clone, Debug)]
                pub struct Transfer {
                    pub from: Address,
                    pub to: Address,
                    pub amount: U256,
                }

                pub enum PolicyType {
                    Whitelist,
                    Blacklist,
                }

                pub enum Error {
                    Unauthorized,
                    InsufficientBalance { available: U256, required: U256 },
                }

                pub enum Event {
                    RoleMembershipUpdated {
                        #[indexed]
                        role: B256,
                        #[indexed]
                        account: Address,
                        sender: Address,
                        has_role: bool,
                    },
                }

                pub trait Interface {
                    fn has_role(&self, account: Address, role: B256) -> Result<bool>;
                    fn grant_role(&mut self, role: B256, account: Address) -> Result<()>;
                }
            }
        });

        assert!(result.is_ok());
        let module = result.unwrap();
        assert_eq!(module.name.to_string(), "roles_auth");
        assert_eq!(module.imports.len(), 1);
        assert_eq!(module.structs.len(), 1);
        assert_eq!(module.unit_enums.len(), 1);
        assert!(module.error.is_some());
        assert!(module.event.is_some());
        assert!(module.interface.is_some());
    }

    #[test]
    fn test_to_camel_case() {
        assert_eq!(to_camel_case("balance_of"), "balanceOf");
        assert_eq!(to_camel_case("transfer_from"), "transferFrom");
        assert_eq!(to_camel_case("name"), "name");
        assert_eq!(to_camel_case("update_quote_token"), "updateQuoteToken");
    }
}
