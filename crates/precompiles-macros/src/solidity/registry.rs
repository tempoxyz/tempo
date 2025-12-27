//! Type registry for ABI signature resolution.
//!
//! The registry collects all type definitions from a `#[solidity]` module and
//! provides methods to resolve Rust types to their Solidity ABI representations.
//!
//! This enables correct selector computation for functions/errors with struct
//! parameters by expanding struct types to their ABI tuple signatures.
//!
//! # Nested Struct Handling
//!
//! The registry performs topological sorting of struct definitions to ensure
//! nested structs are resolved before their containing structs. This is critical
//! for computing correct ABI signatures.
//!
//! ```text
//! struct Inner { value: U256 }
//! struct Outer { inner: Inner, extra: Address }
//!
//! // Inner must be resolved first: Inner -> "(uint256)"
//! // Then Outer can be resolved: Outer -> "((uint256),address)"
//! ```
//!
//! # Cycle Detection
//!
//! Circular struct dependencies are detected and reported as compile errors.

use std::collections::{HashMap, HashSet};

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::Type;

use crate::utils::SolType;

use super::parser::{SolStructDef, SolidityModule, UnitEnumDef};

/// Type registry for resolving Rust types to Solidity ABI.
#[derive(Debug, Default)]
pub(super) struct TypeRegistry {
    /// Map from struct name to its ABI tuple signature (e.g., "(address,uint256)")
    abi_tuples: HashMap<String, String>,

    /// Set of unit enum names (these map to uint8)
    unit_enums: HashSet<String>,

    /// Map from struct name to its direct struct dependencies
    /// Used for topological sort and EIP-712 component tracking
    struct_deps: HashMap<String, Vec<String>>,

    /// Structs in topologically sorted order (dependencies first)
    sorted_structs: Vec<String>,
}

impl TypeRegistry {
    /// Build a registry from a parsed solidity module.
    ///
    /// This performs:
    /// 1. Registration of unit enums
    /// 2. Collection of struct field types
    /// 3. Topological sort of structs (with cycle detection)
    /// 4. ABI tuple computation in dependency order
    pub(super) fn from_module(module: &SolidityModule) -> syn::Result<Self> {
        let mut registry = Self::default();

        for unit_enum in &module.unit_enums {
            registry.register_unit_enum(unit_enum);
        }

        let struct_map: HashMap<String, &SolStructDef> = module
            .structs
            .iter()
            .map(|s| (s.name.to_string(), s))
            .collect();

        registry.collect_struct_dependencies(&struct_map)?;

        registry.topological_sort(&struct_map)?;

        for name in &registry.sorted_structs.clone() {
            if let Some(def) = struct_map.get(name) {
                registry.compute_struct_abi(def)?;
            }
        }

        Ok(registry)
    }

    /// Register a unit enum (encoded as uint8).
    fn register_unit_enum(&mut self, def: &UnitEnumDef) {
        self.unit_enums.insert(def.name.to_string());
    }

    /// Collect struct dependencies by analyzing field types.
    fn collect_struct_dependencies(
        &mut self,
        struct_map: &HashMap<String, &SolStructDef>,
    ) -> syn::Result<()> {
        for (name, def) in struct_map {
            let mut deps = Vec::new();
            for field in &def.fields {
                self.collect_type_dependencies(&field.ty, struct_map, &mut deps);
            }
            self.struct_deps.insert(name.clone(), deps);
        }
        Ok(())
    }

    /// Recursively collect struct type dependencies from a type.
    fn collect_type_dependencies(
        &self,
        ty: &Type,
        struct_map: &HashMap<String, &SolStructDef>,
        deps: &mut Vec<String>,
    ) {
        match ty {
            Type::Path(type_path) => {
                if let Some(seg) = type_path.path.segments.last() {
                    let type_name = seg.ident.to_string();

                    if struct_map.contains_key(&type_name) && !deps.contains(&type_name) {
                        deps.push(type_name);
                    }

                    if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                        for arg in &args.args {
                            if let syn::GenericArgument::Type(inner_ty) = arg {
                                self.collect_type_dependencies(inner_ty, struct_map, deps);
                            }
                        }
                    }
                }
            }
            Type::Array(arr) => {
                self.collect_type_dependencies(&arr.elem, struct_map, deps);
            }
            Type::Tuple(tuple) => {
                for elem in &tuple.elems {
                    self.collect_type_dependencies(elem, struct_map, deps);
                }
            }
            _ => {}
        }
    }

    /// Perform topological sort with cycle detection using Kahn's algorithm.
    fn topological_sort(
        &mut self,
        struct_map: &HashMap<String, &SolStructDef>,
    ) -> syn::Result<()> {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut reverse_deps: HashMap<String, Vec<String>> = HashMap::new();

        for name in struct_map.keys() {
            in_degree.insert(name.clone(), 0);
            reverse_deps.insert(name.clone(), Vec::new());
        }

        for (name, deps) in &self.struct_deps {
            for dep in deps {
                if struct_map.contains_key(dep) {
                    *in_degree.get_mut(name).unwrap() += 1;
                    reverse_deps.get_mut(dep).unwrap().push(name.clone());
                }
            }
        }

        let mut queue: Vec<String> = in_degree
            .iter()
            .filter(|(_, deg)| **deg == 0)
            .map(|(name, _)| name.clone())
            .collect();
        queue.sort();

        let mut sorted = Vec::new();

        while let Some(name) = queue.pop() {
            sorted.push(name.clone());

            if let Some(dependents) = reverse_deps.get(&name) {
                for dependent in dependents {
                    if let Some(deg) = in_degree.get_mut(dependent) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(dependent.clone());
                            queue.sort();
                        }
                    }
                }
            }
        }

        if sorted.len() != struct_map.len() {
            let remaining: Vec<&str> = struct_map
                .keys()
                .filter(|k| !sorted.contains(k))
                .map(|s| s.as_str())
                .collect();

            let cycle_members = remaining.join(", ");
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                format!(
                    "circular dependency detected among structs: {}",
                    cycle_members
                ),
            ));
        }

        self.sorted_structs = sorted;
        Ok(())
    }

    /// Compute and store the ABI tuple for a struct.
    fn compute_struct_abi(&mut self, def: &SolStructDef) -> syn::Result<()> {
        let name = def.name.to_string();

        let parts: syn::Result<Vec<String>> = def
            .fields
            .iter()
            .map(|f| self.resolve_abi(&f.ty))
            .collect();

        let abi_tuple = format!("({})", parts?.join(","));
        self.abi_tuples.insert(name, abi_tuple);

        Ok(())
    }

    // ========================================================================
    // Public Query Methods
    // ========================================================================

    /// Resolve a Rust type to its Solidity ABI representation.
    ///
    /// - If the type is a registered unit enum, returns "uint8"
    /// - If the type is a registered struct, returns its ABI tuple
    /// - Otherwise, uses SolType::from_syn for primitives
    pub(super) fn resolve_abi(&self, ty: &Type) -> syn::Result<String> {
        match ty {
            Type::Path(type_path) => {
                if let Some(seg) = type_path.path.segments.last() {
                    let type_name = seg.ident.to_string();

                    if self.unit_enums.contains(&type_name) {
                        return Ok("uint8".to_string());
                    }

                    if let Some(abi_tuple) = self.abi_tuples.get(&type_name) {
                        return Ok(abi_tuple.clone());
                    }

                    if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                        if seg.ident == "Vec" {
                            if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                                let inner_abi = self.resolve_abi(inner)?;
                                return Ok(format!("{}[]", inner_abi));
                            }
                        }
                    }
                }
                let sol_type = SolType::from_syn(ty)?;
                Ok(sol_type.sol_name())
            }
            Type::Array(arr) => {
                let inner_abi = self.resolve_abi(&arr.elem)?;
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(len),
                    ..
                }) = &arr.len
                {
                    Ok(format!("{}[{}]", inner_abi, len))
                } else {
                    Ok(format!("{}[]", inner_abi))
                }
            }
            Type::Tuple(tuple) => {
                if tuple.elems.is_empty() {
                    return Ok("()".to_string());
                }
                let parts: syn::Result<Vec<String>> =
                    tuple.elems.iter().map(|e| self.resolve_abi(e)).collect();
                Ok(format!("({})", parts?.join(",")))
            }
            _ => {
                let sol_type = SolType::from_syn(ty)?;
                Ok(sol_type.sol_name())
            }
        }
    }

    /// Compute function/error/event signature with struct expansion.
    ///
    /// For a function like `transfer(Transfer memory data)` where Transfer is
    /// `struct Transfer { address from; address to; uint256 amount; }`,
    /// this returns `"transfer((address,address,uint256))"`.
    pub(super) fn compute_signature(&self, name: &str, params: &[Type]) -> syn::Result<String> {
        let param_types: syn::Result<Vec<String>> =
            params.iter().map(|ty| self.resolve_abi(ty)).collect();
        Ok(format!("{}({})", name, param_types?.join(",")))
    }

    /// Check if a type is a registered struct.
    #[allow(dead_code)]
    pub(super) fn is_struct(&self, ty: &Type) -> bool {
        if let Type::Path(type_path) = ty {
            if let Some(seg) = type_path.path.segments.last() {
                return self.abi_tuples.contains_key(&seg.ident.to_string());
            }
        }
        false
    }

    /// Check if a type is a registered unit enum.
    #[allow(dead_code)]
    pub(super) fn is_unit_enum(&self, ty: &Type) -> bool {
        if let Type::Path(type_path) = ty {
            if let Some(seg) = type_path.path.segments.last() {
                return self.unit_enums.contains(&seg.ident.to_string());
            }
        }
        false
    }

    /// Get the ABI tuple for a struct by name.
    pub(super) fn get_struct_abi(&self, name: &str) -> Option<&str> {
        self.abi_tuples.get(name).map(|s| s.as_str())
    }

    /// Get structs in topologically sorted order (dependencies first).
    #[allow(dead_code)]
    pub(super) fn sorted_structs(&self) -> &[String] {
        &self.sorted_structs
    }

    /// Get all registered struct names.
    #[allow(dead_code)]
    pub(super) fn struct_names(&self) -> impl Iterator<Item = &str> {
        self.abi_tuples.keys().map(|s| s.as_str())
    }

    /// Get all registered unit enum names.
    #[allow(dead_code)]
    pub(super) fn unit_enum_names(&self) -> impl Iterator<Item = &str> {
        self.unit_enums.iter().map(|s| s.as_str())
    }

    // ========================================================================
    // EIP-712 Component Support
    // ========================================================================

    /// Get the direct struct dependencies for a struct (for EIP-712 components).
    ///
    /// Returns struct names that are directly referenced in the struct's fields.
    #[allow(dead_code)]
    pub(super) fn get_struct_dependencies(&self, name: &str) -> Option<&[String]> {
        self.struct_deps.get(name).map(|v| v.as_slice())
    }

    /// Get all transitive struct dependencies for a struct (for EIP-712 encodeType).
    ///
    /// Returns all struct names that need to be included in the type hash,
    /// in alphabetical order as required by EIP-712.
    pub(super) fn get_transitive_dependencies(&self, name: &str) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut result = Vec::new();
        self.collect_transitive_deps(name, &mut visited, &mut result);
        result.sort();
        result
    }

    /// Recursively collect transitive dependencies.
    fn collect_transitive_deps(
        &self,
        name: &str,
        visited: &mut HashSet<String>,
        result: &mut Vec<String>,
    ) {
        if visited.contains(name) {
            return;
        }
        visited.insert(name.to_string());

        if let Some(deps) = self.struct_deps.get(name) {
            for dep in deps {
                if self.abi_tuples.contains_key(dep) {
                    if !result.contains(dep) {
                        result.push(dep.clone());
                    }
                    self.collect_transitive_deps(dep, visited, result);
                }
            }
        }
    }

    // ========================================================================
    // Code Generation Support
    // ========================================================================

    /// Generate the ABI signature expression for a type.
    ///
    /// For struct types, this generates a reference to the struct's `ABI_TUPLE` constant.
    /// For primitives, returns a literal string.
    pub(super) fn to_abi_signature_expr(&self, ty: &Type) -> syn::Result<TokenStream> {
        if let Type::Path(type_path) = ty {
            if let Some(seg) = type_path.path.segments.last() {
                let type_name = seg.ident.to_string();

                if self.unit_enums.contains(&type_name) {
                    return Ok(quote! { "uint8" });
                }

                if self.abi_tuples.contains_key(&type_name) {
                    let ident = &seg.ident;
                    return Ok(
                        quote! { <#ident as tempo_precompiles::SolTupleSignature>::ABI_TUPLE },
                    );
                }

                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                    if seg.ident == "Vec" {
                        if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                            let inner_expr = self.to_abi_signature_expr(inner)?;
                            return Ok(quote! {
                                tempo_precompiles::const_format::concatcp!(#inner_expr, "[]")
                            });
                        }
                    }
                }
            }
        }

        if let Type::Array(arr) = ty {
            let inner_expr = self.to_abi_signature_expr(&arr.elem)?;
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(len),
                ..
            }) = &arr.len
            {
                let len_str = len.to_string();
                return Ok(quote! {
                    tempo_precompiles::const_format::concatcp!(#inner_expr, "[", #len_str, "]")
                });
            }
        }

        let sol_type = SolType::from_syn(ty)?;
        let sol_name = sol_type.sol_name();
        Ok(quote! { #sol_name })
    }

    /// Check if any parameters contain struct types.
    pub(super) fn has_struct_params(&self, params: &[Type]) -> bool {
        params.iter().any(|ty| self.contains_struct(ty))
    }

    /// Check if a type contains (directly or nested) a struct type.
    fn contains_struct(&self, ty: &Type) -> bool {
        match ty {
            Type::Path(type_path) => {
                if let Some(seg) = type_path.path.segments.last() {
                    let type_name = seg.ident.to_string();
                    if self.abi_tuples.contains_key(&type_name) {
                        return true;
                    }

                    if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                        for arg in &args.args {
                            if let syn::GenericArgument::Type(inner_ty) = arg {
                                if self.contains_struct(inner_ty) {
                                    return true;
                                }
                            }
                        }
                    }
                }
                false
            }
            Type::Array(arr) => self.contains_struct(&arr.elem),
            Type::Tuple(tuple) => tuple.elems.iter().any(|e| self.contains_struct(e)),
            _ => false,
        }
    }

    /// Generate EIP-712 components implementation for a struct.
    ///
    /// Returns a TokenStream that produces a `Vec<Cow<'static, str>>` of component type strings.
    pub(super) fn generate_eip712_components(&self, struct_name: &Ident) -> TokenStream {
        let name = struct_name.to_string();
        let deps = self.get_transitive_dependencies(&name);

        if deps.is_empty() {
            quote! {
                alloy_sol_types::private::Vec::new()
            }
        } else {
            let dep_idents: Vec<Ident> = deps
                .iter()
                .map(|d| Ident::new(d, struct_name.span()))
                .collect();

            quote! {
                {
                    let mut components = alloy_sol_types::private::Vec::new();
                    #(
                        components.extend(<#dep_idents as alloy_sol_types::SolStruct>::eip712_components());
                        components.push(<#dep_idents as alloy_sol_types::SolStruct>::eip712_root_type());
                    )*
                    components.sort();
                    components.dedup();
                    components
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solidity::parser::{FieldDef, SolStructDef, SolidityModule, UnitEnumDef};
    use proc_macro2::Span;
    use quote::format_ident;
    use syn::{parse_quote, Visibility};

    fn make_field(name: &str, ty: Type) -> FieldDef {
        FieldDef {
            name: format_ident!("{}", name),
            ty,
            indexed: false,
            vis: Visibility::Public(syn::token::Pub {
                span: Span::call_site(),
            }),
        }
    }

    fn make_struct(name: &str, fields: Vec<FieldDef>) -> SolStructDef {
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

    fn make_unit_enum(name: &str, variants: Vec<&str>) -> UnitEnumDef {
        UnitEnumDef {
            name: format_ident!("{}", name),
            variants: variants.iter().map(|v| format_ident!("{}", v)).collect(),
            attrs: vec![],
            vis: Visibility::Public(syn::token::Pub {
                span: Span::call_site(),
            }),
        }
    }

    fn empty_module() -> SolidityModule {
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

    #[test]
    fn test_resolve_primitive() -> syn::Result<()> {
        let registry = TypeRegistry::default();
        assert_eq!(registry.resolve_abi(&parse_quote!(Address))?, "address");
        assert_eq!(registry.resolve_abi(&parse_quote!(U256))?, "uint256");
        assert_eq!(registry.resolve_abi(&parse_quote!(bool))?, "bool");
        Ok(())
    }

    #[test]
    fn test_resolve_unit_enum() -> syn::Result<()> {
        let mut module = empty_module();
        module
            .unit_enums
            .push(make_unit_enum("OrderStatus", vec!["Pending", "Filled"]));

        let registry = TypeRegistry::from_module(&module)?;
        assert_eq!(registry.resolve_abi(&parse_quote!(OrderStatus))?, "uint8");
        Ok(())
    }

    #[test]
    fn test_resolve_struct() -> syn::Result<()> {
        let mut module = empty_module();
        module.structs.push(make_struct(
            "Transfer",
            vec![
                make_field("from", parse_quote!(Address)),
                make_field("to", parse_quote!(Address)),
                make_field("amount", parse_quote!(U256)),
            ],
        ));

        let registry = TypeRegistry::from_module(&module)?;
        assert_eq!(
            registry.resolve_abi(&parse_quote!(Transfer))?,
            "(address,address,uint256)"
        );
        Ok(())
    }

    #[test]
    fn test_nested_structs() -> syn::Result<()> {
        let mut module = empty_module();

        module.structs.push(make_struct(
            "Inner",
            vec![make_field("value", parse_quote!(U256))],
        ));

        module.structs.push(make_struct(
            "Outer",
            vec![
                make_field("inner", parse_quote!(Inner)),
                make_field("extra", parse_quote!(Address)),
            ],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        assert_eq!(registry.resolve_abi(&parse_quote!(Inner))?, "(uint256)");
        assert_eq!(
            registry.resolve_abi(&parse_quote!(Outer))?,
            "((uint256),address)"
        );

        let sig = registry.compute_signature("process", &[parse_quote!(Outer)])?;
        assert_eq!(sig, "process(((uint256),address))");

        Ok(())
    }

    #[test]
    fn test_deeply_nested_structs() -> syn::Result<()> {
        let mut module = empty_module();

        module.structs.push(make_struct(
            "Level1",
            vec![make_field("value", parse_quote!(U256))],
        ));

        module.structs.push(make_struct(
            "Level2",
            vec![make_field("level1", parse_quote!(Level1))],
        ));

        module.structs.push(make_struct(
            "Level3",
            vec![
                make_field("level2", parse_quote!(Level2)),
                make_field("extra", parse_quote!(bool)),
            ],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        assert_eq!(registry.resolve_abi(&parse_quote!(Level1))?, "(uint256)");
        assert_eq!(registry.resolve_abi(&parse_quote!(Level2))?, "((uint256))");
        assert_eq!(
            registry.resolve_abi(&parse_quote!(Level3))?,
            "(((uint256)),bool)"
        );

        Ok(())
    }

    #[test]
    fn test_struct_with_array_of_structs() -> syn::Result<()> {
        let mut module = empty_module();

        module.structs.push(make_struct(
            "Item",
            vec![make_field("id", parse_quote!(U256))],
        ));

        module.structs.push(make_struct(
            "Container",
            vec![make_field("items", parse_quote!(Vec<Item>))],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        assert_eq!(registry.resolve_abi(&parse_quote!(Item))?, "(uint256)");
        assert_eq!(
            registry.resolve_abi(&parse_quote!(Container))?,
            "((uint256)[])"
        );

        Ok(())
    }

    #[test]
    fn test_cycle_detection() {
        let mut module = empty_module();

        module.structs.push(make_struct(
            "A",
            vec![make_field("b", parse_quote!(B))],
        ));

        module.structs.push(make_struct(
            "B",
            vec![make_field("a", parse_quote!(A))],
        ));

        let result = TypeRegistry::from_module(&module);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("circular dependency"));
    }

    #[test]
    fn test_topological_order() -> syn::Result<()> {
        let mut module = empty_module();

        module.structs.push(make_struct(
            "C",
            vec![make_field("b", parse_quote!(B))],
        ));
        module.structs.push(make_struct(
            "A",
            vec![make_field("value", parse_quote!(U256))],
        ));
        module.structs.push(make_struct(
            "B",
            vec![make_field("a", parse_quote!(A))],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        let sorted = registry.sorted_structs();
        let a_pos = sorted.iter().position(|s| s == "A").unwrap();
        let b_pos = sorted.iter().position(|s| s == "B").unwrap();
        let c_pos = sorted.iter().position(|s| s == "C").unwrap();

        assert!(a_pos < b_pos, "A must come before B");
        assert!(b_pos < c_pos, "B must come before C");

        Ok(())
    }

    #[test]
    fn test_transitive_dependencies() -> syn::Result<()> {
        let mut module = empty_module();

        module.structs.push(make_struct(
            "A",
            vec![make_field("value", parse_quote!(U256))],
        ));
        module.structs.push(make_struct(
            "B",
            vec![make_field("a", parse_quote!(A))],
        ));
        module.structs.push(make_struct(
            "C",
            vec![
                make_field("b", parse_quote!(B)),
                make_field("a", parse_quote!(A)),
            ],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        let deps_a = registry.get_transitive_dependencies("A");
        assert!(deps_a.is_empty());

        let deps_b = registry.get_transitive_dependencies("B");
        assert_eq!(deps_b, vec!["A"]);

        let deps_c = registry.get_transitive_dependencies("C");
        assert_eq!(deps_c, vec!["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_compute_signature() -> syn::Result<()> {
        let mut module = empty_module();
        module.structs.push(make_struct(
            "Transfer",
            vec![
                make_field("from", parse_quote!(Address)),
                make_field("to", parse_quote!(Address)),
                make_field("amount", parse_quote!(U256)),
            ],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        let sig = registry.compute_signature("transfer", &[parse_quote!(Transfer)])?;
        assert_eq!(sig, "transfer((address,address,uint256))");

        let sig2 = registry.compute_signature(
            "multiTransfer",
            &[parse_quote!(Transfer), parse_quote!(Address)],
        )?;
        assert_eq!(sig2, "multiTransfer((address,address,uint256),address)");

        Ok(())
    }

    #[test]
    fn test_has_struct_params() -> syn::Result<()> {
        let mut module = empty_module();
        module.structs.push(make_struct(
            "Transfer",
            vec![make_field("amount", parse_quote!(U256))],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        assert!(registry.has_struct_params(&[parse_quote!(Transfer)]));
        assert!(!registry.has_struct_params(&[parse_quote!(Address), parse_quote!(U256)]));
        assert!(registry.has_struct_params(&[parse_quote!(Vec<Transfer>)]));
        Ok(())
    }

    #[test]
    fn test_is_struct() -> syn::Result<()> {
        let mut module = empty_module();
        module.structs.push(make_struct(
            "Transfer",
            vec![make_field("amount", parse_quote!(U256))],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        assert!(registry.is_struct(&parse_quote!(Transfer)));
        assert!(!registry.is_struct(&parse_quote!(Address)));
        assert!(!registry.is_struct(&parse_quote!(OrderStatus)));
        Ok(())
    }

    #[test]
    fn test_is_unit_enum() -> syn::Result<()> {
        let mut module = empty_module();
        module
            .unit_enums
            .push(make_unit_enum("OrderStatus", vec!["Pending"]));

        let registry = TypeRegistry::from_module(&module)?;

        assert!(registry.is_unit_enum(&parse_quote!(OrderStatus)));
        assert!(!registry.is_unit_enum(&parse_quote!(Address)));
        assert!(!registry.is_unit_enum(&parse_quote!(Transfer)));
        Ok(())
    }

    #[test]
    fn test_struct_with_unit_enum_field() -> syn::Result<()> {
        let mut module = empty_module();

        module
            .unit_enums
            .push(make_unit_enum("Status", vec!["Active", "Inactive"]));

        module.structs.push(make_struct(
            "Order",
            vec![
                make_field("id", parse_quote!(U256)),
                make_field("status", parse_quote!(Status)),
            ],
        ));

        let registry = TypeRegistry::from_module(&module)?;

        assert_eq!(registry.resolve_abi(&parse_quote!(Order))?, "(uint256,uint8)");

        Ok(())
    }
}
