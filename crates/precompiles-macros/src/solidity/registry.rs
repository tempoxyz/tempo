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

use super::parser::{FieldDef, SolStructDef, SolidityModule, UnitEnumDef};

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
    pub(super) sorted_structs: Vec<String>,
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

        let sorted = std::mem::take(&mut registry.sorted_structs);
        for name in &sorted {
            if let Some(def) = struct_map.get(name) {
                registry.compute_struct_abi(def)?;
            }
        }
        registry.sorted_structs = sorted;

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
            let mut deps = HashSet::new();
            for field in &def.fields {
                Self::collect_type_dependencies(&field.ty, struct_map, &mut deps);
            }
            self.struct_deps
                .insert(name.clone(), deps.into_iter().collect());
        }
        Ok(())
    }

    /// Recursively collect struct type dependencies from a type.
    fn collect_type_dependencies(
        ty: &Type,
        struct_map: &HashMap<String, &SolStructDef>,
        deps: &mut HashSet<String>,
    ) {
        match ty {
            Type::Path(type_path) => {
                if let Some(seg) = type_path.path.segments.last() {
                    let type_name = seg.ident.to_string();

                    if struct_map.contains_key(&type_name) {
                        deps.insert(type_name);
                    }

                    if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                        for arg in &args.args {
                            if let syn::GenericArgument::Type(inner_ty) = arg {
                                Self::collect_type_dependencies(inner_ty, struct_map, deps);
                            }
                        }
                    }
                }
            }
            Type::Array(arr) => {
                Self::collect_type_dependencies(&arr.elem, struct_map, deps);
            }
            Type::Tuple(tuple) => {
                for elem in &tuple.elems {
                    Self::collect_type_dependencies(elem, struct_map, deps);
                }
            }
            _ => {}
        }
    }

    /// Perform topological sort with cycle detection using Kahn's algorithm.
    fn topological_sort(&mut self, struct_map: &HashMap<String, &SolStructDef>) -> syn::Result<()> {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut reverse_deps: HashMap<String, Vec<String>> = HashMap::new();

        for name in struct_map.keys() {
            in_degree.insert(name.clone(), 0);
            reverse_deps.insert(name.clone(), Vec::new());
        }

        for (name, deps) in &self.struct_deps {
            for dep in deps {
                if struct_map.contains_key(dep)
                    && let (Some(deg), Some(rdeps)) =
                        (in_degree.get_mut(name), reverse_deps.get_mut(dep))
                {
                    *deg += 1;
                    rdeps.push(name.clone());
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
                            let pos = queue.binary_search(dependent).unwrap_or_else(|p| p);
                            queue.insert(pos, dependent.clone());
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
                format!("circular dependency detected among structs: {cycle_members}"),
            ));
        }

        self.sorted_structs = sorted;
        Ok(())
    }

    /// Compute and store the ABI tuple for a struct.
    fn compute_struct_abi(&mut self, def: &SolStructDef) -> syn::Result<()> {
        let name = def.name.to_string();

        let parts: syn::Result<Vec<String>> =
            def.fields.iter().map(|f| self.resolve_abi(&f.ty)).collect();

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

                    if let syn::PathArguments::AngleBracketed(args) = &seg.arguments
                        && seg.ident == "Vec"
                        && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
                    {
                        let inner_abi = self.resolve_abi(inner)?;
                        return Ok(format!("{inner_abi}[]"));
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
                    Ok(format!("{inner_abi}[{len}]"))
                } else {
                    Ok(format!("{inner_abi}[]"))
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

    /// Compute signature from field definitions.
    pub(super) fn compute_signature_from_fields(
        &self,
        name: &str,
        fields: &[FieldDef],
    ) -> syn::Result<String> {
        let types: Vec<_> = fields.iter().map(|f| f.ty.clone()).collect();
        self.compute_signature(name, &types)
    }

    /// Check if a type is a registered struct.
    #[cfg(test)]
    pub(super) fn is_struct(&self, ty: &Type) -> bool {
        if let Type::Path(type_path) = ty
            && let Some(seg) = type_path.path.segments.last()
        {
            return self.abi_tuples.contains_key(&seg.ident.to_string());
        }
        false
    }

    /// Check if a type is a registered unit enum.
    #[cfg(test)]
    pub(super) fn is_unit_enum(&self, ty: &Type) -> bool {
        if let Type::Path(type_path) = ty
            && let Some(seg) = type_path.path.segments.last()
        {
            return self.unit_enums.contains(&seg.ident.to_string());
        }
        false
    }

    // ========================================================================
    // EIP-712 Component Support
    // ========================================================================

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
    use crate::solidity::test_utils::{empty_module, make_field, make_struct, make_unit_enum};
    use syn::parse_quote;

    #[test]
    fn test_resolve_abi_types() -> syn::Result<()> {
        // Primitives (no module needed)
        let registry = TypeRegistry::default();
        assert_eq!(registry.resolve_abi(&parse_quote!(Address))?, "address");
        assert_eq!(registry.resolve_abi(&parse_quote!(U256))?, "uint256");
        assert_eq!(registry.resolve_abi(&parse_quote!(bool))?, "bool");

        // Unit enum -> uint8
        let mut module = empty_module();
        module
            .unit_enums
            .push(make_unit_enum("OrderStatus", vec!["Pending", "Filled"]));
        let registry = TypeRegistry::from_module(&module)?;
        assert_eq!(registry.resolve_abi(&parse_quote!(OrderStatus))?, "uint8");

        // Struct -> tuple
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

        // Struct with unit enum field
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
        assert_eq!(
            registry.resolve_abi(&parse_quote!(Order))?,
            "(uint256,uint8)"
        );

        Ok(())
    }

    #[test]
    fn test_nested_struct_resolution() -> syn::Result<()> {
        // Simple nesting: Outer { inner: Inner }
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
        assert_eq!(
            registry.compute_signature("process", &[parse_quote!(Outer)])?,
            "process(((uint256),address))"
        );

        // Deep nesting: Level3 { Level2 { Level1 } }
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

        // Array of structs: Container { items: Vec<Item> }
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
    fn test_type_classification() -> syn::Result<()> {
        let mut module = empty_module();
        module.structs.push(make_struct(
            "Transfer",
            vec![make_field("amount", parse_quote!(U256))],
        ));
        module
            .unit_enums
            .push(make_unit_enum("OrderStatus", vec!["Pending"]));
        let registry = TypeRegistry::from_module(&module)?;

        // is_struct
        assert!(registry.is_struct(&parse_quote!(Transfer)));
        assert!(!registry.is_struct(&parse_quote!(Address)));
        assert!(!registry.is_struct(&parse_quote!(OrderStatus)));

        // is_unit_enum
        assert!(registry.is_unit_enum(&parse_quote!(OrderStatus)));
        assert!(!registry.is_unit_enum(&parse_quote!(Address)));
        assert!(!registry.is_unit_enum(&parse_quote!(Transfer)));

        Ok(())
    }

    #[test]
    fn test_cycle_detection() {
        let mut module = empty_module();
        module
            .structs
            .push(make_struct("A", vec![make_field("b", parse_quote!(B))]));
        module
            .structs
            .push(make_struct("B", vec![make_field("a", parse_quote!(A))]));
        let result = TypeRegistry::from_module(&module);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("circular dependency")
        );
    }

    #[test]
    fn test_topological_order() -> syn::Result<()> {
        let mut module = empty_module();
        module
            .structs
            .push(make_struct("C", vec![make_field("b", parse_quote!(B))]));
        module.structs.push(make_struct(
            "A",
            vec![make_field("value", parse_quote!(U256))],
        ));
        module
            .structs
            .push(make_struct("B", vec![make_field("a", parse_quote!(A))]));
        let registry = TypeRegistry::from_module(&module)?;

        let a_pos = registry
            .sorted_structs
            .iter()
            .position(|s| s == "A")
            .unwrap();
        let b_pos = registry
            .sorted_structs
            .iter()
            .position(|s| s == "B")
            .unwrap();
        let c_pos = registry
            .sorted_structs
            .iter()
            .position(|s| s == "C")
            .unwrap();
        assert!(a_pos < b_pos && b_pos < c_pos);

        Ok(())
    }

    #[test]
    fn test_transitive_dependencies() -> syn::Result<()> {
        let mut module = empty_module();
        module.structs.push(make_struct(
            "A",
            vec![make_field("value", parse_quote!(U256))],
        ));
        module
            .structs
            .push(make_struct("B", vec![make_field("a", parse_quote!(A))]));
        module.structs.push(make_struct(
            "C",
            vec![
                make_field("b", parse_quote!(B)),
                make_field("a", parse_quote!(A)),
            ],
        ));
        let registry = TypeRegistry::from_module(&module)?;

        assert!(registry.get_transitive_dependencies("A").is_empty());
        assert_eq!(registry.get_transitive_dependencies("B"), vec!["A"]);
        assert_eq!(registry.get_transitive_dependencies("C"), vec!["A", "B"]);

        Ok(())
    }
}
