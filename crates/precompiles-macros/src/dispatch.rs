use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    Expr, ExprPath, Ident, Pat, Path, PathArguments, PathSegment, Result, Token,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    spanned::Spanned,
};

// The macro assumes:
// - a `calldata: &[u8]` binding is in scope at the call site
// - every arm uses a qualified pattern `ICalls::variant(call) =>` to infer its `ICalls::abi_decode`

pub(crate) fn expand(input: TokenStream) -> Result<TokenStream> {
    let input = syn::parse2::<DispatchInput>(input)?;
    input.expand()
}

struct DispatchInput {
    decode: Expr,
    calls: Path,
    arms: Vec<DispatchArm>,
}

impl Parse for DispatchInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut arms = Vec::new();
        while !input.is_empty() {
            let arm: DispatchArm = input.parse()?;
            let needs_comma = arm_body_requires_comma(&arm.body);
            arms.push(arm);
            if input.is_empty() {
                break;
            }
            // Mirror Rust's `match` rule: arms with block-like bodies may omit the trailing comma.
            // All other bodies (call expressions, etc.) require it.
            if needs_comma {
                input.parse::<Token![,]>()?;
            } else {
                let _: Option<Token![,]> = input.parse()?;
            }
        }

        if arms.is_empty() {
            return Err(syn::Error::new(
                input.span(),
                "expected at least one dispatch arm",
            ));
        }

        let calls = infer_calls_from_arms(&arms).ok_or_else(|| {
            syn::Error::new(
                input.span(),
                "could not infer a decode path from the arm patterns; \
                 every arm must use a qualified pattern like `ICalls::variant(call) => ...`",
            )
        })?;
        let decode = build_decode_expr(&calls);

        Ok(Self {
            decode,
            calls,
            arms,
        })
    }
}

impl DispatchInput {
    fn expand(&self) -> Result<TokenStream> {
        let schedules = self
            .arms
            .iter()
            .try_fold(Vec::new(), |mut schedules, arm| {
                schedules.extend(arm.schedules(Some(&self.calls))?);
                Ok::<Vec<TokenStream>, syn::Error>(schedules)
            })?;

        let match_arms = self
            .arms
            .iter()
            .map(|arm| arm.expand(Some(&self.calls)))
            .collect::<Result<Vec<_>>>()?;

        let decode = &self.decode;

        let schedules = if schedules.is_empty() {
            quote!(&[])
        } else {
            quote!(&[#(#schedules),*])
        };

        Ok(quote! {
            crate::dispatch_call(
                calldata,
                #schedules,
                #decode,
                |call| match call {
                    #(#match_arms),*
                },
            )
        })
    }
}

struct DispatchArm {
    attrs: ArmAttrs,
    pat: Pat,
    body: Expr,
}

impl Parse for DispatchArm {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let attrs = ArmAttrs::parse(input)?;
        let pat = input.call(Pat::parse_multi_with_leading_vert)?;
        input.parse::<Token![=>]>()?;
        let body = input.parse()?;
        Ok(Self { attrs, pat, body })
    }
}

impl DispatchArm {
    fn expand(&self, calls: Option<&Path>) -> Result<TokenStream> {
        let pat = expand_match_pat(&self.pat, calls)?;
        let body = &self.body;
        Ok(quote!(#pat => #body))
    }

    fn schedules(&self, interface: Option<&Path>) -> Result<Vec<TokenStream>> {
        let mut schedules = Vec::new();
        if let Some(since) = &self.attrs.since {
            let selector = self.selector(interface)?;
            schedules.push(quote! {
                crate::SelectorSchedule::new(tempo_chainspec::hardfork::TempoHardfork::#since)
                    .with_added(&[#selector])
            });
        }
        if let Some(until) = &self.attrs.until {
            let selector = self.selector(interface)?;
            schedules.push(quote! {
                crate::SelectorSchedule::new(tempo_chainspec::hardfork::TempoHardfork::#until)
                    .with_dropped(&[#selector])
            });
        }
        Ok(schedules)
    }

    fn selector(&self, calls: Option<&Path>) -> Result<TokenStream> {
        if let Some(selector) = &self.attrs.selector {
            let selector = selector_path(selector, Ident::new("SELECTOR", selector.span()));
            return Ok(quote!(#selector));
        }

        if let Some((calls, variant)) = infer_calls_and_variant_from_pat(&self.pat) {
            return selector_from_calls_and_variant(&calls, &variant);
        }

        let calls = calls.ok_or_else(|| {
            syn::Error::new_spanned(
                &self.pat,
                "could not infer a selector from this pattern; use `#[selector = ...]`",
            )
        })?;
        let variant = infer_variant_ident(&self.pat).ok_or_else(|| {
            syn::Error::new_spanned(
                &self.pat,
                "could not infer a selector from this pattern; use `#[selector = ...]`",
            )
        })?;
        selector_from_calls_and_variant(calls, &variant)
    }
}

#[derive(Default)]
struct ArmAttrs {
    since: Option<Ident>,
    until: Option<Ident>,
    selector: Option<Path>,
}

impl ArmAttrs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut attrs = Self::default();

        while input.peek(Token![#]) {
            input.parse::<Token![#]>()?;
            let content;
            syn::bracketed!(content in input);

            let metas = Punctuated::<ArmMeta, Token![,]>::parse_terminated(&content)?;
            for meta in metas {
                match meta {
                    ArmMeta::Since(value) => {
                        if attrs.since.replace(value).is_some() {
                            return Err(syn::Error::new(
                                input.span(),
                                "duplicate `since` on dispatch arm",
                            ));
                        }
                    }
                    ArmMeta::Until(value) => {
                        if attrs.until.replace(value).is_some() {
                            return Err(syn::Error::new(
                                input.span(),
                                "duplicate `until` on dispatch arm",
                            ));
                        }
                    }
                    ArmMeta::Selector(value) => {
                        if attrs.selector.replace(value).is_some() {
                            return Err(syn::Error::new(
                                input.span(),
                                "duplicate `selector` on dispatch arm",
                            ));
                        }
                    }
                }
            }
        }

        Ok(attrs)
    }
}

enum ArmMeta {
    Since(Ident),
    Until(Ident),
    Selector(Path),
}

impl Parse for ArmMeta {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let key: Ident = input.parse()?;
        input.parse::<Token![=]>()?;

        match key.to_string().as_str() {
            "since" => Ok(Self::Since(input.parse()?)),
            "until" => Ok(Self::Until(input.parse()?)),
            "selector" => Ok(Self::Selector(input.parse()?)),
            _ => Err(syn::Error::new(
                key.span(),
                "expected `since`, `until`, or `selector`",
            )),
        }
    }
}

fn expand_match_pat(pat: &Pat, calls: Option<&Path>) -> Result<TokenStream> {
    if let Pat::TupleStruct(tuple) = pat
        && tuple.qself.is_none()
        && tuple.path.leading_colon.is_none()
        && tuple.path.segments.len() == 1
    {
        let calls = calls.ok_or_else(|| {
            syn::Error::new_spanned(
                pat,
                "shorthand dispatch arms require a decode path like `ICalls::abi_decode`",
            )
        })?;
        let variant = &tuple.path.segments[0].ident;
        let variant_path = selector_path(calls, variant.clone());
        let elems = &tuple.elems;
        return Ok(quote!(#variant_path(#elems)));
    }

    Ok(quote!(#pat))
}

fn infer_variant_ident(pat: &Pat) -> Option<Ident> {
    match pat {
        Pat::TupleStruct(tuple) => tuple
            .elems
            .iter()
            .find_map(infer_variant_ident)
            .or_else(|| {
                tuple
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.clone())
            }),
        Pat::Tuple(tuple) => tuple.elems.iter().find_map(infer_variant_ident),
        Pat::Paren(paren) => infer_variant_ident(&paren.pat),
        Pat::Reference(reference) => infer_variant_ident(&reference.pat),
        Pat::Type(typed) => infer_variant_ident(&typed.pat),
        Pat::Or(or) => or.cases.iter().find_map(infer_variant_ident),
        Pat::Slice(slice) => slice.elems.iter().find_map(infer_variant_ident),
        Pat::Struct(strukt) => strukt
            .fields
            .iter()
            .find_map(|field| infer_variant_ident(&field.pat)),
        _ => None,
    }
}

/// Infers the `calls` path from the first arm whose outermost pattern is a qualified tuple-struct.
fn arm_body_requires_comma(body: &Expr) -> bool {
    #[rustfmt::skip]
    !matches!(
        body,
        Expr::Block(_) | Expr::If(_) | Expr::Match(_) | Expr::Loop(_) | Expr::While(_) | Expr::ForLoop(_)
            | Expr::TryBlock(_) | Expr::Unsafe(_) | Expr::Const(_) | Expr::Async(_)
    )
}

fn infer_calls_from_arms(arms: &[DispatchArm]) -> Option<Path> {
    arms.iter().find_map(|arm| infer_calls_from_pat(&arm.pat))
}

/// Returns the `calls` path from the outermost tuple-struct pattern
fn infer_calls_from_pat(pat: &Pat) -> Option<Path> {
    match pat {
        Pat::TupleStruct(tuple) => path_prefix(&tuple.path),
        Pat::Or(or) => or.cases.iter().find_map(infer_calls_from_pat),
        Pat::Paren(p) => infer_calls_from_pat(&p.pat),
        Pat::Reference(r) => infer_calls_from_pat(&r.pat),
        Pat::Type(t) => infer_calls_from_pat(&t.pat),
        _ => None,
    }
}

/// Constructs `calls::abi_decode` as an `Expr` from a `calls` path.
fn build_decode_expr(calls: &Path) -> Expr {
    let mut path = calls.clone();
    path.segments.push(PathSegment {
        ident: Ident::new("abi_decode", Span::call_site()),
        arguments: PathArguments::None,
    });
    Expr::Path(ExprPath {
        attrs: vec![],
        qself: None,
        path,
    })
}

fn infer_calls_and_variant_from_pat(pat: &Pat) -> Option<(Path, Ident)> {
    match pat {
        Pat::TupleStruct(tuple) => tuple
            .elems
            .iter()
            .find_map(infer_calls_and_variant_from_pat)
            .or_else(|| {
                let variant = tuple.path.segments.last()?.ident.clone();
                let calls = path_prefix(&tuple.path)?;
                Some((calls, variant))
            }),
        Pat::Tuple(tuple) => tuple
            .elems
            .iter()
            .find_map(infer_calls_and_variant_from_pat),
        Pat::Paren(paren) => infer_calls_and_variant_from_pat(&paren.pat),
        Pat::Reference(reference) => infer_calls_and_variant_from_pat(&reference.pat),
        Pat::Type(typed) => infer_calls_and_variant_from_pat(&typed.pat),
        Pat::Or(or) => or.cases.iter().find_map(infer_calls_and_variant_from_pat),
        Pat::Slice(slice) => slice
            .elems
            .iter()
            .find_map(infer_calls_and_variant_from_pat),
        Pat::Struct(strukt) => strukt
            .fields
            .iter()
            .find_map(|field| infer_calls_and_variant_from_pat(&field.pat)),
        _ => None,
    }
}

fn path_prefix(path: &Path) -> Option<Path> {
    if path.segments.len() < 2 {
        return None;
    }

    let mut prefix = path.clone();
    prefix.segments.pop();
    Some(prefix)
}

fn selector_from_calls_and_variant(calls: &Path, variant: &Ident) -> Result<TokenStream> {
    let interface = infer_interface_from_calls(calls).ok_or_else(|| {
        syn::Error::new_spanned(
            calls,
            "could not derive an interface path from this decode/pattern path; use `#[selector = ...]`",
        )
    })?;
    let selector = format_ident!("{}Call", variant);
    let selector = selector_path(
        &selector_path(&interface, selector),
        Ident::new("SELECTOR", variant.span()),
    );
    Ok(quote!(#selector))
}

fn infer_interface_from_calls(calls: &Path) -> Option<Path> {
    let last = calls.segments.last()?;
    let last_name = last.ident.to_string();
    let interface_name = last_name.strip_suffix("Calls")?;
    if interface_name.is_empty() {
        return None;
    }

    let mut interface = calls.clone();
    let interface_ident = Ident::new(interface_name, last.ident.span());

    let duplicate_parent = interface
        .segments
        .iter()
        .rev()
        .nth(1)
        .map(|segment| segment.ident == interface_ident)
        .unwrap_or(false);

    if duplicate_parent {
        interface.segments.pop();
    } else {
        let slot = interface.segments.last_mut()?;
        *slot = PathSegment {
            ident: interface_ident,
            arguments: PathArguments::None,
        };
    }

    Some(interface)
}

fn selector_path(path: &Path, ident: Ident) -> Path {
    let mut path = path.clone();
    path.segments.push(PathSegment {
        ident,
        arguments: PathArguments::None,
    });
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(tokens: proc_macro2::TokenStream) -> Vec<DispatchArm> {
        match syn::parse2::<DispatchInput>(tokens) {
            Ok(input) => input.arms,
            Err(err) => panic!("parse failed: {err}"),
        }
    }

    fn parse_err(tokens: proc_macro2::TokenStream) -> String {
        syn::parse2::<DispatchInput>(tokens)
            .err()
            .expect("expected parse error")
            .to_string()
    }

    #[test]
    fn body_with_nested_commas_in_call() {
        // Commas inside `()` and `||` of the body must not be treated as arm separators.
        let arms = parse_ok(quote! {
            ICalls::foo(call) => view(call, |c| do_stuff(c.a, c.b, c.c)),
            ICalls::bar(call) => view(call, |c| self.bar(c)),
        });
        assert_eq!(arms.len(), 2);
    }

    #[test]
    fn body_with_block_and_internal_commas() {
        let arms = parse_ok(quote! {
            ICalls::foo(call) => view(call, |c| {
                let (a, b) = split(c);
                combine(a, b, c.extra)
            }),
            ICalls::bar(call) => view(call, |_| Ok(())),
        });
        assert_eq!(arms.len(), 2);
    }

    #[test]
    fn block_body_allows_optional_trailing_comma() {
        // A block-bodied arm may omit the trailing comma (matches Rust `match` semantics).
        let arms = parse_ok(quote! {
            ICalls::foo(call) => {
                let x = thing(call.a, call.b);
                view(call, |_| Ok(x))
            }
            ICalls::bar(call) => view(call, |_| Ok(())),
        });
        assert_eq!(arms.len(), 2);
    }

    #[test]
    fn non_block_body_requires_trailing_comma() {
        // Two call-expression arms without a separating comma must error.
        let err = parse_err(quote! {
            ICalls::foo(call) => view(call, |_| Ok(()))
            ICalls::bar(call) => view(call, |_| Ok(()))
        });
        assert!(err.contains("expected `,`"), "unexpected error: {err}");
    }

    #[test]
    fn or_pattern_with_leading_vert() {
        let arms = parse_ok(quote! {
            | ICalls::foo(call) | ICalls::bar(call) => view(call, |c| self.handle(c)),
        });
        assert_eq!(arms.len(), 1);
    }
}
