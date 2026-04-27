use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Expr, ExprPath, Ident, Pat, Path, PathArguments, PathSegment, Result, Token, braced,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    spanned::Spanned,
};

pub(crate) fn expand(input: TokenStream) -> Result<TokenStream> {
    let input = syn::parse2::<DispatchInput>(input)?;
    input.expand()
}

struct DispatchInput {
    calldata: Expr,
    decode: Expr,
    calls: Option<Path>,
    arms: Vec<DispatchArm>,
}

impl Parse for DispatchInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let calldata = input.parse()?;
        input.parse::<Token![,]>()?;

        let decode = input.parse()?;
        input.parse::<Token![,]>()?;

        let content;
        braced!(content in input);

        let mut arms = Vec::new();
        while !content.is_empty() {
            arms.push(content.parse()?);
            if content.is_empty() {
                break;
            }
            content.parse::<Token![,]>()?;
        }

        if !input.is_empty() {
            input.parse::<Token![,]>()?;
        }

        if arms.is_empty() {
            return Err(syn::Error::new(
                input.span(),
                "expected at least one dispatch arm",
            ));
        }

        let calls = infer_calls_from_decode(&decode);

        Ok(Self {
            calldata,
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
                schedules.extend(arm.schedules(self.calls.as_ref())?);
                Ok::<Vec<TokenStream>, syn::Error>(schedules)
            })?;

        let match_arms = self
            .arms
            .iter()
            .map(|arm| arm.expand(self.calls.as_ref()))
            .collect::<Result<Vec<_>>>()?;

        let calldata = &self.calldata;
        let decode = &self.decode;

        let schedules = if schedules.is_empty() {
            quote!(&[])
        } else {
            quote!(&[#(#schedules),*])
        };

        Ok(quote! {
            crate::dispatch_call(
                #calldata,
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
        if let Some(to) = &self.attrs.to {
            let selector = self.selector(interface)?;
            schedules.push(quote! {
                crate::SelectorSchedule::new(tempo_chainspec::hardfork::TempoHardfork::#to)
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
    to: Option<Ident>,
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
                    ArmMeta::To(value) => {
                        if attrs.to.replace(value).is_some() {
                            return Err(syn::Error::new(
                                input.span(),
                                "duplicate `to` on dispatch arm",
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
    To(Ident),
    Selector(Path),
}

impl Parse for ArmMeta {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let key: Ident = input.parse()?;
        input.parse::<Token![=]>()?;

        match key.to_string().as_str() {
            "since" => Ok(Self::Since(input.parse()?)),
            "to" => Ok(Self::To(input.parse()?)),
            "selector" => Ok(Self::Selector(input.parse()?)),
            _ => Err(syn::Error::new(
                key.span(),
                "expected `since`, `to`, or `selector`",
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

fn infer_calls_from_decode(decode: &Expr) -> Option<Path> {
    let Expr::Path(ExprPath {
        qself: None, path, ..
    }) = decode
    else {
        return None;
    };

    let last = path.segments.last()?;
    if last.ident != "abi_decode" {
        return None;
    }

    path_prefix(path)
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
