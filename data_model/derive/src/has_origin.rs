use darling::{FromDeriveInput, FromVariant};
use iroha_macro_utils::{attr_struct, parse_single_list_attr, parse_single_list_attr_opt, Emitter};
use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_quote, Ident, Token, Type};

mod kw {
    syn::custom_keyword!(origin);
}

const HAS_ORIGIN_ATTR: &str = "has_origin";

pub struct HasOriginEnum {
    ident: Ident,
    #[allow(unused)]
    generics: syn::Generics,
    variants: Vec<HasOriginVariant>,
    origin: Type,
}

impl FromDeriveInput for HasOriginEnum {
    fn from_derive_input(input: &syn::DeriveInput) -> darling::Result<Self> {
        let ident = input.ident.clone();
        let generics = input.generics.clone();

        let Some(variants) =
            darling::ast::Data::<HasOriginVariant, ()>::try_from(&input.data)?.take_enum()
        else {
            return Err(darling::Error::custom("Expected enum"));
        };

        let origin = parse_single_list_attr::<OriginAttr>(HAS_ORIGIN_ATTR, &input.attrs)?.ty;

        Ok(Self {
            ident,
            generics,
            variants,
            origin,
        })
    }
}

pub struct HasOriginVariant {
    ident: Ident,
    extractor: Option<OriginExtractorAttr>,
}

impl FromVariant for HasOriginVariant {
    fn from_variant(variant: &syn::Variant) -> darling::Result<Self> {
        let ident = variant.ident.clone();
        let extractor = parse_single_list_attr_opt(HAS_ORIGIN_ATTR, &variant.attrs)?;

        Ok(Self { ident, extractor })
    }
}

attr_struct! {
    pub struct OriginAttr {
        _kw: kw::origin,
        _eq: Token![=],
        ty: Type,
    }
}

attr_struct! {
    pub struct OriginExtractorAttr {
        ident: Ident,
        _eq: Token![=>],
        extractor: syn::Expr,
    }
}

pub fn impl_has_origin(emitter: &mut Emitter, input: &syn::DeriveInput) -> TokenStream {
    let Some(enum_) = emitter.handle(HasOriginEnum::from_derive_input(input)) else {
        return quote!();
    };

    if enum_.variants.is_empty() {
        return quote!();
    }

    let enum_ident = &enum_.ident;
    let enum_origin = &enum_.origin;
    let variants_match_arms = &enum_
        .variants
        .iter()
        .map(|variant| {
            let variant_ident = &variant.ident;
            variant.extractor.as_ref().map_or_else(
                || parse_quote!(#variant_ident(inner) => inner,),
                |extractor| {
                    let extractor_ident = &extractor.ident;
                    let extractor_expr = &extractor.extractor;
                    parse_quote!(#variant_ident(#extractor_ident) => #extractor_expr,)
                },
            )
        })
        .collect::<Vec<syn::Arm>>();

    let (impl_generics, ty_generics, where_clause) = enum_.generics.split_for_impl();

    quote! {
        impl #impl_generics HasOrigin for #enum_ident #ty_generics #where_clause {
            type Origin = #enum_origin;

            fn origin_path(&self) -> &Self::Origin {
                use #enum_ident::*;
                match self {
                    #(
                        #variants_match_arms
                    )*
                }
            }
        }
    }
}
