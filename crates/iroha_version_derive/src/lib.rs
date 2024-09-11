//! Crate containing schema related macro functionality

use std::ops::Range;

use darling::{ast::NestedMeta, FromMeta};
use manyhow::{bail, manyhow, Result};
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_quote,
    punctuated::Punctuated,
    Data, DeriveInput, Error as SynError, Ident, LitInt, Path, Result as SynResult, Token,
};

const VERSION_FIELD_NAME: &str = "version";
const CONTENT_FIELD_NAME: &str = "content";

/// Used to declare that this struct represents a particular version as a part of the versioned container.
///
/// Adds support for both scale codec and json serialization. To declare only with json support, use [`version_with_json()`], for scale — [`version_with_scale()`].
///
/// ### Arguments
/// - named `n: u8`: what version this particular struct represents.
/// - named `versioned: String`: to which versioned container to link this struct. Versioned containers are created with [`declare_versioned`](`declare_versioned()`).
///
/// ### Examples
/// See [`declare_versioned`](`declare_versioned()`).
#[manyhow]
#[proc_macro_attribute]
pub fn version(args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    impl_version(args, &item)
}

/// See [`version()`] for more information.
#[manyhow]
#[proc_macro_attribute]
pub fn version_with_scale(args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    impl_version(args, &item)
}

/// See [`version()`] for more information.
#[manyhow]
#[proc_macro_attribute]
pub fn version_with_json(args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    impl_version(args, &item)
}

/// Used to generate a versioned container with the given name and given range of supported versions.
///
/// Adds support for both scale codec and json serialization. To declare only with json support,
/// use [`declare_versioned_with_json`](`declare_versioned_with_json()`), for scale — [`declare_versioned_with_scale`](`declare_versioned_with_json()`).
///
/// It's a user responsibility to export `Box` so that this macro works properly
///
/// ### Arguments
/// 1. positional `versioned_enum_name`
/// 2. positional `supported_version_range`
///
/// ### Examples
///
/// ```rust
/// use parity_scale_codec::{Decode, Encode};
/// use serde::{Deserialize, Serialize};
/// use iroha_version_derive::{declare_versioned, version};
/// use iroha_version::json::*;
///
/// declare_versioned!(VersionedMessage 1..2, Debug, Clone, iroha_macro::FromVariant);
///
/// #[version(version = 1, versioned_alias = "VersionedMessage")]
/// #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
/// pub struct Message1;
///
/// let versioned_message: VersionedMessage = Message1.into();
/// let json = versioned_message.to_versioned_json_str().unwrap();
/// let decoded_message = VersionedMessage::from_versioned_json_str(&json).unwrap();
/// match decoded_message {
///    VersionedMessage::V1(message) => {
///        let _message: Message1 = message.into();
///        Ok(())
///    }
///    _ => Err("Unsupported version.".to_string()),
/// }.unwrap();
/// ```
#[manyhow]
#[proc_macro]
pub fn declare_versioned(input: TokenStream) -> Result<TokenStream> {
    let args = syn::parse2(input)?;
    Ok(impl_declare_versioned(&args, true, true))
}

/// See [`declare_versioned`](`declare_versioned()`) for more information.
#[manyhow]
#[proc_macro]
pub fn declare_versioned_with_scale(input: TokenStream) -> Result<TokenStream> {
    let args = syn::parse2(input)?;
    Ok(impl_declare_versioned(&args, true, false))
}

/// See [`declare_versioned`](`declare_versioned()`) for more information.
#[manyhow]
#[proc_macro]
pub fn declare_versioned_with_json(input: TokenStream) -> Result<TokenStream> {
    let args = syn::parse2(input)?;
    Ok(impl_declare_versioned(&args, false, true))
}

#[derive(FromMeta)]
struct VersionArgs {
    version: u32,
    versioned_alias: syn::Ident,
}

fn impl_version(args: TokenStream, item: &TokenStream) -> Result<TokenStream> {
    let args = NestedMeta::parse_meta_list(args)?;
    let VersionArgs {
        version,
        versioned_alias,
    } = VersionArgs::from_list(&args)?;

    let (struct_name, generics) = {
        let item = syn::parse2::<DeriveInput>(item.clone())?;
        match &item.data {
            Data::Struct(_) | Data::Enum(_) => {}
            _ => bail!("The attribute should be attached to either struct or enum."),
        }
        (item.ident, item.generics)
    };

    let alias_type_name = format_ident!("_{}V{}", versioned_alias, version);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    Ok(quote!(
        /// Autogenerated alias type to link versioned item to its container.
        #[allow(clippy::redundant_pub_crate)]
        pub(crate) type #alias_type_name #impl_generics = #struct_name #ty_generics #where_clause;

        #item
    ))
}

struct DeclareVersionedArgs {
    pub enum_name: Ident,
    pub generics: syn::Generics,
    pub range: Range<u8>,
    pub _comma: Option<Token![,]>,
    pub derive: Punctuated<Path, Token![,]>,
}

impl DeclareVersionedArgs {
    pub fn version_idents(&self) -> Vec<Ident> {
        self.range
            .clone()
            .map(|i| Ident::new(&format!("V{i}"), Span::call_site()))
            .collect()
    }

    pub fn version_struct_idents(&self) -> Vec<Ident> {
        self.range
            .clone()
            .map(|i| Ident::new(&format!("_{}V{}", self.enum_name, i), Span::call_site()))
            .collect()
    }

    pub fn version_numbers(&self) -> Vec<u8> {
        self.range.clone().collect()
    }
}

impl Parse for DeclareVersionedArgs {
    fn parse(input: ParseStream) -> SynResult<Self> {
        let enum_name: Ident = input.parse()?;
        let generics: syn::Generics = input.parse()?;
        let start_version: LitInt = input.parse()?;
        let start_version: u8 = start_version.base10_parse()?;
        let _: Token![..] = input.parse::<Token![..]>()?;
        let end_version: LitInt = input.parse()?;
        let end_version: u8 = end_version.base10_parse()?;
        if end_version <= start_version {
            return Err(SynError::new(
                Span::call_site(),
                "The end version should be higher then the start version.",
            ));
        }
        Ok(Self {
            enum_name,
            generics,
            range: start_version..end_version,
            _comma: input.parse()?,
            derive: Punctuated::parse_terminated(input)?,
        })
    }
}

fn impl_decode_versioned(enum_name: &Ident, generics: &syn::Generics) -> proc_macro2::TokenStream {
    let mut decode_where_clause = generics
        .where_clause
        .clone()
        .unwrap_or_else(|| parse_quote!(where));
    decode_where_clause
        .predicates
        .push(parse_quote!(Self: parity_scale_codec::DecodeAll));
    let mut encode_where_clause = generics
        .where_clause
        .clone()
        .unwrap_or_else(|| parse_quote!(where));
    encode_where_clause
        .predicates
        .push(parse_quote!(Self: parity_scale_codec::Encode));
    let (impl_generics, ty_generics, _) = generics.split_for_impl();

    quote! (
        impl #impl_generics iroha_version::scale::DecodeVersioned for #enum_name #ty_generics #decode_where_clause {
            fn decode_all_versioned(input: &[u8]) -> iroha_version::error::Result<Self> {
                use iroha_version::{error::Error, Version, UnsupportedVersion, RawVersioned};
                use parity_scale_codec::DecodeAll;

                if let Some(version) = input.first() {
                    if Self::supported_versions().contains(version) {
                        let mut input = input.clone();
                        Ok(Self::decode_all(&mut input)?)
                    } else {
                        Err(Error::UnsupportedVersion(Box::new(UnsupportedVersion::new(
                            *version,
                            RawVersioned::ScaleBytes(input.to_vec())
                        ))))
                    }
                } else {
                    Err(Error::NotVersioned)
                }
            }
        }

        impl #impl_generics iroha_version::scale::EncodeVersioned for #enum_name #ty_generics #encode_where_clause {
            fn encode_versioned(&self) -> Vec<u8> {
                use parity_scale_codec::Encode;

                self.encode()
            }
        }
    )
}

fn impl_json(
    enum_name: &Ident,
    generics: &syn::Generics,
    version_field_name: &str,
) -> proc_macro2::TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote!(
        impl #impl_generics iroha_version::json::DeserializeVersioned<'_> for #enum_name #ty_generics #where_clause {
            fn from_versioned_json_str(input: &str) -> iroha_version::error::Result<Self> {
                use iroha_version::{error::Error, Version, UnsupportedVersion, RawVersioned};
                use serde_json::Value;

                let json: Value = serde_json::from_str(input)?;
                if let Value::Object(map) = json {
                    if let Some(Value::String(version_number)) = map.get(#version_field_name) {
                        let version: u8 = version_number.parse()?;
                        if Self::supported_versions().contains(&version) {
                            Ok(serde_json::from_str(input)?)
                        } else {
                            Err(Error::UnsupportedVersion(Box::new(
                                UnsupportedVersion::new(version, RawVersioned::Json(String::from(input)))
                            )))
                        }
                    } else {
                        Err(Error::NotVersioned)
                    }
                } else {
                    Err(Error::ExpectedJson)
                }
            }
        }

        impl #impl_generics iroha_version::json::SerializeVersioned for #enum_name #ty_generics #where_clause {
            fn to_versioned_json_str(&self) -> iroha_version::error::Result<String> {
                Ok(serde_json::to_string(self)?)
            }
        }
    )
}

fn impl_declare_versioned(
    args: &DeclareVersionedArgs,
    with_scale: bool,
    with_json: bool,
) -> TokenStream {
    let version_idents = args.version_idents();
    let version_struct_idents = args.version_struct_idents();
    let version_numbers = args.version_numbers();
    let range_end = args.range.end;
    let range_start = args.range.start;
    let enum_name = &args.enum_name;
    let (impl_generics, ty_generics, where_clause) = args.generics.split_for_impl();
    let scale_impl = if with_scale {
        impl_decode_versioned(enum_name, &args.generics)
    } else {
        quote!()
    };
    let scale_derives = if with_scale {
        quote!(parity_scale_codec::Encode, parity_scale_codec::Decode,)
    } else {
        quote!()
    };
    let scale_variant_attributes: Vec<_> = version_numbers
        .iter()
        .map(|version| {
            if with_scale {
                quote!(#[codec(index = #version)])
            } else {
                quote!()
            }
        })
        .collect();
    let version_field_name = VERSION_FIELD_NAME;
    let json_impl = if with_json {
        impl_json(enum_name, &args.generics, version_field_name)
    } else {
        quote!()
    };
    let json_derives = if with_json {
        quote!(serde::Serialize, serde::Deserialize,)
    } else {
        quote!()
    };
    let content_field_name = CONTENT_FIELD_NAME;
    let json_enum_attribute = if with_json {
        quote!(#[serde(tag = #version_field_name, content = #content_field_name)])
    } else {
        quote!()
    };
    let json_variant_attributes: Vec<_> = version_numbers
        .iter()
        .map(|version| {
            if with_json {
                let version = version.to_string();
                quote!(#[serde(rename = #version)])
            } else {
                quote!()
            }
        })
        .collect();
    let derives = &args.derive;

    let enum_ = quote! {
        /// Autogenerated versioned container.
        #[derive(#scale_derives #json_derives #derives)]
        #json_enum_attribute
        pub enum #enum_name #ty_generics #where_clause {
            #(
                /// This variant represents a particular version.
                #scale_variant_attributes #json_variant_attributes
                #version_idents (#version_struct_idents #ty_generics),
            )*
        }
    };

    quote!(
        #enum_

        impl #impl_generics iroha_version::Version for #enum_name #ty_generics #where_clause {
            fn version(&self) -> u8 {
                match self {
                    #(#enum_name::#version_idents (_) => #version_numbers),*
                }
            }

            fn supported_versions() -> core::ops::Range<u8> {
                #range_start .. #range_end
            }
        }

        #scale_impl

        #json_impl
    )
}