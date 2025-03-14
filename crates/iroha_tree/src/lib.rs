//! A transitional crate that can be merged into other crates.
//!
//! It aims to integrate executables, events, and event filters while enabling recursive trigger prediction in a static manner.
//! The prediction is based on the union of possible execution paths, enabling pessimistic event loop detection.
//!
//! Additionally, to improve performance, it consolidates:
//!
//! - Instructions into a single [`ChangeSet`] per transaction.
//! - (Data) events into a single [`Event`] per transaction.
//! - (Data) event filters into a single [`Receptor`] per trigger.
//! - Permissions, roles, and ownerships into a single [`Permission`] per validation.

#![allow(missing_docs)] // SATO disallow
#![allow(dead_code)] // SATO disallow
#![expect(missing_copy_implementations)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::{
    convert::Infallible,
    fmt::{self, Debug, Display},
    ops::{Add, BitOr},
    str::FromStr,
};

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    collections::{btree_map, BTreeMap, BTreeSet},
    rc::Rc,
    vec,
    vec::Vec,
};
#[cfg(feature = "std")]
use std::{
    collections::{btree_map, BTreeMap, BTreeSet},
    rc::Rc,
};

use derive_more::{BitOr, Constructor, DebugCustom, From};
use parity_scale_codec::{Decode, Encode};
use serde_with::{DeserializeFromStr, SerializeDisplay};

/// A flattened node map with a fixed skeleton equivalent to the world state.
/// Node values may vary by [`Mode`].
#[derive(Debug, PartialEq, Eq, Decode, Encode)]
pub struct Tree<M: Mode>(BTreeMap<NodeKey, NodeValue<M>>);

/// The same structure as [`Tree`], except that node keys can represent a certain group of nodes.
#[derive(Debug, PartialEq, Eq, Decode, Encode)]
pub struct FuzzyTree<M: Mode>(BTreeMap<FuzzyNodeKey, NodeValue<M>>);

macro_rules! declare_nodes {
    ($(($variant:ident, $key:ident, $fuzzy_key:ident: $($key_element:ty),*),)+) => {
        /// Exact path to nodes:
        /// Can be considered as composite primary keys in an RDB.
        #[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Decode, Encode)]
        pub enum NodeKey {
            $(
            $variant($key),
            )+
        }

        $(
        declare_nodes!(_key_alias $key: $($key_element),*);
        )+

        /// Fuzzy path to nodes:
        /// A `None` key element represents __any__ node.
        /// For example, `(None, Some(domain)): AccountKey` represents any account within the specified `domain`.
        #[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Decode, Encode)]
        pub enum FuzzyNodeKey {
            $(
            $variant($fuzzy_key),
            )+
        }

        $(
        declare_nodes!(_fuzzy_key_alias $fuzzy_key: $($key_element),*);
        )+

        /// Represents various states such as the current state, intention, result, or readiness at the node.
        #[derive(Debug, PartialEq, Eq, Decode, Encode)]
        pub enum NodeValue<M: Mode> {
            $(
            $variant(M::$variant),
            )+
        }

        /// This trait implementation serves as a declaration of node values.
        pub trait Mode {
            $(
            type $variant: Debug + PartialEq + Eq + Decode + Encode;
            )+
        }
    };
    (_key_alias $key:ident:) => {
        type $key = ();
    };
    (_key_alias $key:ident: $key_element:ty) => {
        type $key = Rc<$key_element>;
    };
    (_key_alias $key:ident: $key_element_head:ty, $($key_element:ty),+) => {
        type $key = (Rc<$key_element_head>, $(Rc<$key_element>),+);
    };
    (_fuzzy_key_alias $key:ident:) => {
        type $key = ();
    };
    (_fuzzy_key_alias $key:ident: $key_element:ty) => {
        type $key = Option<Rc<$key_element>>;
    };
    (_fuzzy_key_alias $key:ident: $key_element_head:ty, $($key_element:ty),+) => {
        type $key = (Option<Rc<$key_element_head>>, $(Option<Rc<$key_element>>),+);
    };
}

declare_nodes!(
    (Authorizer, AuthorizerK, AuthorizerKF:),
    (Parameter, ParameterK, ParameterKF: tr::ParameterId),
    (Peer, PeerK, PeerKF: dm::PeerId),
    (Domain, DomainK, DomainKF: dm::DomainId),
    (Account, AccountK, AccountKF: dm::PublicKey, dm::DomainId),
    (Asset, AssetK, AssetKF: dm::Name, dm::DomainId),
    (Nft, NftK, NftKF: dm::Name, dm::DomainId),
    (AccountAsset, AccountAssetK, AccountAssetKF: dm::PublicKey, dm::DomainId, dm::Name, dm::DomainId),
    (Role, RoleK, RoleKF: dm::RoleId),
    (Permission, PermissionK, PermissionKF: tr::PermissionId),
    (AccountRole, AccountRoleK, AccountRoleKF: dm::PublicKey, dm::DomainId, dm::RoleId),
    (AccountPermission, AccountPermissionK, AccountPermissionKF: dm::PublicKey, dm::DomainId, tr::PermissionId),
    (RolePermission, RolePermissionK, RolePermissionKF: dm::RoleId, tr::PermissionId),
    (Trigger, TriggerK, TriggerKF: dm::TriggerId),
    (Condition, ConditionK, ConditionKF: tr::ConditionId),
    (Executable, ExecutableK, ExecutableKF: tr::ExecutableId),
    (TriggerCondition, TriggerConditionK, TriggerConditionKF: dm::TriggerId, tr::ConditionId),
    (TriggerExecutable, TriggerExecutableK, TriggerExecutableKF: dm::TriggerId, tr::ExecutableId),
    (DomainMetadata, DomainMetadataK, DomainMetadataKF: dm::DomainId, dm::Name),
    (AccountMetadata, AccountMetadataK, AccountMetadataKF: dm::PublicKey, dm::DomainId, dm::Name),
    (AssetMetadata, AssetMetadataK, AssetMetadataKF: dm::Name, dm::DomainId, dm::Name),
    (NftData, NftDataK, NftDataKF: dm::Name, dm::DomainId, dm::Name),
    (TriggerMetadata, TriggerMetadataK, TriggerMetadataKF: dm::TriggerId, dm::Name),
    (DomainAdmin, DomainAdminK, DomainAdminKF: dm::DomainId, dm::PublicKey, dm::DomainId),
    (AssetAdmin, AssetAdminK, AssetAdminKF: dm::Name, dm::DomainId, dm::PublicKey, dm::DomainId),
    (NftAdmin, NftAdminK, NftAdminKF: dm::Name, dm::DomainId, dm::PublicKey, dm::DomainId),
    (NftOwner, NftOwnerK, NftOwnerKF: dm::Name, dm::DomainId, dm::PublicKey, dm::DomainId),
    (TriggerAdmin, TriggerAdminK, TriggerAdminKF: dm::TriggerId, dm::PublicKey, dm::DomainId),
);

pub trait NodeReadWrite: Filtered {
    type Status: Filtered;

    fn as_status(&self) -> Self::Status;
}

pub trait Filtered {
    type Filter;

    /// # Errors
    ///
    /// Returns the difference from the expected filter required for `self` to pass.
    fn passes(&self, filter: &Self::Filter) -> Result<(), Self::Filter>;
}

#[derive(
    DebugCustom,
    PartialEq,
    Eq,
    Clone,
    Copy,
    From,
    BitOr,
    SerializeDisplay,
    DeserializeFromStr,
    Decode,
    Encode,
)]
pub struct FilterU8(#[debug("{_0:#010b}")] u8);

impl Filtered for FilterU8 {
    type Filter = Self;

    fn passes(&self, filter: &Self::Filter) -> Result<(), Self::Filter> {
        let obstacle = self.0 & !filter.0;
        if obstacle == 0 {
            Ok(())
        } else {
            Err(obstacle.into())
        }
    }
}

impl FromStr for FilterU8 {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let byte = event::STATUS_CHARS.into_iter().fold(u8::MIN, |mut acc, c| {
            acc <<= 1;
            acc + u8::from(s.contains(c))
        });
        Ok(byte.into())
    }
}

impl Display for FilterU8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut byte = self.0;
        for c in event::STATUS_CHARS {
            if byte & 0b1000_0000 == 0b1000_0000 {
                write!(f, "{c}")?;
            } else {
                write!(f, "-")?;
            }
            byte <<= 1;
        }
        Ok(())
    }
}

impl FilterU8 {
    const ANY: Self = Self(u8::MAX);
    const DENY: Self = Self(u8::MIN);
}

#[derive(Debug, Constructor)]
/// SATO docs, impl Error
pub struct NodeConflict<M: Mode> {
    pub key: NodeKey,
    pub lhs: NodeValue<M>,
    pub rhs: NodeValue<M>,
}

impl NodeKey {
    fn fuzzy(&self) -> FuzzyNodeKey {
        self.receptor_keys().last().unwrap().clone()
    }
}

trait NodeKeyValue {
    fn node_type(&self) -> NodeType;
}

// This should be asserted whenever constructing key-value pairs, as type safety was lost during tree size reduction.
fn consistent_key_value(key: &impl NodeKeyValue, value: &impl NodeKeyValue) -> bool {
    key.node_type() == value.node_type()
}

macro_rules! impl_for_node_key_values {
    ($($variant:ident,)+) => {
        #[derive(Debug, PartialEq, Eq)]
        enum NodeType {
            $(
            $variant,
            )+
        }

        impl NodeKeyValue for NodeKey {
            fn node_type(&self) -> NodeType {
                match self {
                    $(
                    Self::$variant(_) => NodeType::$variant,
                    )+
                }
            }
        }

        impl NodeKeyValue for FuzzyNodeKey {
            fn node_type(&self) -> NodeType {
                match self {
                    $(
                    Self::$variant(_) => NodeType::$variant,
                    )+
                }
            }
        }

        impl<M: Mode> NodeKeyValue for NodeValue<M> {
            fn node_type(&self) -> NodeType {
                match self {
                    $(
                    Self::$variant(_) => NodeType::$variant,
                    )+
                }
            }
        }

        impl From<&NodeValue<state::State>> for NodeValue<event::ReadWriteStatus> {
            fn from(value: &NodeValue<state::State>) -> Self {
                match value {
                    $(
                    NodeValue::$variant(state) => Self::$variant(state.into()),
                    )+
                }
            }
        }

        impl From<&NodeValue<changeset::Write>> for NodeValue<event::ReadWriteStatus> {
            fn from(value: &NodeValue<changeset::Write>) -> Self {
                match value {
                    $(
                    NodeValue::$variant(write) => Self::$variant(write.into()),
                    )+
                }
            }
        }

        impl From<&NodeValue<event::ReadWriteStatus>> for FilterU8 {
            fn from(value: &NodeValue<event::ReadWriteStatus>) -> Self {
                match value {
                    $(
                    NodeValue::$variant(status) => (*status).into(),
                    )+
                }
            }
        }

        impl From<&NodeValue<receptor::ReadWriteStatusFilter>> for FilterU8 {
            fn from(value: &NodeValue<receptor::ReadWriteStatusFilter>) -> Self {
                match value {
                    $(
                    NodeValue::$variant(filter_u8) => *filter_u8,
                    )+
                }
            }
        }

        impl From<(&NodeKey, FilterU8)> for NodeValue<receptor::ReadWriteStatusFilter> {
            fn from(value: (&NodeKey, FilterU8)) -> Self {
                match value.0 {
                    $(
                    NodeKey::$variant(_) => NodeValue::$variant(value.1),
                    )+
                }
            }
        }

        impl Add for NodeValue<changeset::Write> {
            type Output = Result<Self, (Self, Self)>;

            fn add(self, rhs: Self) -> Self::Output {
                match (self, rhs) {
                    $(
                    (Self::$variant(l), Self::$variant(r)) => match l + r {
                        Ok(add) => Ok(Self::$variant(add)),
                        Err((l, r)) => Err((Self::$variant(l), Self::$variant(r))),
                    },
                    )+
                    // SATO return errors
                    _ => unreachable!(),
                }
            }
        }

        impl BitOr for NodeValue<permission::ReadWriteStatusFilter> {
            type Output = Self;

            fn bitor(self, rhs: Self) -> Self::Output {
                match (self, rhs) {
                    $(
                    (Self::$variant(l), Self::$variant(r)) => Self::$variant(l | r),
                    )+
                    // SATO return errors
                    _ => unreachable!(),
                }
            }
        }
    };
}

impl_for_node_key_values!(
    Authorizer,
    Parameter,
    Peer,
    Domain,
    Account,
    Asset,
    Nft,
    AccountAsset,
    Role,
    Permission,
    AccountRole,
    AccountPermission,
    RolePermission,
    Trigger,
    Condition,
    Executable,
    TriggerCondition,
    TriggerExecutable,
    DomainMetadata,
    AccountMetadata,
    AssetMetadata,
    NftData,
    TriggerMetadata,
    DomainAdmin,
    AssetAdmin,
    NftAdmin,
    NftOwner,
    TriggerAdmin,
);

macro_rules! impl_for_tree {
    ($(($tree:ident, $key:ty),)+) => {
        $(
        impl<M: Mode> Default for $tree<M> {
            fn default() -> Self {
                Self(BTreeMap::default())
            }
        }

        impl<M: Mode> FromIterator<($key, NodeValue<M>)> for $tree<M> {
            fn from_iter<I: IntoIterator<Item = ($key, NodeValue<M>)>>(iter: I) -> Self {
                $tree(
                    iter.into_iter()
                        .inspect(|(k, v)| assert!(consistent_key_value(k, v)))
                        .collect::<BTreeMap<_, _>>(),
                )
            }
        }

        impl<M: Mode> IntoIterator for $tree<M> {
            type Item = ($key, NodeValue<M>);
            type IntoIter = btree_map::IntoIter<$key, NodeValue<M>>;

            fn into_iter(self) -> Self::IntoIter {
                self.0.into_iter()
            }
        }

        impl<M: Mode> $tree<M> {
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }

            pub fn get(&self, key: &$key) -> Option<&NodeValue<M>> {
                self.0.get(key)
            }

            pub fn insert(&mut self, key: $key, value: NodeValue<M>) -> Option<NodeValue<M>> {
                assert!(consistent_key_value(&key, &value));
                self.0.insert(key, value)
            }

            pub fn remove(&mut self, key: &$key) -> Option<NodeValue<M>> {
                self.0.remove(key)
            }

            pub fn iter(&self) -> impl Iterator<Item = (&$key, &NodeValue<M>)> {
                self.0.iter()
            }

            pub fn keys(&self) -> impl Iterator<Item = &$key> {
                self.0.keys()
            }
        }
        )+
    };
}

impl_for_tree!((Tree, NodeKey), (FuzzyTree, FuzzyNodeKey),);

#[macro_export]
macro_rules! node {
    (_ $node_type:ident, $key:expr, $value:expr) => {
        ($crate::NodeKey::$node_type($key), $crate::NodeValue::$node_type($value.into()))
    };
    ($node_type:ident, $value:expr) => {
        $crate::node!(_ $node_type, (), $value)
    };
    ($node_type:ident, $k0:expr, $value:expr) => {
        $crate::node!(_ $node_type, Rc::new($k0), $value)
    };
    ($node_type:ident, $k0:expr, $k1:expr, $value:expr) => {
        $crate::node!(_ $node_type, (Rc::new($k0), Rc::new($k1)), $value)
    };
    ($node_type:ident, $k0:expr, $k1:expr, $k2:expr, $value:expr) => {
        $crate::node!(_ $node_type, (Rc::new($k0), Rc::new($k1), Rc::new($k2)), $value)
    };
    ($node_type:ident, $k0:expr, $k1:expr, $k2:expr, $k3:expr, $value:expr) => {
        $crate::node!(_ $node_type, (Rc::new($k0), Rc::new($k1), Rc::new($k2), Rc::new($k3)), $value)
    };
}

#[macro_export]
macro_rules! fuzzy_node {
    (_ $node_type:ident, $key:expr, $value:expr) => {
        ($crate::FuzzyNodeKey::$node_type($key), $crate::NodeValue::$node_type($value.into()))
    };
    ($node_type:ident, $value:expr) => {
        $crate::fuzzy_node!(_ $node_type, (), $value)
    };
    ($node_type:ident, $k0:expr, $value:expr) => {
        $crate::fuzzy_node!(_ $node_type, $k0, $value)
    };
    ($node_type:ident, $k0:expr, $k1:expr, $value:expr) => {
        $crate::fuzzy_node!(_ $node_type, ($k0, $k1), $value)
    };
    ($node_type:ident, $k0:expr, $k1:expr, $k2:expr, $value:expr) => {
        $crate::fuzzy_node!(_ $node_type, ($k0, $k1, $k2), $value)
    };
    ($node_type:ident, $k0:expr, $k1:expr, $k2:expr, $k3:expr, $value:expr) => {
        $crate::fuzzy_node!(_ $node_type, ($k0, $k1, $k2, $k3), $value)
    };
}

pub mod changeset;
pub mod event;
pub mod permission;
pub mod readset;
pub mod receptor;
pub mod state;

pub mod transitional {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Decode, Encode)]
    pub struct ParameterId;

    macro_rules! declare_ids_from_values {
        ($(($id:ident, $value:path),)+) => {
            $(
            #[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, From, Decode, Encode)]
            pub struct $id(dm::HashOf<$value>);

            impl From<&$value> for $id {
                fn from(value: &$value) -> Self {
                    dm::HashOf::new(value).into()
                }
            }
            )+
        };
    }

    declare_ids_from_values!(
        (PermissionId, state::tr::PermissionV),
        (ConditionId, state::tr::ConditionV),
        (ExecutableId, state::tr::ExecutableV),
    );
}

use transitional as tr;

pub mod dm {
    pub use iroha_data_model::{ipfs::IpfsPath, parameter::CustomParameterId, prelude::*, Level};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_filter_u8() {
        use serde_json::{from_str as de, to_string as ser};
        // Be conservative in what we do.
        assert_eq!(ser(&FilterU8::DENY).unwrap(), r#""--------""#);
        assert_eq!(ser(&FilterU8::ANY).unwrap(), r#""dcbmuoir""#);
        assert_eq!(ser(&FilterU8::from(0b1100_1001)).unwrap(), r#""dc--u--r""#);
        // Be liberal in what we accept from others.
        assert_eq!(de::<FilterU8>(r#""""#).unwrap(), FilterU8::DENY);
        assert_eq!(de::<FilterU8>(r#""--------""#).unwrap(), FilterU8::DENY);
        assert_eq!(de::<FilterU8>(r#""--------ext""#).unwrap(), FilterU8::DENY);
        assert_eq!(de::<FilterU8>(r#""dcbmuoir""#).unwrap(), FilterU8::ANY);
        assert_eq!(de::<FilterU8>(r#""rioumbcd""#).unwrap(), FilterU8::ANY);
        assert_eq!(de::<FilterU8>(r#""d-------""#).unwrap(), 0b1000_0000.into());
        assert_eq!(de::<FilterU8>(r#""-------r""#).unwrap(), 0b0000_0001.into());
        assert_eq!(de::<FilterU8>(r#""dc--u--r""#).unwrap(), 0b1100_1001.into());
        assert_eq!(de::<FilterU8>(r#""rdrdr""#).unwrap(), 0b1000_0001.into());
    }
}
