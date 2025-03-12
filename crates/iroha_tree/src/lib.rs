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

use std::{
    collections::HashMap,
    convert::Infallible,
    fmt::{Debug, Display},
    hash::Hash,
    ops::{Add, BitOr},
    rc::Rc,
    str::FromStr,
};

use derive_more::{BitOr, Constructor, From};
use serde_with::{DeserializeFromStr, SerializeDisplay};

/// A flattened node map with a fixed skeleton equivalent to the world state.
/// Node values may vary by [`Mode`].
#[derive(Debug, PartialEq, Eq)]
pub struct Tree<M: Mode>(HashMap<NodeKey, NodeValue<M>>);

macro_rules! declare_nodes {
    ($(($variant:ident, $key:ident: $($key_element:ty),*),)+) => {
        /// Full path to nodes.
        /// A `None` key element represents __any__ node.
        /// For example, `(None, domain): AccountKey` represents any account within the specified `domain`.
        #[derive(Debug, PartialEq, Eq, Hash, Clone)]
        pub enum NodeKey {
            $(
            $variant($key),
            )+
        }

        $(
        declare_nodes!(_key_alias $key: $($key_element),*);
        )+

        /// Represents various states such as the current state, intention, result, or readiness at the node.
        #[derive(Debug, PartialEq, Eq)]
        pub enum NodeValue<M: Mode> {
            $(
            $variant(M::$variant),
            )+
        }

        /// This trait implementation serves as a declaration of node values.
        pub trait Mode {
            $(
            type $variant: Debug + PartialEq + Eq;
            )+
        }

        // This should be asserted whenever constructing key-value pairs, as type safety was lost during tree size reduction.
        fn consistent_key_value<M: Mode>(key: &NodeKey, value: &NodeValue<M>) -> bool {
            match (key, value) {
                $(
                (NodeKey::$variant(_), NodeValue::$variant(_))
                )|+ => true,
                (_, _) => false,
            }
        }
    };
    (_key_alias $key:ident:) => {
        type $key = ();
    };
    (_key_alias $key:ident: $key_element:ty) => {
        type $key = Option<Rc<$key_element>>;
    };
    (_key_alias $key:ident: $key_element_head:ty, $($key_element:ty),+) => {
        type $key = (Option<Rc<$key_element_head>>, $(Option<Rc<$key_element>>),+);
    };
}

declare_nodes!(
    (Authorizer, AuthorizerKey:),
    (Parameter, ParameterKey: tr::ParameterId),
    (Peer, PeerKey: dm::PeerId),
    (Domain, DomainKey: dm::DomainId),
    (Account, AccountKey: dm::PublicKey, dm::DomainId),
    (Asset, AssetKey: dm::Name, dm::DomainId),
    (Nft, NftKey: dm::Name, dm::DomainId),
    (AccountAsset, AccountAssetKey: dm::PublicKey, dm::DomainId, dm::Name, dm::DomainId),
    (Role, RoleKey: tr::RoleId),
    (Permission, PermissionKey: tr::PermissionId),
    (AccountRole, AccountRoleKey: dm::PublicKey, dm::DomainId, tr::RoleId),
    (AccountPermission, AccountPermissionKey: dm::PublicKey, dm::DomainId, tr::PermissionId),
    (RolePermission, RolePermissionKey: tr::RoleId, tr::PermissionId),
    (Trigger, TriggerKey: dm::TriggerId),
    (Condition, ConditionKey: tr::ConditionId),
    (Executable, ExecutableKey: tr::ExecutableId),
    (TriggerCondition, TriggerConditionKey: dm::TriggerId, tr::ConditionId),
    (TriggerExecutable, TriggerExecutableKey: dm::TriggerId, tr::ExecutableId),
    (AccountTrigger, AccountTriggerKey: dm::PublicKey, dm::DomainId, dm::TriggerId),
    (DomainMetadata, DomainMetadataKey: dm::DomainId, dm::Name),
    (AccountMetadata, AccountMetadataKey: dm::PublicKey, dm::DomainId, dm::Name),
    (AssetMetadata, AssetMetadataKey: dm::Name, dm::DomainId, dm::Name),
    (NftData, NftDataKey: dm::Name, dm::DomainId, dm::Name),
    (TriggerMetadata, TriggerMetadataKey: dm::TriggerId, dm::Name),
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

#[derive(Debug, PartialEq, Eq, Clone, Copy, From, BitOr, SerializeDisplay, DeserializeFromStr)]
pub struct FilterU8(u8);

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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
/// SATO docs
pub struct NodeConflict<M: Mode> {
    pub key: NodeKey,
    pub lhs: NodeValue<M>,
    pub rhs: NodeValue<M>,
}

macro_rules! impl_for_node_values {
    ($($variant:ident,)+) => {
        impl From<&NodeValue<readset::Read>> for NodeValue<event::ReadWriteStatus> {
            fn from(value: &NodeValue<readset::Read>) -> Self {
                match value {
                    $(
                    NodeValue::$variant(read) => Self::$variant(read.into()),
                    )+
                }
            }
        }

        impl From<&NodeValue<changeset::Write>> for NodeValue<event::ReadWriteStatus> {
            fn from(value: &NodeValue<changeset::Write>) -> Self {
                match value {
                    $(
                    NodeValue::$variant(write) => Self::$variant(write.as_status()),
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
                    _ => unreachable!(),
                }
            }
        }
    };
}

impl_for_node_values!(
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
    AccountTrigger,
    DomainMetadata,
    AccountMetadata,
    AssetMetadata,
    NftData,
    TriggerMetadata,
);

impl<M: Mode> Default for Tree<M> {
    fn default() -> Self {
        Self(HashMap::default())
    }
}

impl<M: Mode> FromIterator<(NodeKey, NodeValue<M>)> for Tree<M> {
    fn from_iter<I: IntoIterator<Item = (NodeKey, NodeValue<M>)>>(iter: I) -> Self {
        Tree(
            iter.into_iter()
                .inspect(|(k, v)| assert!(consistent_key_value(k, v)))
                .collect::<HashMap<_, _>>(),
        )
    }
}

impl<M: Mode> IntoIterator for Tree<M> {
    type Item = (NodeKey, NodeValue<M>);
    type IntoIter = std::collections::hash_map::IntoIter<NodeKey, NodeValue<M>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<M: Mode> Tree<M> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, key: &NodeKey) -> Option<&NodeValue<M>> {
        self.0.get(key)
    }

    pub fn insert(&mut self, key: NodeKey, value: NodeValue<M>) -> Option<NodeValue<M>> {
        assert!(consistent_key_value(&key, &value));
        self.0.insert(key, value)
    }

    pub fn remove(&mut self, key: &NodeKey) -> Option<NodeValue<M>> {
        self.0.remove(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&NodeKey, &NodeValue<M>)> {
        self.0.iter()
    }

    pub fn keys(&self) -> impl Iterator<Item = &NodeKey> {
        self.0.keys()
    }
}

#[macro_export]
macro_rules! node_key_value {
    (_ $node:ident, $key:expr, $value:expr) => {
        ($crate::NodeKey::$node($key), $crate::NodeValue::$node($value))
    };
    ($node:ident, $value:expr) => {
        node_key_value!(_ $node, (), $value)
    };
    ($node:ident, $k0:expr, $value:expr) => {
        node_key_value!(_ $node, Some(Rc::new($k0)), $value)
    };
    ($node:ident, $k0:expr, $k1:expr, $value:expr) => {
        node_key_value!(_ $node, (Some(Rc::new($k0)), Some(Rc::new($k1))), $value)
    };
    ($node:ident, $k0:expr, $k1:expr, $k2:expr, $value:expr) => {
        node_key_value!(_ $node, (Some(Rc::new($k0)), Some(Rc::new($k1)), Some(Rc::new($k2))), $value)
    };
    ($node:ident, $k0:expr, $k1:expr, $k2:expr, $k3:expr, $value:expr) => {
        node_key_value!(_ $node, (Some(Rc::new($k0)), Some(Rc::new($k1)), Some(Rc::new($k2)), Some(Rc::new($k3))), $value)
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

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub enum ParameterId {
        Any, // TODO remove ParameterId::Any
        Preset(PresetParameterId),
        Custom(dm::CustomParameterId),
    }

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub struct PresetParameterId;

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub enum RoleId {
        Named(dm::Name),
        DomainAdmin(dm::DomainId),
        AssetAdmin(dm::AssetDefinitionId),
        NftAdmin(dm::NftId),
        NftOwner(dm::NftId),
        TriggerAdmin(dm::TriggerId),
        MultisigSignatory(dm::AccountId),
    }

    #[derive(Debug, PartialEq, Eq, Hash, Clone, From)]
    pub struct PermissionId(String);

    // SATO HashOf<T: Encode>
    // pub struct ConditionId(dm::HashOf<state::tr::ConditionValue>);
    pub type ConditionId = dm::TriggerId;

    // SATO HashOf<T: Encode>
    // pub struct ExecutableId(dm::HashOf<state::tr::ExecutableValue>);
    pub type ExecutableId = dm::TriggerId;
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
