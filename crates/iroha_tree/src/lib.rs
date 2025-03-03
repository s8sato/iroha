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

use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    ops::{Add, BitOr, Deref},
    rc::Rc,
};

use derive_more::{BitOr, Constructor, From};

/// A flattened node map with a fixed skeleton equivalent to the world state.
/// Node values may vary by mode.
#[derive(Debug, PartialEq, Eq, From)]
struct Tree<M: Mode>(HashMap<NodeKey, NodeValue<M>>);

#[derive(Debug, PartialEq, Eq, From)]
struct TreeRef<'a, M: Mode>(HashMap<&'a NodeKey, &'a NodeValue<M>>);

macro_rules! declare_nodes {
    ($(($variant:ident, $key:ident: $($key_element:ty),*),)+) => {
        /// Full path to nodes.
        /// A `None` key element represents __any__ node.
        /// For example, `(None, domain): AccountKey` represents any account within the specified `domain`.
        #[derive(Debug, PartialEq, Eq, Hash, Clone)]
        enum NodeKey {
            $(
            $variant($key),
            )+
        }

        $(
        declare_nodes!(_key_alias $key: $($key_element),*);
        )+

        /// Represents various states such as the current state, intention, result, or readiness at a given point in the world.
        #[derive(Debug, PartialEq, Eq)]
        enum NodeValue<M: Mode> {
            $(
            $variant(M::$variant),
            )+
        }

        /// This trait implementation serves as a declaration of node values.
        trait Mode {
            $(
            type $variant: Debug + PartialEq + Eq;
            )+
        }

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
    (Executable, ExecutableKey: tr::WasmExecutableId),
    (DomainMetadata, DomainMetadataKey: dm::DomainId, dm::Name),
    (AccountMetadata, AccountMetadataKey: dm::PublicKey, dm::DomainId, dm::Name),
    (AssetMetadata, AssetMetadataKey: dm::Name, dm::DomainId, dm::Name),
    (NftData, NftDataKey: dm::Name, dm::DomainId, dm::Name),
    (TriggerMetadata, TriggerMetadataKey: dm::TriggerId, dm::Name),
);

trait NodeWrite: Filtered {
    type Status: Filtered;

    fn as_status(&self) -> Self::Status;
}

trait Filtered {
    type Filter: PartialOrd;

    fn as_filter(&self) -> Self::Filter;

    fn passes(&self, filter: &Self::Filter) -> bool {
        self.as_filter() <= *filter
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default, From, BitOr)]
struct FilterU8(u8);

impl PartialOrd for FilterU8 {
    /// Attempts to summarize bitwise comparisons.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let l = self.0;
        let r = other.0;
        let xor = l ^ r;
        if xor == 0 {
            Some(Ordering::Equal)
        } else if l & xor == 0 {
            Some(Ordering::Less)
        } else if r & xor == 0 {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}

macro_rules! impl_for_node_values {
    ($($ident:ident,)+) => {
        impl From<&NodeValue<changeset::Write>> for NodeValue<event::WriteStatus> {
            fn from(value: &NodeValue<changeset::Write>) -> Self {
                match value {
                    $(
                    NodeValue::$ident(write) => Self::$ident(write.as_status()),
                    )+
                }
            }
        }

        impl From<&NodeValue<event::WriteStatus>> for NodeValue<receptor::WriteStatusFilter> {
            fn from(value: &NodeValue<event::WriteStatus>) -> Self {
                match value {
                    $(
                    NodeValue::$ident(write_status) => Self::$ident(write_status.as_filter()),
                    )+
                }
            }
        }

        impl From<&NodeValue<changeset::Write>> for NodeValue<permission::ReadWriteStatusFilter> {
            fn from(value: &NodeValue<changeset::Write>) -> Self {
                match value {
                    $(
                    NodeValue::$ident(write) => Self::$ident(write.as_status().as_filter()),
                    )+
                }
            }
        }

        impl From<&NodeValue<receptor::WriteStatusFilter>> for FilterU8 {
            fn from(value: &NodeValue<receptor::WriteStatusFilter>) -> Self {
                match value {
                    $(
                    NodeValue::$ident(filter_u8) => *filter_u8,
                    )+
                }
            }
        }

        impl Add for NodeValue<changeset::Write> {
            type Output = Result<Self, (Self, Self)>;

            fn add(self, rhs: Self) -> Self::Output {
                match (self, rhs) {
                    $(
                    (Self::$ident(l), Self::$ident(r)) => match l + r {
                        Ok(add) => Ok(Self::$ident(add)),
                        Err((l, r)) => Err((Self::$ident(l), Self::$ident(r))),
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
                    (Self::$ident(l), Self::$ident(r)) => Self::$ident(l | r),
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
    Executable,
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
        Tree::from(iter.into_iter().collect::<HashMap<_, _>>())
    }
}

impl<'a, M: Mode> FromIterator<(&'a NodeKey, &'a NodeValue<M>)> for TreeRef<'a, M> {
    fn from_iter<I: IntoIterator<Item = (&'a NodeKey, &'a NodeValue<M>)>>(iter: I) -> Self {
        TreeRef::from(iter.into_iter().collect::<HashMap<_, _>>())
    }
}

impl<M: Mode> Tree<M> {
    fn get(&self, key: &NodeKey) -> Option<&NodeValue<M>> {
        self.0.get(key)
    }

    fn insert(&mut self, key: NodeKey, value: NodeValue<M>) -> Option<NodeValue<M>> {
        // SATO Type safety was lost while reducing tree size.
        assert!(consistent_key_value(&key, &value));
        self.0.insert(key, value)
    }

    fn remove(&mut self, key: &NodeKey) -> Option<NodeValue<M>> {
        self.0.remove(key)
    }

    fn iter(&self) -> impl Iterator<Item = (&NodeKey, &NodeValue<M>)> {
        self.0.iter()
    }

    fn into_iter(self) -> impl Iterator<Item = (NodeKey, NodeValue<M>)> {
        self.0.into_iter()
    }

    fn map<N, F>(self, f: F) -> Tree<N>
    where
        N: Mode,
        F: Fn(NodeValue<M>) -> NodeValue<N>,
    {
        self.into_iter().map(|(k, v)| (k, f(v))).collect()
    }

    fn as_ref(&self) -> TreeRef<M> {
        self.iter().collect()
    }
}

impl<'a, M: Mode> TreeRef<'a, M> {
    fn get(&self, key: &NodeKey) -> Option<&NodeValue<M>> {
        self.0.get(key).map(Deref::deref)
    }

    fn into_iter(self) -> impl Iterator<Item = (&'a NodeKey, &'a NodeValue<M>)> {
        self.0.into_iter()
    }

    fn map<N, F>(self, f: F) -> TreeRef<'a, N>
    where
        N: Mode,
        F: Fn(&NodeValue<M>) -> &NodeValue<N>,
    {
        self.into_iter().map(|(k, v)| (k, f(v))).collect()
    }
}

macro_rules! node_key_value {
    (_ $node:ident, $key:expr, $value:expr) => {
        (NodeKey::$node($key), NodeValue::$node($value))
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

mod changeset;
mod event;
mod permission;
mod receptor;
mod state;

mod transitional {
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
        MultisigSignatory(dm::AccountId),
    }

    #[derive(Debug, PartialEq, Eq, Hash, Clone, From)]
    pub struct PermissionId(String);

    #[derive(Debug, PartialEq, Eq, Hash, Clone, From)]
    pub struct WasmExecutableId(dm::HashOf<state::tr::WasmExecutableValue>);
}

use transitional as tr;

mod dm {
    pub use iroha_data_model::{ipfs::IpfsPath, parameter::CustomParameterId, prelude::*, Level};
}
