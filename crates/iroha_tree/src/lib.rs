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
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    ops::{Add, BitOr},
    rc::Rc,
};

use derive_more::{BitOr, Constructor, From};

/// A flattened node map with a fixed skeleton equivalent to the world state.
/// Node values may vary by mode.
#[derive(Debug, PartialEq, Eq)]
struct Tree<M: Mode>(HashMap<NodeKey, NodeValue<M>>);

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
    (AccountTrigger, AccountTriggerKey: dm::PublicKey, dm::DomainId, dm::TriggerId),
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
    type Filter;

    /// # Errors
    ///
    /// Returns the difference from the expected filter required for `self` to pass.
    fn passes(&self, filter: &Self::Filter) -> Result<(), Self::Filter>;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, From, BitOr)]
struct FilterU8(u8);

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

impl FilterU8 {
    const ANY: Self = Self(u8::MAX);
    const DENY: Self = Self(u8::MIN);
}

macro_rules! impl_for_node_values {
    ($($variant:ident,)+) => {
        impl From<&NodeValue<changeset::Write>> for NodeValue<event::WriteStatus> {
            fn from(value: &NodeValue<changeset::Write>) -> Self {
                match value {
                    $(
                    NodeValue::$variant(write) => Self::$variant(write.as_status()),
                    )+
                }
            }
        }

        impl From<&NodeValue<event::WriteStatus>> for FilterU8 {
            fn from(value: &NodeValue<event::WriteStatus>) -> Self {
                match value {
                    $(
                    NodeValue::$variant(status) => status.into(),
                    )+
                }
            }
        }

        impl From<&NodeValue<receptor::WriteStatusFilter>> for FilterU8 {
            fn from(value: &NodeValue<receptor::WriteStatusFilter>) -> Self {
                match value {
                    $(
                    NodeValue::$variant(filter_u8) => *filter_u8,
                    )+
                }
            }
        }

        impl From<(&NodeKey, FilterU8)> for NodeValue<receptor::WriteStatusFilter> {
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
    AccountTrigger,
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
        Tree(
            iter.into_iter()
                .inspect(|(k, v)| assert!(consistent_key_value(k, v)))
                .collect::<HashMap<_, _>>(),
        )
    }
}

impl<M: Mode> Tree<M> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn get(&self, key: &NodeKey) -> Option<&NodeValue<M>> {
        self.0.get(key)
    }

    fn insert(&mut self, key: NodeKey, value: NodeValue<M>) -> Option<NodeValue<M>> {
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
        TriggerAdmin(dm::TriggerId),
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
