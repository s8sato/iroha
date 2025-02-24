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
    ops::{Add, Deref},
};

use derive_more::From;

mod changeset;
mod event;
mod permission;
mod receptor;
mod state;

/// A flattened node map with a fixed skeleton equivalent to the world state.
/// Node values may vary by mode.
#[derive(Debug, PartialEq, Eq, From)]
struct Tree<M: Mode>(HashMap<NodeKey, NodeValue<M>>);

#[derive(Debug, PartialEq, Eq, From)]
struct TreeRef<'a, M: Mode>(HashMap<&'a NodeKey, &'a NodeValue<M>>);

/// Full path to nodes.
/// A `None` key represents __any__ node.
/// For example, `(None, domain): AccountKey` represents any account within the specified `domain`.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
enum NodeKey {
    Authorizer,
    Parameter(ParameterKey),
    Peer(PeerKey),
    Domain(DomainKey),
    Account(AccountKey),
    Asset(AssetKey),
    Nft(NftKey),
    AccountAsset(AccountAssetKey),
    Role(RoleKey),
    Permission(PermissionKey),
    AccountRole(AccountRoleKey),
    AccountPermission(AccountPermissionKey),
    RolePermission(RolePermissionKey),
    Command(CommandKey),
    Trigger(TriggerKey),
    Executable(ExecutableKey),
    DomainMetadata(DomainMetadataKey),
    AccountMetadata(AccountMetadataKey),
    AssetMetadata(AssetMetadataKey),
    NftData(NftDataKey),
    TriggerMetadata(TriggerMetadataKey),
}

type ParameterKey = Option<tr::ParameterId>;
type PeerKey = Option<dm::PeerId>;
type DomainKey = Option<dm::DomainId>;
type AccountKey = (Option<dm::PublicKey>, DomainKey);
type AssetKey = (Option<dm::Name>, DomainKey);
type NftKey = (Option<dm::Name>, DomainKey);
type AccountAssetKey = (AccountKey, AssetKey);
type RoleKey = Option<dm::RoleId>;
type PermissionKey = Option<tr::PermissionId>;
type AccountRoleKey = (AccountKey, RoleKey);
type AccountPermissionKey = (AccountKey, PermissionKey);
type RolePermissionKey = (RoleKey, PermissionKey);
type CommandKey = Option<tr::CommandId>;
type TriggerKey = Option<dm::TriggerId>;
type ExecutableKey = Option<tr::ExecutableId>;
type DomainMetadataKey = (DomainKey, Option<dm::Name>);
type AccountMetadataKey = (AccountKey, Option<dm::Name>);
type AssetMetadataKey = (AssetKey, Option<dm::Name>);
type NftDataKey = (NftKey, Option<dm::Name>);
type TriggerMetadataKey = (TriggerKey, Option<dm::Name>);

/// Represents various states such as the current state, intention, result, or readiness at a given point in the world.
#[derive(Debug, PartialEq, Eq)]
enum NodeValue<M: Mode> {
    Authorizer(M::Authorizer),
    Parameter(M::Parameter),
    Peer(M::Peer),
    Domain(M::Domain),
    Account(M::Account),
    Asset(M::Asset),
    Nft(M::Nft),
    AccountAsset(M::AccountAsset),
    Role(M::Role),
    Permission(M::Permission),
    AccountRole(M::AccountRole),
    AccountPermission(M::AccountPermission),
    RolePermission(M::RolePermission),
    Command(M::Command),
    Trigger(M::Trigger),
    Executable(M::Executable),
    DomainMetadata(M::Metadata),
    AccountMetadata(M::Metadata),
    AssetMetadata(M::Metadata),
    NftData(M::Metadata),
    TriggerMetadata(M::Metadata),
}

/// This trait implementation serves as a declaration of node values.
trait Mode {
    type Authorizer: Debug + PartialEq + Eq;
    type Parameter: Debug + PartialEq + Eq;
    type Peer: Debug + PartialEq + Eq;
    type Domain: Debug + PartialEq + Eq;
    type Account: Debug + PartialEq + Eq;
    type Asset: Debug + PartialEq + Eq;
    type Nft: Debug + PartialEq + Eq;
    type AccountAsset: Debug + PartialEq + Eq;
    type Role: Debug + PartialEq + Eq;
    type Permission: Debug + PartialEq + Eq;
    type AccountRole: Debug + PartialEq + Eq;
    type AccountPermission: Debug + PartialEq + Eq;
    type RolePermission: Debug + PartialEq + Eq;
    type Command: Debug + PartialEq + Eq;
    type Trigger: Debug + PartialEq + Eq;
    type Executable: Debug + PartialEq + Eq;
    type Metadata: Debug + PartialEq + Eq;
}

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

#[derive(Debug, PartialEq, Eq, From, Default)]
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

impl Add for FilterU8 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        #[expect(clippy::suspicious_arithmetic_impl)]
        Self(self.0 | rhs.0)
    }
}

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
        debug_assert!(consistent_key_value(&key, &value));
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

fn consistent_key_value<M: Mode>(key: &NodeKey, value: &NodeValue<M>) -> bool {
    match (key, value) {
        (NodeKey::Authorizer, NodeValue::<M>::Authorizer(_))
        | (NodeKey::Parameter(_), NodeValue::<M>::Parameter(_))
        | (NodeKey::Peer(_), NodeValue::<M>::Peer(_))
        | (NodeKey::Domain(_), NodeValue::<M>::Domain(_))
        | (NodeKey::Account(_), NodeValue::<M>::Account(_))
        | (NodeKey::Asset(_), NodeValue::<M>::Asset(_))
        | (NodeKey::Nft(_), NodeValue::<M>::Nft(_))
        | (NodeKey::AccountAsset(_), NodeValue::<M>::AccountAsset(_))
        | (NodeKey::Role(_), NodeValue::<M>::Role(_))
        | (NodeKey::Permission(_), NodeValue::<M>::Permission(_))
        | (NodeKey::AccountRole(_), NodeValue::<M>::AccountRole(_))
        | (NodeKey::AccountPermission(_), NodeValue::<M>::AccountPermission(_))
        | (NodeKey::RolePermission(_), NodeValue::<M>::RolePermission(_))
        | (NodeKey::Command(_), NodeValue::<M>::Command(_))
        | (NodeKey::Trigger(_), NodeValue::<M>::Trigger(_))
        | (NodeKey::Executable(_), NodeValue::<M>::Executable(_))
        | (NodeKey::DomainMetadata(_), NodeValue::<M>::DomainMetadata(_))
        | (NodeKey::AccountMetadata(_), NodeValue::<M>::AccountMetadata(_))
        | (NodeKey::AssetMetadata(_), NodeValue::<M>::AssetMetadata(_))
        | (NodeKey::NftData(_), NodeValue::<M>::NftData(_))
        | (NodeKey::TriggerMetadata(_), NodeValue::<M>::TriggerMetadata(_)) => true,
        (_, _) => false,
    }
}

mod transitional {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub enum ParameterId {
        Preset(PresetParameterId),
        Custom(dm::CustomParameterId),
    }

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub struct PresetParameterId;

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub struct PermissionId;

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub struct CommandId;

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub struct ExecutableId;
}

use transitional as tr;

mod dm {
    pub use iroha_data_model::{ipfs::IpfsPath, parameter::CustomParameterId, prelude::*};
}
