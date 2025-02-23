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

#[derive(Debug, PartialEq, Eq, From)]
struct Tree<M: NodeMode>(HashMap<NodeKey, NodeValue<M>>);

#[derive(Debug, PartialEq, Eq, From)]
struct Leaves<M: LeafMode>(HashMap<LeafKey, LeafValue<M>>);

#[derive(Debug, PartialEq, Eq, From)]
struct TreeRef<'a, M: NodeMode>(HashMap<&'a NodeKey, &'a NodeValue<M>>);

#[derive(Debug, PartialEq, Eq, From)]
struct LeavesRef<'a, M: LeafMode>(HashMap<&'a LeafKey, &'a LeafValue<M>>);

#[derive(Debug, PartialEq, Eq, Hash, Clone, From)]
enum NodeKey {
    Branch(BranchKey),
    Leaf(LeafKey),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
enum BranchKey {
    Parameters,
    Peers,
    Domains,
    Accounts,
    Assets,
    Nfts,
    AccountAssets,
    Roles,
    Permissions,
    AccountRoles,
    AccountPermissions,
    RolePermissions,
    Commands,
    Triggers,
    Executables,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
enum LeafKey {
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

type ParameterKey = tr::ParameterId;
type PeerKey = dm::PeerId;
type DomainKey = dm::DomainId;
type AccountKey = dm::AccountId;
type AssetKey = tr::AssetId;
type NftKey = tr::NftId;
type AccountAssetKey = (dm::AccountId, tr::AssetId);
type RoleKey = dm::RoleId;
type PermissionKey = tr::PermissionId;
type AccountRoleKey = (dm::AccountId, dm::RoleId);
type AccountPermissionKey = (dm::AccountId, tr::PermissionId);
type RolePermissionKey = (dm::RoleId, tr::PermissionId);
type CommandKey = tr::CommandId;
type TriggerKey = dm::TriggerId;
type ExecutableKey = tr::ExecutableId;
type DomainMetadataKey = (DomainKey, dm::Name);
type AccountMetadataKey = (AccountKey, dm::Name);
type AssetMetadataKey = (AssetKey, dm::Name);
type NftDataKey = (NftKey, dm::Name);
type TriggerMetadataKey = (TriggerKey, dm::Name);

#[derive(Debug, PartialEq, Eq, From)]
enum NodeValue<M: NodeMode> {
    Branch(BranchValue<M>),
    Leaf(LeafValue<M>),
}

#[derive(Debug, PartialEq, Eq)]
enum BranchValue<M: BranchMode> {
    Parameters(M::Parameters),
    Peers(M::Peers),
    Domains(M::Domains),
    Accounts(M::Accounts),
    Assets(M::Assets),
    Nfts(M::Nfts),
    AccountAssets(M::AccountAssets),
    Roles(M::Roles),
    Permissions(M::Permissions),
    AccountRoles(M::AccountRoles),
    AccountPermissions(M::AccountPermissions),
    RolePermissions(M::RolePermissions),
    Commands(M::Commands),
    Triggers(M::Triggers),
    Executables(M::Executables),
}

#[derive(Debug, PartialEq, Eq)]
enum LeafValue<M: LeafMode> {
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

trait NodeMode: LeafMode + BranchMode {}

trait BranchMode {
    type Parameters: Debug + PartialEq + Eq;
    type Peers: Debug + PartialEq + Eq;
    type Domains: Debug + PartialEq + Eq;
    type Accounts: Debug + PartialEq + Eq;
    type Assets: Debug + PartialEq + Eq;
    type Nfts: Debug + PartialEq + Eq;
    type AccountAssets: Debug + PartialEq + Eq;
    type Roles: Debug + PartialEq + Eq;
    type Permissions: Debug + PartialEq + Eq;
    type AccountRoles: Debug + PartialEq + Eq;
    type AccountPermissions: Debug + PartialEq + Eq;
    type RolePermissions: Debug + PartialEq + Eq;
    type Commands: Debug + PartialEq + Eq;
    type Triggers: Debug + PartialEq + Eq;
    type Executables: Debug + PartialEq + Eq;
}

trait LeafMode {
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

macro_rules! impl_tree_leaves {
    ($(($ty:ident, $ref:ident, $mode:ident, $key:ty, $value:ident),)+) => {
        $(
        impl<M: $mode> Default for $ty<M> {
            fn default() -> Self {
                Self(HashMap::default())
            }
        }

        impl<M: $mode> FromIterator<($key, $value<M>)> for $ty<M> {
            fn from_iter<I: IntoIterator<Item = ($key, $value<M>)>>(iter: I) -> Self {
                $ty::from(iter.into_iter().collect::<HashMap<_, _>>())
            }
        }

        impl<'a, M: $mode> FromIterator<(&'a $key, &'a $value<M>)> for $ref<'a, M> {
            fn from_iter<I: IntoIterator<Item = (&'a $key, &'a $value<M>)>>(iter: I) -> Self {
                $ref::from(iter.into_iter().collect::<HashMap<_, _>>())
            }
        }

        impl<M: $mode> $ty<M> {
            fn get(&self, key: &$key) -> Option<&$value<M>> {
                self.0.get(key)
            }

            fn remove(&mut self, key: &$key) -> Option<$value<M>> {
                self.0.remove(key)
            }

            fn iter(&self) -> impl Iterator<Item = (&$key, &$value<M>)> {
                self.0.iter()
            }

            fn into_iter(self) -> impl Iterator<Item = ($key, $value<M>)> {
                self.0.into_iter()
            }

            fn map<N, F>(self, f: F) -> $ty<N>
            where
                N: $mode,
                F: Fn($value<M>) -> $value<N>,
            {
                self.into_iter().map(|(k, v)| (k, f(v))).collect()
            }

            fn as_ref(&self) -> $ref<M> {
                self.iter().collect()
            }
        }

        impl<'a, M: $mode> $ref<'a, M> {
            fn get(&self, key: &$key) -> Option<&$value<M>> {
                self.0.get(key).map(Deref::deref)
            }

            fn into_iter(self) -> impl Iterator<Item = (&'a $key, &'a $value<M>)> {
                self.0.into_iter()
            }

            fn map<N, F>(self, f: F) -> $ref<'a, N>
            where
                N: $mode,
                F: Fn(&$value<M>) -> &$value<N>,
            {
                self.into_iter().map(|(k, v)| (k, f(v))).collect()
            }
        }
        )+
    };
}

impl_tree_leaves!(
    (Tree, TreeRef, NodeMode, NodeKey, NodeValue),
    (Leaves, LeavesRef, LeafMode, LeafKey, LeafValue),
);

impl<M: NodeMode> Tree<M> {
    fn insert(&mut self, key: NodeKey, value: NodeValue<M>) -> Option<NodeValue<M>> {
        debug_assert!(consistent_node(&key, &value));
        self.0.insert(key, value)
    }
}

impl<M: LeafMode> Leaves<M> {
    fn insert(&mut self, key: LeafKey, value: LeafValue<M>) -> Option<LeafValue<M>> {
        debug_assert!(consistent_leaf(&key, &value));
        self.0.insert(key, value)
    }
}

fn consistent_node<M: NodeMode>(key: &NodeKey, value: &NodeValue<M>) -> bool {
    match (key, value) {
        (NodeKey::Branch(key), NodeValue::Branch(value)) => consistent_branch(key, value),
        (NodeKey::Leaf(key), NodeValue::Leaf(value)) => consistent_leaf(key, value),
        _ => false,
    }
}

fn consistent_branch<M: BranchMode>(key: &BranchKey, value: &BranchValue<M>) -> bool {
    matches!(
        (key, value),
        (BranchKey::Parameters, BranchValue::Parameters(_))
            | (BranchKey::Peers, BranchValue::Peers(_))
            | (BranchKey::Domains, BranchValue::Domains(_))
            | (BranchKey::Accounts, BranchValue::Accounts(_))
            | (BranchKey::Assets, BranchValue::Assets(_))
            | (BranchKey::Nfts, BranchValue::Nfts(_))
            | (BranchKey::AccountAssets, BranchValue::AccountAssets(_))
            | (BranchKey::Roles, BranchValue::Roles(_))
            | (BranchKey::Permissions, BranchValue::Permissions(_))
            | (BranchKey::AccountRoles, BranchValue::AccountRoles(_))
            | (
                BranchKey::AccountPermissions,
                BranchValue::AccountPermissions(_)
            )
            | (BranchKey::RolePermissions, BranchValue::RolePermissions(_))
            | (BranchKey::Commands, BranchValue::Commands(_))
            | (BranchKey::Triggers, BranchValue::Triggers(_))
            | (BranchKey::Executables, BranchValue::Executables(_))
    )
}

fn consistent_leaf<M: LeafMode>(key: &LeafKey, value: &LeafValue<M>) -> bool {
    matches!(
        (key, value),
        (LeafKey::Authorizer, LeafValue::Authorizer(_))
            | (LeafKey::Parameter(_), LeafValue::Parameter(_))
            | (LeafKey::Peer(_), LeafValue::Peer(_))
            | (LeafKey::Domain(_), LeafValue::Domain(_))
            | (LeafKey::Account(_), LeafValue::Account(_))
            | (LeafKey::Asset(_), LeafValue::Asset(_))
            | (LeafKey::Nft(_), LeafValue::Nft(_))
            | (LeafKey::AccountAsset(_), LeafValue::AccountAsset(_))
            | (LeafKey::Role(_), LeafValue::Role(_))
            | (LeafKey::Permission(_), LeafValue::Permission(_))
            | (LeafKey::AccountRole(_), LeafValue::AccountRole(_))
            | (
                LeafKey::AccountPermission(_),
                LeafValue::AccountPermission(_)
            )
            | (LeafKey::RolePermission(_), LeafValue::RolePermission(_))
            | (LeafKey::Command(_), LeafValue::Command(_))
            | (LeafKey::Trigger(_), LeafValue::Trigger(_))
            | (LeafKey::Executable(_), LeafValue::Executable(_))
            | (LeafKey::DomainMetadata(_), LeafValue::DomainMetadata(_))
            | (LeafKey::AccountMetadata(_), LeafValue::AccountMetadata(_))
            | (LeafKey::AssetMetadata(_), LeafValue::AssetMetadata(_))
            | (LeafKey::NftData(_), LeafValue::NftData(_))
            | (LeafKey::TriggerMetadata(_), LeafValue::TriggerMetadata(_))
    )
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

    pub type AssetId = dm::AssetDefinitionId;

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub struct NftId;

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
