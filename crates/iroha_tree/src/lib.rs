//! A transitional crate that can be merged into other crates.
//!
//! It aims to integrate executables, events, and event filters while enabling recursive trigger prediction in a static manner.
//! The prediction is based on the union of possible execution paths, enabling pessimistic event loop detection.
//!
//! Additionally, to improve performance, it consolidates:
//!
//! - Instructions into a single [`ChangeSet`] per transaction (or per block/epoch, depending on feature requests such as chain compression).
//! - (Data) events into a single [`Event`] per transaction.
//! - (Data) event filters into a single [`Receptor`] per trigger.
//! - Permissions, roles, and ownerships into a single [`Permission`] per validation.

#![allow(missing_docs)] // SATO disallow
#![allow(dead_code)] // SATO disallow

use std::{cmp::Ordering, collections::HashMap, fmt::Debug, hash::Hash};

use derive_more::From;

mod changeset;
mod event;
mod permission;
mod receptor;
mod state;

#[derive(Debug, PartialEq, Eq)]
struct Tree<M: Mode>(HashMap<NodeKey, NodeValue<M>>);

#[derive(Debug, PartialEq, Eq, Hash)]
enum NodeKey {
    // Rank 1
    Authorizer,
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
    // Rank 2
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
    // Rank 3
    DomainMetadata(DomainMetadataKey),
    AccountMetadata(AccountMetadataKey),
    AssetMetadata(AssetMetadataKey),
    NftData(NftDataKey),
    TriggerMetadata(TriggerMetadataKey),
}

// Rank 2
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
// Rank 3
type DomainMetadataKey = (DomainKey, dm::Name);
type AccountMetadataKey = (AccountKey, dm::Name);
type AssetMetadataKey = (AssetKey, dm::Name);
type NftDataKey = (NftKey, dm::Name);
type TriggerMetadataKey = (TriggerKey, dm::Name);

#[derive(Debug, PartialEq, Eq)]
enum NodeValue<M: Mode> {
    // Rank 1
    Authorizer(M::Authorizer),
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
    // Rank 2
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
    // Rank 3
    DomainMetadata(M::Metadata),
    AccountMetadata(M::Metadata),
    AssetMetadata(M::Metadata),
    NftData(M::Metadata),
    TriggerMetadata(M::Metadata),
}

trait Mode {
    // Rank 1
    type Authorizer: Debug + PartialEq + Eq;
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
    // Rank 2
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
    // Rank 3
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

#[derive(Debug, PartialEq, Eq, From)]
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

mod transitional {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Hash)]
    pub struct ParameterId;

    pub type AssetId = dm::AssetDefinitionId;

    #[derive(Debug, PartialEq, Eq, Hash)]
    pub struct NftId;

    #[derive(Debug, PartialEq, Eq, Hash)]
    pub struct PermissionId;

    #[derive(Debug, PartialEq, Eq, Hash)]
    pub struct CommandId;

    #[derive(Debug, PartialEq, Eq, Hash)]
    pub struct ExecutableId;
}

use transitional as tr;

mod dm {
    pub use iroha_data_model::{ipfs::IpfsPath, parameter::CustomParameterId, prelude::*};
}
