#![allow(missing_docs)] // SATO disallow
#![allow(dead_code)] // SATO disallow

use std::{cmp::Ordering, hash::Hash};

use derive_more::From;

enum Node<K, V>
where
    K: NodeKey,
    V: NodeValue<K>,
{
    End(V),
    #[expect(clippy::type_complexity)]
    #[expect(clippy::disallowed_types)]
    Ext(std::collections::HashMap<<K::Ext as NodeKey>::Key, Node<K::Ext, V::Ext>>),
}

trait NodeKey {
    type Key: std::hash::Hash;
    type Ext: NodeKey;
}

trait NodeValue<K: NodeKey> {
    type Value;
    type Ext: NodeValue<K::Ext>;
}

struct Tree<M: Mode> {
    parameters: Node<Parameters, M::Parameters>,
    peers: Node<Peers, M::Peers>,
    domains: Node<Domains, M::Domains>,
    accounts: Node<Accounts, M::Accounts>,
    assets: Node<Assets, M::Assets>,
    nfts: Node<Nfts, M::Nfts>,
    account_assets: Node<AccountAssets, M::AccountAssets>,
    roles: Node<Roles, M::Roles>,
    permissions: Node<Permissions, M::Permissions>,
    account_roles: Node<AccountRoles, M::AccountRoles>,
    account_permissions: Node<AccountPermissions, M::AccountPermissions>,
    role_permissions: Node<RolePermissions, M::RolePermissions>,
    commands: Node<Commands, M::Commands>,
    triggers: Node<Triggers, M::Triggers>,
    executables: Node<Executables, M::Executables>,
    authorizers: Node<Authorizers, M::Authorizers>,
}

trait Mode {
    // Rank 1
    type Parameters: NodeValue<Parameters>;
    type Peers: NodeValue<Peers>;
    type Domains: NodeValue<Domains>;
    type Accounts: NodeValue<Accounts>;
    type Assets: NodeValue<Assets>;
    type Nfts: NodeValue<Nfts>;
    type AccountAssets: NodeValue<AccountAssets>;
    type Roles: NodeValue<Roles>;
    type Permissions: NodeValue<Permissions>;
    type AccountRoles: NodeValue<AccountRoles>;
    type AccountPermissions: NodeValue<AccountPermissions>;
    type RolePermissions: NodeValue<RolePermissions>;
    type Commands: NodeValue<Commands>;
    type Triggers: NodeValue<Triggers>;
    type Executables: NodeValue<Executables>;
    type Authorizers: NodeValue<Authorizers>;
    // Rank 2
    type Parameter: NodeValue<Parameter>;
    type Peer: NodeValue<Peer>;
    type Domain: NodeValue<Domain>;
    type Account: NodeValue<Account>;
    type Asset: NodeValue<Asset>;
    type Nft: NodeValue<Nft>;
    type AccountAsset: NodeValue<AccountAsset>;
    type Role: NodeValue<Role>;
    type Permission: NodeValue<Permission>;
    type AccountRole: NodeValue<AccountRole>;
    type AccountPermission: NodeValue<AccountPermission>;
    type RolePermission: NodeValue<RolePermission>;
    type Command: NodeValue<Command>;
    type Trigger: NodeValue<Trigger>;
    type Executable: NodeValue<Executable>;
    type Authorizer: NodeValue<Authorizer>;
    // Rank 3
    type Metadata: NodeValue<Metadata>;
}

macro_rules! declare_node_keys {
    ($(($ident:ident, $key:ty, $ext:ty),)+) => {
        $(
        struct $ident;

        impl NodeKey for $ident {
            type Key = $key;
            type Ext = $ext;
        }
        )+
    };
}

declare_node_keys!(
    // Rank 1
    (Parameters, (), Parameter),
    (Peers, (), Peer),
    (Domains, (), Domain),
    (Accounts, (), Account),
    (Assets, (), Asset),
    (Nfts, (), Nft),
    (AccountAssets, (), AccountAsset),
    (Roles, (), Role),
    (Permissions, (), Permission),
    (AccountRoles, (), AccountRole),
    (AccountPermissions, (), AccountPermission),
    (RolePermissions, (), RolePermission),
    (Commands, (), Command),
    (Triggers, (), Trigger),
    (Executables, (), Executable),
    (Authorizers, (), Authorizer),
    // Rank 2
    (Parameter, (), ()),
    (Peer, dm::PeerId, ()),
    (Domain, dm::DomainId, Metadata),
    (Account, dm::AccountId, Metadata),
    (Asset, tr::AssetId, Metadata),
    (Nft, tr::NftId, Metadata),
    (AccountAsset, (dm::AccountId, tr::AssetId), ()),
    (Role, dm::RoleId, ()),
    (Permission, tr::PermissionId, ()),
    (AccountRole, (dm::AccountId, dm::RoleId), ()),
    (AccountPermission, (dm::AccountId, tr::PermissionId), ()),
    (RolePermission, (dm::RoleId, tr::PermissionId), ()),
    (Command, tr::CommandId, ()),
    (Trigger, dm::TriggerId, Metadata),
    (Executable, tr::ExecutableId, ()),
    (Authorizer, tr::AuthorizerId, ()),
    // Rank 3
    (Metadata, dm::Name, ()),
);

impl NodeKey for () {
    type Key = ();
    type Ext = ();
}

macro_rules! impl_node_values {
    ($(($ty:ty, $key:ty, $ext:ty),)+) => {
        $(
        impl NodeValue<$key> for $ty {
            type Value = Self;
            type Ext = $ext;
        }
        )+
    };
}

impl_node_values!(((), (), ()),);

trait NodeWrite<T: NodeKey>: NodeValue<T> + Filtered {
    type Status: NodeValue<T> + Filtered;

    fn as_status(&self) -> Self::Status;
}

trait Filtered {
    type Filter: PartialOrd;

    fn as_filter(&self) -> Self::Filter;

    fn passes(&self, filter: Self::Filter) -> bool {
        self.as_filter() <= filter
    }
}

#[derive(Debug, PartialEq, From)]
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

impl_node_values!(
    // Rank 1
    (FilterU8, Parameters, FilterU8),
    (FilterU8, Peers, FilterU8),
    (FilterU8, Domains, FilterU8),
    (FilterU8, Accounts, FilterU8),
    (FilterU8, Assets, FilterU8),
    (FilterU8, Nfts, FilterU8),
    (FilterU8, AccountAssets, FilterU8),
    (FilterU8, Roles, FilterU8),
    (FilterU8, Permissions, FilterU8),
    (FilterU8, AccountRoles, FilterU8),
    (FilterU8, AccountPermissions, FilterU8),
    (FilterU8, RolePermissions, FilterU8),
    (FilterU8, Commands, FilterU8),
    (FilterU8, Triggers, FilterU8),
    (FilterU8, Executables, FilterU8),
    (FilterU8, Authorizers, FilterU8),
    // Rank 2
    (FilterU8, Parameter, ()),
    (FilterU8, Peer, ()),
    (FilterU8, Domain, FilterU8),
    (FilterU8, Account, FilterU8),
    (FilterU8, Asset, FilterU8),
    (FilterU8, Nft, FilterU8),
    (FilterU8, AccountAsset, ()),
    (FilterU8, Role, ()),
    (FilterU8, Permission, ()),
    (FilterU8, AccountRole, ()),
    (FilterU8, AccountPermission, ()),
    (FilterU8, RolePermission, ()),
    (FilterU8, Command, ()),
    (FilterU8, Trigger, FilterU8),
    (FilterU8, Executable, ()),
    (FilterU8, Authorizer, ()),
    // Rank 3
    (FilterU8, Metadata, ()),
);

mod changeset;
mod event;
mod permission;
mod receptor;
mod state;

mod transitional {
    use super::*;

    pub type AssetId = dm::AssetDefinitionId;

    pub type NftId = dm::AssetDefinitionId;

    #[derive(Hash)]
    pub struct PermissionId;

    #[derive(Hash)]
    pub struct CommandId;

    #[derive(Hash)]
    pub struct ExecutableId;

    #[derive(Hash)]
    pub struct AuthorizerId;
}

use transitional as tr;

mod dm {
    pub use iroha_data_model::{ipfs::IpfsPath, parameter::CustomParameterId, prelude::*};
}
