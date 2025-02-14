use super::*;

pub type Event = Tree<WriteStatus>;

pub struct WriteStatus;

impl Mode for WriteStatus {
    // Rank 1
    type Parameters = ();
    type Peers = ();
    type Domains = ();
    type Accounts = ();
    type Assets = ();
    type Nfts = ();
    type AccountAssets = ();
    type Roles = ();
    type Permissions = ();
    type AccountRoles = ();
    type AccountPermissions = ();
    type RolePermissions = ();
    type Commands = ();
    type Triggers = ();
    type Executables = ();
    type Authorizers = ();
    // Rank 2
    type Parameter = ParameterWS;
    type Peer = UnitWS;
    type Domain = DomainWS;
    type Account = UnitWS;
    type Asset = AssetWS;
    type Nft = NftWS;
    type AccountAsset = AccountAssetWS;
    type Role = UnitWS;
    type Permission = PermissionWS;
    type AccountRole = UnitWS;
    type AccountPermission = UnitWS;
    type RolePermission = UnitWS;
    type Command = CommandWS;
    type Trigger = TriggerWS;
    type Executable = ExecutableWS;
    type Authorizer = AuthorizerWS;
    // Rank 3
    type Metadata = MetadataWS;
}

impl_node_values!(
    // Rank 1
    (WriteStatus, Parameters, ParameterWS),
    (WriteStatus, Peers, UnitWS),
    (WriteStatus, Domains, DomainWS),
    (WriteStatus, Accounts, UnitWS),
    (WriteStatus, Assets, AssetWS),
    (WriteStatus, Nfts, NftWS),
    (WriteStatus, AccountAssets, AccountAssetWS),
    (WriteStatus, Roles, UnitWS),
    (WriteStatus, Permissions, PermissionWS),
    (WriteStatus, AccountRoles, UnitWS),
    (WriteStatus, AccountPermissions, UnitWS),
    (WriteStatus, RolePermissions, UnitWS),
    (WriteStatus, Commands, CommandWS),
    (WriteStatus, Triggers, TriggerWS),
    (WriteStatus, Executables, ExecutableWS),
    (WriteStatus, Authorizers, AuthorizerWS),
    // Rank 2
    (ParameterWS, Parameter, ()),
    (UnitWS, Peer, ()),
    (DomainWS, Domain, MetadataWS),
    (UnitWS, Account, MetadataWS),
    (AssetWS, Asset, MetadataWS),
    (NftWS, Nft, ()),
    (AccountAssetWS, AccountAsset, ()),
    (UnitWS, Role, ()),
    (PermissionWS, Permission, ()),
    (UnitWS, AccountRole, ()),
    (UnitWS, AccountPermission, ()),
    (UnitWS, RolePermission, ()),
    (CommandWS, Command, ()),
    (TriggerWS, Trigger, MetadataWS),
    (ExecutableWS, Executable, ()),
    (AuthorizerWS, Authorizer, ()),
    // Rank 3
    (MetadataWS, Metadata, ()),
);

macro_rules! impl_filtered {
    ($($ty:ty,)+) => {
        $(
        impl Filtered for $ty {
            type Filter = super::FilterU8;

            fn as_filter(&self) -> Self::Filter {
                todo!()
            }
        }
        )+
    };
}

impl_filtered!(
    // Rank 2
    UnitWS,
    ParameterWS,
    DomainWS,
    AssetWS,
    NftWS,
    AccountAssetWS,
    PermissionWS,
    CommandWS,
    TriggerWS,
    ExecutableWS,
    AuthorizerWS,
    // Rank 3
    MetadataWS,
);

pub enum UnitWS {}

pub enum ParameterWS {}

pub enum DomainWS {}

pub enum AssetWS {}

pub enum NftWS {}

pub enum AccountAssetWS {}

pub enum PermissionWS {}

pub enum CommandWS {}

pub enum TriggerWS {}

pub enum ExecutableWS {}

pub enum AuthorizerWS {}

pub enum MetadataWS {}

mod transitional {}
