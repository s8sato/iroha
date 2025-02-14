use super::*;

pub type ChangeSet = Tree<Write>;

pub struct Write;

impl Mode for Write {
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
    type Parameter = ParameterW;
    type Peer = UnitW;
    type Domain = DomainW;
    type Account = UnitW;
    type Asset = AssetW;
    type Nft = NftW;
    type AccountAsset = AccountAssetW;
    type Role = UnitW;
    type Permission = PermissionW;
    type AccountRole = UnitW;
    type AccountPermission = UnitW;
    type RolePermission = UnitW;
    type Command = CommandW;
    type Trigger = TriggerW;
    type Executable = ExecutableW;
    type Authorizer = AuthorizerW;
    // Rank 3
    type Metadata = MetadataW;
}

impl_node_values!(
    // Rank 1
    (Write, Parameters, ParameterW),
    (Write, Peers, UnitW),
    (Write, Domains, DomainW),
    (Write, Accounts, UnitW),
    (Write, Assets, AssetW),
    (Write, Nfts, NftW),
    (Write, AccountAssets, AccountAssetW),
    (Write, Roles, UnitW),
    (Write, Permissions, PermissionW),
    (Write, AccountRoles, UnitW),
    (Write, AccountPermissions, UnitW),
    (Write, RolePermissions, UnitW),
    (Write, Commands, CommandW),
    (Write, Triggers, TriggerW),
    (Write, Executables, ExecutableW),
    (Write, Authorizers, AuthorizerW),
    // Rank 2
    (ParameterW, Parameter, ()),
    (UnitW, Peer, ()),
    (DomainW, Domain, MetadataW),
    (UnitW, Account, MetadataW),
    (AssetW, Asset, MetadataW),
    (NftW, Nft, ()),
    (AccountAssetW, AccountAsset, ()),
    (UnitW, Role, ()),
    (PermissionW, Permission, ()),
    (UnitW, AccountRole, ()),
    (UnitW, AccountPermission, ()),
    (UnitW, RolePermission, ()),
    (CommandW, Command, ()),
    (TriggerW, Trigger, MetadataW),
    (ExecutableW, Executable, ()),
    (AuthorizerW, Authorizer, ()),
    // Rank 3
    (MetadataW, Metadata, ()),
);

macro_rules! impl_node_write {
    ($(($ty:ty, $key:ty, $status:ident),)+) => {
        $(
        impl NodeWrite<$key> for $ty {
            type Status = event::$status;

            fn as_status(&self) -> Self::Status {
                todo!()
            }
        }
        )+
    };
}

impl_node_write!(
    // Rank 2
    (ParameterW, Parameter, ParameterWS),
    (UnitW, Peer, UnitWS),
    (DomainW, Domain, DomainWS),
    (UnitW, Account, UnitWS),
    (AssetW, Asset, AssetWS),
    (NftW, Nft, NftWS),
    (AccountAssetW, AccountAsset, AccountAssetWS),
    (UnitW, Role, UnitWS),
    (PermissionW, Permission, PermissionWS),
    (UnitW, AccountRole, UnitWS),
    (UnitW, AccountPermission, UnitWS),
    (UnitW, RolePermission, UnitWS),
    (CommandW, Command, CommandWS),
    (TriggerW, Trigger, TriggerWS),
    (ExecutableW, Executable, ExecutableWS),
    (AuthorizerW, Authorizer, AuthorizerWS),
    // Rank 3
    (MetadataW, Metadata, MetadataWS),
);

macro_rules! impl_filtered {
    ($($ty:ty,)+) => {
        $(
        impl Filtered for $ty {
            type Filter = super::FilterU8;

            fn as_filter(&self) -> Self::Filter {
                todo!()
                // self.as_status().as_filter()
            }
        }
        )+
    };
}

impl_filtered!(
    // Rank 2
    UnitW,
    ParameterW,
    DomainW,
    AssetW,
    NftW,
    AccountAssetW,
    PermissionW,
    CommandW,
    TriggerW,
    ExecutableW,
    AuthorizerW,
    // Rank 3
    MetadataW,
);

pub enum UnitW {
    Create,
    Delete,
}

pub enum ParameterW {
    Set(state::tr::ParameterValue),
    Unset(dm::CustomParameterId),
}

pub enum DomainW {
    Transfer(dm::AccountId),
    Create(state::tr::DomainValue),
    Delete,
}

pub enum AssetW {
    Transfer(dm::AccountId),
    Create(state::tr::AssetValue),
    Delete,
}

pub enum NftW {
    Transfer(dm::AccountId),
    Create(state::tr::NftValue),
    Delete,
}

pub enum AccountAssetW {
    Receive(dm::Numeric),
    Send(dm::Numeric),
    Mint(dm::Numeric),
    Burn(dm::Numeric),
}

pub enum PermissionW {
    Set(state::tr::PermissionValue),
    Unset,
}

pub enum CommandW {
    Set(state::tr::CommandValue),
    Unset,
}

pub enum TriggerW {
    Inc(u32),
    Dec(u32),
    Create(state::tr::TriggerValue),
    Delete,
}

pub enum ExecutableW {
    Set(state::tr::ExecutableValue),
    Unset,
}

pub enum AuthorizerW {
    Update(state::tr::AuthorizerValue),
}

pub enum MetadataW {
    Set(state::tr::MetadataValue),
    Unset,
}

mod transitional {}
