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
            type Filter = FilterU8;

            fn as_filter(&self) -> Self::Filter {
                FilterU8((*self) as u8)
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

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum UnitWS {
    Create = 0b0000_0010,
    Delete = 0b0000_0100,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ParameterWS {
    Set = 0b0000_0010,
    Unset = 0b0000_0100,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum DomainWS {
    Transfer = 0b0000_0010,
    Create = 0b0000_0100,
    Delete = 0b0000_1000,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum AssetWS {
    Transfer = 0b0000_0010,
    Create = 0b0000_0100,
    Delete = 0b0000_1000,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum NftWS {
    Transfer = 0b0000_0010,
    Create = 0b0000_0100,
    Delete = 0b0000_1000,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum AccountAssetWS {
    Receive = 0b0000_0010,
    Send = 0b0000_0100,
    Mint = 0b0000_1000,
    Burn = 0b0001_0000,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum PermissionWS {
    Set = 0b0000_0010,
    Unset = 0b0000_0100,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum CommandWS {
    Set = 0b0000_0010,
    Unset = 0b0000_0100,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum TriggerWS {
    Increase = 0b0000_0010,
    Decrease = 0b0000_0100,
    Create = 0b0000_1000,
    Delete = 0b0001_0000,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ExecutableWS {
    Set = 0b0000_0010,
    Unset = 0b0000_0100,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum AuthorizerWS {
    Set = 0b0000_0010,
    Unset = 0b0000_0100,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum MetadataWS {
    Set = 0b0000_0010,
    Unset = 0b0000_0100,
}

macro_rules! impl_from_write {
    ($(($ty:ty, $write:ident: $($variant:ident)|+),)+) => {
        $(
        use changeset::$write;

        impl From<&$write> for $ty {
            fn from(value: &$write) -> Self {
                match value {
                    $(
                    $write::$variant(_) => Self::$variant,
                    )+
                }
            }
        }
        )+
    };
}

impl_from_write!(
    // Rank 2
    (UnitWS, UnitW: Create | Delete),
    (ParameterWS, ParameterW: Set | Unset),
    (DomainWS, DomainW: Transfer | Create | Delete),
    (AssetWS, AssetW: Transfer | Create | Delete),
    (NftWS, NftW: Transfer | Create | Delete),
    (AccountAssetWS, AccountAssetW: Receive | Send | Mint | Burn),
    (PermissionWS, PermissionW: Set | Unset),
    (CommandWS, CommandW: Set | Unset),
    (TriggerWS, TriggerW: Increase | Decrease | Create | Delete),
    (ExecutableWS, ExecutableW: Set | Unset),
    (AuthorizerWS, AuthorizerW: Set | Unset),
    // Rank 3
    (MetadataWS, MetadataW: Set | Unset),
);

mod transitional {}
