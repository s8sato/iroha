use super::*;

type State = Tree<()>;

impl Mode for () {
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
    type Parameter = tr::ParameterValue;
    type Peer = ();
    type Domain = tr::DomainValue;
    type Account = ();
    type Asset = tr::AssetValue;
    type Nft = tr::NftValue;
    type AccountAsset = tr::AccountAssetValue;
    type Role = ();
    type Permission = tr::PermissionValue;
    type AccountRole = ();
    type AccountPermission = ();
    type RolePermission = ();
    type Command = tr::CommandValue;
    type Trigger = tr::TriggerValue;
    type Executable = tr::ExecutableValue;
    type Authorizer = tr::AuthorizerValue;
    // Rank 3
    type Metadata = tr::MetadataValue;
}

impl_node_values!(
    // Rank 1
    ((), Parameters, tr::ParameterValue),
    ((), Peers, ()),
    ((), Domains, tr::DomainValue),
    ((), Accounts, ()),
    ((), Assets, tr::AssetValue),
    ((), Nfts, tr::NftValue),
    ((), AccountAssets, tr::AccountAssetValue),
    ((), Roles, ()),
    ((), Permissions, tr::PermissionValue),
    ((), AccountRoles, ()),
    ((), AccountPermissions, ()),
    ((), RolePermissions, ()),
    ((), Commands, tr::CommandValue),
    ((), Triggers, tr::TriggerValue),
    ((), Executables, tr::ExecutableValue),
    ((), Authorizers, tr::AuthorizerValue),
    // Rank 2
    (tr::ParameterValue, Parameter, ()),
    ((), Peer, ()),
    (tr::DomainValue, Domain, tr::MetadataValue),
    ((), Account, tr::MetadataValue),
    (tr::AssetValue, Asset, tr::MetadataValue),
    (tr::NftValue, Nft, tr::MetadataValue),
    (tr::AccountAssetValue, AccountAsset, ()),
    ((), Role, ()),
    (tr::PermissionValue, Permission, ()),
    ((), AccountRole, ()),
    ((), AccountPermission, ()),
    ((), RolePermission, ()),
    (tr::CommandValue, Command, ()),
    (tr::TriggerValue, Trigger, tr::MetadataValue),
    (tr::ExecutableValue, Executable, ()),
    (tr::AuthorizerValue, Authorizer, ()),
    // Rank 3
    (tr::MetadataValue, Metadata, ()),
);

pub mod transitional {
    use super::*;

    #[derive(Debug, PartialEq)]
    pub struct ParameterValue {
        parameter: dm::Parameter,
    }

    #[derive(Debug, PartialEq)]
    pub struct DomainValue {
        logo: Option<dm::IpfsPath>,
        admin: dm::AccountId,
    }

    #[derive(Debug, PartialEq)]
    pub struct AssetValue {
        total_quantity: dm::Numeric,
        mintable: dm::Mintable,
        logo: Option<dm::IpfsPath>,
        admin: dm::AccountId,
    }

    #[derive(Debug, PartialEq)]
    pub struct NftValue {
        owner: dm::AccountId,
    }

    #[derive(Debug, PartialEq)]
    pub struct AccountAssetValue {
        balance: dm::Numeric,
    }

    #[derive(Debug, PartialEq)]
    pub struct PermissionValue {
        permission: permission::Permission,
    }

    #[derive(Debug, PartialEq)]
    pub struct CommandValue {
        changeset: changeset::ChangeSet,
    }

    #[derive(Debug, PartialEq)]
    pub struct TriggerValue {
        receptor: receptor::Receptor,
        executable: self::TriggerExecutable,
        repeats: dm::Repeats,
        authority: dm::AccountId,
    }

    #[derive(Debug, PartialEq)]
    enum TriggerExecutable {
        Cmd(crate::tree::tr::CommandId),
        Exe(crate::tree::tr::ExecutableId),
    }

    #[derive(Debug, PartialEq)]
    pub struct ExecutableValue {
        wasm: dm::WasmSmartContract,
    }

    #[derive(Debug, PartialEq)]
    pub struct AuthorizerValue {
        wasm: dm::WasmSmartContract,
    }

    #[derive(Debug, PartialEq)]
    pub struct MetadataValue {
        json: dm::Json,
    }
}

pub use transitional as tr;
