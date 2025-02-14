use super::*;

pub type Receptor = Tree<WriteStatusFilter>;

pub struct WriteStatusFilter;

impl Mode for WriteStatusFilter {
    // Rank 1
    type Parameters = FilterU8;
    type Peers = FilterU8;
    type Domains = FilterU8;
    type Accounts = FilterU8;
    type Assets = FilterU8;
    type Nfts = FilterU8;
    type AccountAssets = FilterU8;
    type Roles = FilterU8;
    type Permissions = FilterU8;
    type AccountRoles = FilterU8;
    type AccountPermissions = FilterU8;
    type RolePermissions = FilterU8;
    type Commands = FilterU8;
    type Triggers = FilterU8;
    type Executables = FilterU8;
    type Authorizers = FilterU8;
    // Rank 2
    type Parameter = FilterU8;
    type Peer = FilterU8;
    type Domain = FilterU8;
    type Account = FilterU8;
    type Asset = FilterU8;
    type Nft = FilterU8;
    type AccountAsset = FilterU8;
    type Role = FilterU8;
    type Permission = FilterU8;
    type AccountRole = FilterU8;
    type AccountPermission = FilterU8;
    type RolePermission = FilterU8;
    type Command = FilterU8;
    type Trigger = FilterU8;
    type Executable = FilterU8;
    type Authorizer = FilterU8;
    // Rank 3
    type Metadata = FilterU8;
}

mod transitional {}
