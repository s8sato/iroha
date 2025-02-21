use super::*;

pub type State = Tree<()>;

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
    use std::collections::HashSet;

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
    pub struct ExecutableValue;

    #[derive(Debug, PartialEq)]
    pub struct AuthorizerValue;

    #[derive(Debug, PartialEq)]
    pub struct MetadataValue {
        json: dm::Json,
    }

    #[expect(clippy::disallowed_types)]
    use std::collections::HashMap;

    impl State {
        fn triggers(&self) -> HashMap<dm::TriggerId, &TriggerValue> {
            todo!()
        }

        fn command(&self, _id: &crate::tree::tr::CommandId) -> Option<&CommandValue> {
            todo!()
        }
    }

    impl TriggerValue {
        fn leads_event_loops(&self, candidate_id: &dm::TriggerId, state: &State) -> bool {
            let mut triggers: HashMap<dm::TriggerId, &TriggerValue> = state.triggers();
            triggers.insert(candidate_id.clone(), self);
            let mut stack = vec![candidate_id];
            let mut seen = HashSet::new();
            while let Some(trigger_id) = stack.pop() {
                if seen.contains(&trigger_id) {
                    return true;
                }
                seen.insert(trigger_id);
                let changeset = {
                    let TriggerExecutable::Cmd(cmd_id) = &triggers[&trigger_id].executable else {
                        unimplemented!()
                    };
                    &state.command(cmd_id).unwrap().changeset
                };
                // TODO update detection of trigger mutations
                // if changeset.iter().any(|(path, _change)| 100 <= *path) {
                //     return true;
                // }
                let next_trigger_ids = triggers
                    .iter()
                    .filter_map(|(id, v)| changeset.as_status().passes(&v.receptor).then_some(id));
                stack.extend(next_trigger_ids);
            }
            false
        }
    }
}

pub use transitional as tr;
