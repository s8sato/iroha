use super::*;

pub type State = Leaves<()>;

pub type StateRef<'a> = LeavesRef<'a, ()>;

impl LeafMode for () {
    type Authorizer = tr::AuthorizerValue;
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
    type Metadata = tr::MetadataValue;
}

pub mod transitional {
    use std::collections::HashSet;

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    pub struct AuthorizerValue;

    #[derive(Debug, PartialEq, Eq)]
    pub struct ParameterValue {
        pub(crate) parameter: dm::Parameter,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct DomainValue {
        pub(crate) logo: Option<dm::IpfsPath>,
        pub(crate) admin: dm::AccountId,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct AssetValue {
        pub(crate) total_quantity: dm::Numeric,
        pub(crate) mintable: dm::Mintable,
        pub(crate) logo: Option<dm::IpfsPath>,
        pub(crate) admin: dm::AccountId,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct NftValue {
        pub(crate) owner: dm::AccountId,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct AccountAssetValue {
        pub(crate) balance: dm::Numeric,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct PermissionValue {
        pub(crate) permission: permission::Permission,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct CommandValue {
        pub(crate) changeset: changeset::ChangeSet,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct TriggerValue {
        pub(crate) receptor: receptor::Receptor,
        pub(crate) executable: self::TriggerExecutable,
        pub(crate) repeats: dm::Repeats,
        pub(crate) authority: dm::AccountId,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub enum TriggerExecutable {
        Cmd(crate::tr::CommandId),
        Exe(crate::tr::ExecutableId),
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct ExecutableValue;

    #[derive(Debug, PartialEq, Eq)]
    pub struct MetadataValue {
        pub(crate) json: dm::Json,
    }

    impl State {
        fn triggers(&self) -> HashMap<dm::TriggerId, &TriggerValue> {
            todo!()
        }

        fn command(&self, _id: &crate::tr::CommandId) -> Option<&CommandValue> {
            todo!()
        }
    }

    impl TriggerValue {
        fn leads_event_loops(&self, candidate_id: &dm::TriggerId, state: &State) -> bool {
            let mut triggers = state.triggers();
            triggers.insert(candidate_id.clone(), self);
            let mut stack = vec![candidate_id];
            let mut seen = HashSet::new();
            while let Some(trigger_id) = stack.pop() {
                if seen.contains(&trigger_id) {
                    return true;
                }
                seen.insert(trigger_id);
                let changeset = {
                    let TriggerExecutable::Cmd(cmd_id) = &triggers[trigger_id].executable else {
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
