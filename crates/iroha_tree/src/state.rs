use super::*;

pub type State = Tree<()>;

pub type StateRef<'a> = TreeRef<'a, ()>;

impl Mode for () {
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
    type Trigger = tr::TriggerValue;
    type Executable = tr::WasmExecutableValue;
    type Metadata = tr::MetadataValue;
}

pub mod transitional {
    use std::collections::HashSet;

    use iroha_core::state::StateReadOnly;

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    pub struct AuthorizerValue;

    #[derive(Debug, PartialEq, Eq, From)]
    pub struct ParameterValue {
        pub(crate) parameter: dm::Parameter,
    }

    #[derive(Debug, PartialEq, Eq, From)]
    pub struct DomainValue {
        pub(crate) logo: Option<dm::IpfsPath>,
    }

    #[derive(Debug, PartialEq, Eq, Constructor)]
    pub struct AssetValue {
        pub(crate) total_quantity: dm::Numeric,
        pub(crate) mintable: dm::Mintable,
        pub(crate) logo: Option<dm::IpfsPath>,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct NftValue;

    #[derive(Debug, PartialEq, Eq, From)]
    pub struct AccountAssetValue {
        pub(crate) balance: dm::Numeric,
    }

    #[derive(Debug, PartialEq, Eq, From)]
    pub struct PermissionValue {
        pub(crate) permission: permission::Permission,
    }

    #[derive(Debug, PartialEq, Eq, Constructor)]
    pub struct TriggerValue {
        pub(crate) receptor: receptor::Receptor,
        pub(crate) executable: TriggerExecutable,
        pub(crate) repeats: dm::Repeats,
        pub(crate) authority: dm::AccountId,
    }

    #[derive(Debug, PartialEq, Eq, From)]
    pub enum TriggerExecutable {
        Static(changeset::ChangeSet),
        Dynamic(crate::tr::WasmExecutableId),
    }

    pub type WasmExecutableValue = dm::WasmSmartContract;

    #[derive(Debug, PartialEq, Eq, From)]
    pub struct MetadataValue {
        pub(crate) json: dm::Json,
    }

    impl State {
        fn triggers(&self) -> HashMap<dm::TriggerId, &TriggerValue> {
            // self
            //     .iter()
            //     .filter_by(NodeKey::Trigger(None))
            //     .map(|(NodeKey::Trigger(Some(k)), NodeValue::Trigger(v))| (k, v))
            //     .collect()
            todo!()
        }

        fn load(_state: &impl StateReadOnly, _keys: &impl Iterator<Item = NodeKey>) -> Self {
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
                let event_expected = match &triggers[trigger_id].executable {
                    state::tr::TriggerExecutable::Static(changeset) => changeset.as_status(),
                    state::tr::TriggerExecutable::Dynamic(_wasm) => todo!(),
                };
                // TODO update detection of trigger mutations
                // if event_expected.iter().any(|(k, _v)| k.is_trigger()) {
                //     return true;
                // }
                let next_trigger_ids = triggers
                    .iter()
                    .filter_map(|(id, v)| event_expected.passes(&v.receptor).then_some(id));
                stack.extend(next_trigger_ids);
            }
            false
        }
    }
}

pub use transitional as tr;
