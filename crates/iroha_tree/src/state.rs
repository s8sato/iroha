use super::*;

pub type PartialState = Tree<()>;

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
    type AccountTrigger = ();
    type Executable = tr::WasmExecutableValue;
    type DomainMetadata = tr::MetadataValue;
    type AccountMetadata = tr::MetadataValue;
    type AssetMetadata = tr::MetadataValue;
    type NftData = tr::MetadataValue;
    type TriggerMetadata = tr::MetadataValue;
}

pub mod transitional {
    use std::collections::HashSet;

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

    impl PartialState {
        fn triggers(&self) -> impl Iterator<Item = (&dm::TriggerId, &TriggerValue)> {
            self.iter().filter_map(|(k, v)| match (k, v) {
                (NodeKey::Trigger(Some(k)), NodeValue::Trigger(v)) => Some((&**k, v)),
                _ => None,
            })
        }
    }

    impl TriggerValue {
        pub fn leads_to_event_loop(
            &self,
            candidate_id: &dm::TriggerId,
            state: &PartialState,
        ) -> bool {
            let mut triggers: HashMap<_, _> = state.triggers().collect();
            triggers.insert(candidate_id, self);
            let mut stack = vec![candidate_id];
            let mut seen = HashSet::new();
            while let Some(trigger_id) = stack.pop() {
                if seen.contains(&trigger_id) {
                    return true;
                }
                seen.insert(trigger_id);
                let event_expected = match &triggers[trigger_id].executable {
                    state::tr::TriggerExecutable::Static(changeset) => changeset.as_status(),
                    state::tr::TriggerExecutable::Dynamic(_wasm) => {
                        todo!("Wasm executable should declare the union of possible events")
                    }
                };
                if event_expected
                    .iter()
                    .any(|(_k, v)| matches!(v, NodeValue::Trigger(event::TriggerS::Create)))
                {
                    // Trigger registration by another trigger is not allowed unless Wasm executables declare the candidate trigger executables.
                    return true;
                }
                let next_trigger_ids = triggers
                    .iter()
                    .filter_map(|(id, v)| event_expected.passes(&v.receptor).is_ok().then_some(id));
                stack.extend(next_trigger_ids);
            }
            false
        }
    }

    impl TryFrom<dm::Action> for TriggerValue {
        type Error = TryFromError;

        fn try_from(value: dm::Action) -> Result<Self, Self::Error> {
            let (executable, wasm_entry) =
                TriggerExecutable::from_and_entry(value.executable, value.authority)?;
            iroha_logger::info!("discarding Wasm entry:\n{wasm_entry:#?}");
            Ok(Self::new(value.filter.into(), executable, value.repeats))
        }
    }

    type WasmEntry = Option<(NodeKey, NodeValue<changeset::Write>)>;
    type TryFromError = Box<NodeConflict<changeset::Write>>;

    impl TriggerExecutable {
        /// # Errors
        ///
        /// SATO docs
        pub fn from_and_entry(
            executable: dm::Executable,
            authority: dm::AccountId,
        ) -> Result<(Self, WasmEntry), TryFromError> {
            match executable {
                dm::Executable::Instructions(instructions) => {
                    let changeset =
                        changeset::ChangeSet::try_from((authority, instructions.into_vec()))?;
                    Ok((changeset.into(), None))
                }
                dm::Executable::Wasm(wasm) => {
                    let wasm_id = crate::tr::WasmExecutableId::from(dm::HashOf::new(&wasm));
                    let (k, v) = node_key_value!(
                        Executable,
                        wasm_id.clone(),
                        changeset::ExecutableW::Set(wasm)
                    );
                    Ok((wasm_id.into(), Some((k, v))))
                }
            }
        }
    }
}

pub use transitional as tr;
