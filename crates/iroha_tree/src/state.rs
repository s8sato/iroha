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
    type Condition = tr::ConditionValue;
    type Executable = tr::ExecutableValue;
    type TriggerCondition = ();
    type TriggerExecutable = ();
    type AccountTrigger = ();
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

    #[derive(Debug, PartialEq, Eq, From)]
    pub struct TriggerValue {
        pub(crate) repeats: dm::Repeats,
    }

    #[derive(Debug, PartialEq, Eq, From)]
    pub enum ConditionValue {
        World(receptor::Receptor),
        Time(dm::TimeSchedule),
        Block(BlockCommit),
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct BlockCommit;

    #[derive(Debug, PartialEq, Eq, From)]
    pub enum ExecutableValue {
        Static(changeset::ChangeSet),
        Dynamic(WasmExecutable),
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct WasmExecutable;

    #[derive(Debug, PartialEq, Eq, From)]
    pub struct MetadataValue {
        pub(crate) json: dm::Json,
    }

    #[derive(Debug, PartialEq, Eq, Constructor, Clone)]
    pub struct TriggerEntry<'a> {
        pub id: &'a dm::TriggerId,
        pub condition: &'a ConditionValue,
        pub executable: &'a ExecutableValue,
    }

    #[derive(Debug, PartialEq, Eq, Constructor, Clone)]
    pub struct WorldTriggerEntry<'a> {
        pub id: &'a dm::TriggerId,
        pub receptor: &'a receptor::Receptor,
        pub executable: &'a ExecutableValue,
    }

    impl<'a> TryFrom<TriggerEntry<'a>> for WorldTriggerEntry<'a> {
        type Error = &'static str;

        fn try_from(entry: TriggerEntry<'a>) -> Result<Self, Self::Error> {
            match entry.condition {
                ConditionValue::World(receptor) => {
                    Ok(WorldTriggerEntry::new(entry.id, receptor, entry.executable))
                }
                _ => Err("conversion succeeds only when this trigger subscribes to world events"),
            }
        }
    }

    impl PartialState {
        pub fn triggers(&self) -> impl Iterator<Item = TriggerEntry> {
            let ids = self.keys().filter_map(|k| match k {
                NodeKey::Trigger(Some(id)) => Some(&**id),
                _ => None,
            });
            let conditions: HashMap<_, _> = self
                .keys()
                .filter_map(|k| match k {
                    NodeKey::TriggerCondition((Some(trg), Some(con))) => {
                        let Some(NodeValue::Condition(condition)) =
                            self.get(&NodeKey::Condition(Some(con.clone())))
                        else {
                            panic!("should be loaded into the partial state")
                        };
                        Some((&**trg, condition))
                    }
                    _ => None,
                })
                .collect();
            let executables: HashMap<_, _> = self
                .keys()
                .filter_map(|k| match k {
                    NodeKey::TriggerExecutable((Some(trg), Some(exe))) => {
                        let Some(NodeValue::Executable(executable)) =
                            self.get(&NodeKey::Executable(Some(exe.clone())))
                        else {
                            panic!("should be loaded into the partial state")
                        };
                        Some((&**trg, executable))
                    }
                    _ => None,
                })
                .collect();

            ids.map(move |id| {
                let condition = *conditions
                    .get(id)
                    .expect("should be loaded into the partial state");
                let executable = *executables
                    .get(id)
                    .expect("should be loaded into the partial state");
                TriggerEntry::new(id, condition, executable)
            })
        }

        pub fn world_triggers(&self) -> impl Iterator<Item = WorldTriggerEntry> {
            self.triggers().filter_map(|entry| entry.try_into().ok())
        }
    }

    impl TriggerEntry<'_> {
        pub fn leads_to_event_loop(&self, state: &PartialState) -> bool {
            let mut world_triggers: HashMap<_, _> = state
                .world_triggers()
                .map(|entry| (entry.id, (entry.receptor, entry.executable)))
                .collect();
            if let Ok(entry) = WorldTriggerEntry::try_from(self.clone()) {
                world_triggers.insert(entry.id, (entry.receptor, entry.executable));
            }
            let mut stack = vec![self.id];
            let mut seen = HashSet::new();
            while let Some(trigger_id) = stack.pop() {
                if seen.contains(&trigger_id) {
                    return true;
                }
                seen.insert(trigger_id);
                let event_expected = match &world_triggers[trigger_id].1 {
                    state::tr::ExecutableValue::Static(changeset) => changeset.as_status(),
                    state::tr::ExecutableValue::Dynamic(_wasm) => {
                        todo!("Wasm executable should declare the union of possible events")
                    }
                };
                if event_expected.iter().any(|(_k, v)| {
                    matches!(
                        v,
                        NodeValue::TriggerCondition(event::UnitS::Create)
                            | NodeValue::TriggerExecutable(event::UnitS::Create)
                    )
                }) {
                    // Trigger registration by another trigger is not allowed unless Wasm executables declare the candidate trigger executables.
                    return true;
                }
                let next_trigger_ids = world_triggers.iter().filter_map(|(id, (receptor, _))| {
                    event_expected.passes(receptor).is_ok().then_some(id)
                });
                stack.extend(next_trigger_ids);
            }
            false
        }
    }

    impl TryFrom<(dm::AccountId, dm::Executable)> for ExecutableValue {
        type Error = Box<NodeConflict<changeset::Write>>;

        fn try_from(
            (authority, executable): (dm::AccountId, dm::Executable),
        ) -> Result<Self, Self::Error> {
            match executable {
                dm::Executable::Instructions(instructions) => {
                    let changeset =
                        changeset::ChangeSet::try_from((authority, instructions.into_vec()))?;
                    Ok(changeset.into())
                }
                dm::Executable::Wasm(_wasm) => Ok(WasmExecutable.into()),
            }
        }
    }
}

pub use transitional as tr;

#[cfg(test)]
mod tests {
    use dm::{DomainId, Repeats, TriggerId};

    use super::{transitional::TriggerEntry, *};
    use crate::{
        changeset::{ChangeSet, ConditionW, DomainW, ExecutableW, TriggerW, UnitW},
        receptor::Receptor,
    };

    /// See the corresponding integration test `triggers::not_registered_when_potential_event_loop_detected`.
    #[test]
    fn event_loop_detection() {
        // Subscribes to changes in the domain "dom_{i}" with statuses "{s}".
        let receptor = |i: usize, s: &str| {
            Receptor::from_iter([node_key_value!(
                Domain,
                DomainId::from_str(&format!("dom_{i}")).unwrap(),
                FilterU8::from_str(s).unwrap()
            )])
        };
        // Publishes the deletion of the domain "dom_{j}".
        let changeset = |j: usize| {
            ChangeSet::from_iter([node_key_value!(
                Domain,
                DomainId::from_str(&format!("dom_{j}")).unwrap(),
                DomainW::Delete(())
            )])
        };
        // Bridges the above subscriber and publisher.
        let trigger = |i: usize, s: &str, j: usize| {
            (
                (
                    TriggerId::from_str(&format!("trg_{i}_{j}")).unwrap(),
                    tr::TriggerValue::from(Repeats::Indefinitely),
                ),
                (
                    crate::tr::ConditionId::from_str(&format!("con_{i}?{s}")).unwrap(),
                    tr::ConditionValue::from(receptor(i, s)),
                ),
                (
                    crate::tr::ExecutableId::from_str(&format!("exe_{j}")).unwrap(),
                    tr::ExecutableValue::from(changeset(j)),
                ),
            )
        };
        // A potential connection exists through the deletion of "dom_1".
        let (trg_0d_1d, trg_1d_2d) = (trigger(0, "d", 1), trigger(1, "d", 2));
        // The state after registering the above triggers.
        let state = PartialState::from_iter([
            node_key_value!(Condition, trg_0d_1d.1 .0.clone(), trg_0d_1d.1 .1),
            node_key_value!(Condition, trg_1d_2d.1 .0.clone(), trg_1d_2d.1 .1),
            node_key_value!(Executable, trg_0d_1d.2 .0.clone(), trg_0d_1d.2 .1),
            node_key_value!(Executable, trg_1d_2d.2 .0.clone(), trg_1d_2d.2 .1),
            node_key_value!(TriggerCondition, trg_0d_1d.0 .0.clone(), trg_0d_1d.1 .0, ()),
            node_key_value!(TriggerCondition, trg_1d_2d.0 .0.clone(), trg_1d_2d.1 .0, ()),
            node_key_value!(
                TriggerExecutable,
                trg_0d_1d.0 .0.clone(),
                trg_0d_1d.2 .0,
                ()
            ),
            node_key_value!(
                TriggerExecutable,
                trg_1d_2d.0 .0.clone(),
                trg_1d_2d.2 .0,
                ()
            ),
            node_key_value!(Trigger, trg_0d_1d.0 .0, trg_0d_1d.0 .1),
            node_key_value!(Trigger, trg_1d_2d.0 .0, trg_1d_2d.0 .1),
        ]);

        for (entry, leads_to_event_loop) in [
            // Short-circuiting.
            (trigger(2, "d", 0), true),
            // No short-circuiting due to status mismatch.
            (trigger(2, "cu", 0), false),
            // Extending the graph.
            (trigger(2, "d", 3), false),
            // Creating another cyclic cluster.
            (trigger(3, "d", 3), true),
            // Creating another acyclic cluster.
            (trigger(3, "d", 4), false),
            {
                let mut trg_3d_x = trigger(3, "d", 4);
                let another = trigger(10, "", 20);
                trg_3d_x.2 .1 = ChangeSet::from_iter([
                    node_key_value!(
                        Condition,
                        another.1 .0.clone(),
                        ConditionW::Set(another.1 .1)
                    ),
                    node_key_value!(
                        Executable,
                        another.2 .0.clone(),
                        ExecutableW::Set(another.2 .1)
                    ),
                    node_key_value!(
                        TriggerCondition,
                        another.0 .0.clone(),
                        another.1 .0,
                        UnitW::Create(())
                    ),
                    node_key_value!(
                        TriggerExecutable,
                        another.0 .0.clone(),
                        another.2 .0,
                        UnitW::Create(())
                    ),
                    node_key_value!(Trigger, another.0 .0, TriggerW::Create(another.0 .1)),
                ])
                .into();
                // Creating an additional trigger.
                (trg_3d_x, true)
            },
        ]
        .iter()
        .map(|(trg, b)| (TriggerEntry::new(&trg.0 .0, &trg.1 .1, &trg.2 .1), *b))
        {
            assert_eq!(leads_to_event_loop, entry.leads_to_event_loop(&state));
        }
    }
}
