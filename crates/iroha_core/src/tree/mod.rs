//! Transitional interface for [`iroha_tree`].

#![allow(dead_code)] // SATO disallow

use std::rc::Rc;

use iroha_tree::{
    changeset, event, node, readset, receptor, state, transitional as tr, FuzzyNodeKey,
    NodeReadWrite,
};
use mv::storage::StorageReadOnly;

use crate::{
    smartcontracts::triggers::{
        set::{ExecutableRef, SetReadOnly},
        specialized::LoadedActionTrait,
    },
    state::{StateReadOnly, StateTransaction, WorldReadOnly},
};

type State<'block, 'state> = StateTransaction<'block, 'state>;

struct InvariantsViolation;

impl State<'_, '_> {
    /// Unordered reflection to state, allowing inconsistencies between nodes.
    fn update(
        &mut self,
        changeset: changeset::ChangeSet,
    ) -> Result<event::Event, InvariantsViolation> {
        let event = changeset.as_status();

        #[expect(clippy::never_loop)]
        for (_k, _v) in changeset {
            unimplemented!("todo when instructions as an executable were replaced with a changeset")
        }

        self.sanitize(&event)?;
        Ok(event)
    }

    /// Scan and resolve inconsistencies based on events.
    #[expect(clippy::unused_self)]
    fn sanitize(&mut self, _event: &event::Event) -> Result<(), InvariantsViolation> {
        // TODO #4672 Cascade or restrict on delete.
        unimplemented!("todo when instructions as an executable were replaced with a changeset")
    }

    /// SATO docs
    pub fn load(&self, readset: &readset::ReadSet) -> state::PartialState {
        let mut res = state::PartialState::default();
        for (k, _v) in readset.iter() {
            match k {
                FuzzyNodeKey::Trigger(key) => {
                    self.world()
                        .triggers()
                        // Other types of triggers are irrelevant as long as this function is used solely for event loop detection.
                        .data_triggers()
                        .iter()
                        .filter(|(id, _)| key.as_ref().map_or(true, |key| **key == **id))
                        .for_each(|(id, action)| {
                            let trigger = state::tr::TriggerV::from(action.repeats);
                            let condition = state::tr::ConditionV::from(receptor::Receptor::from(action.filter.clone()));
                            let executable = match action.executable() {
                                ExecutableRef::Wasm(_hash) => {
                                    let wasm = state::tr::WasmExecutable;
                                    state::tr::ExecutableV::Dynamic(wasm)
                                }
                                ExecutableRef::Instructions(instructions) => {
                                    let changeset = (
                                        action.authority.clone(),
                                        instructions.clone().into_vec(),
                                    )
                                        .try_into()
                                        .expect("instructions that are already registered as an executable should be converted into a changeset");
                                    state::tr::ExecutableV::Static(changeset)
                                }
                            };
                            let trigger_id = id.clone();
                            let condition_id = tr::ConditionId::from(&condition);
                            let executable_id = tr::ExecutableId::from(&executable);

                            for (k, v) in [
                                node!(Trigger, trigger_id.clone(), trigger),
                                node!(
                                    Condition,
                                    condition_id.clone(),
                                    condition
                                ),
                                node!(
                                    Executable,
                                    executable_id.clone(),
                                    executable
                                ),
                                node!(
                                    TriggerCondition,
                                    trigger_id.clone(),
                                    condition_id,
                                    state::tr::UnitV
                                ),
                                node!(
                                    TriggerExecutable,
                                    trigger_id.clone(),
                                    executable_id,
                                    state::tr::UnitV
                                ),
                                node!(
                                    TriggerAdmin,
                                    trigger_id,
                                    action.authority.signatory.clone(),
                                    action.authority.domain.clone(),
                                    state::tr::UnitV
                                ),
                            ] {
                                res.insert(k, v);
                            }
                        })
                }
                _ => unimplemented!("no use for now"),
            }
        }
        res
    }
}
