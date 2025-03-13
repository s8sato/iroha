//! Transitional interface for [`iroha_tree::state`].

use std::rc::Rc;

use iroha_tree::{changeset, event, node_key_value, readset, receptor, state};
use mv::storage::StorageReadOnly;

use super::*;
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
                NodeKey::Trigger(key) => {
                    self.world()
                        .triggers()
                        // Other types of triggers are irrelevant as long as this function is used solely for event loop detection.
                        .data_triggers()
                        .iter()
                        .filter(|(id, _)| key.as_ref().map_or(true, |key| **key == **id))
                        .for_each(|(id, action)| {
                            let trigger = state::tr::TriggerValue::from(action.repeats);
                            let condition = receptor::Receptor::from(action.filter.clone()).into();
                            let executable = match action.executable() {
                                ExecutableRef::Wasm(_hash) => {
                                    let wasm = state::tr::WasmExecutable;
                                    state::tr::ExecutableValue::Dynamic(wasm)
                                }
                                ExecutableRef::Instructions(instructions) => {
                                    let changeset = (
                                        action.authority.clone(),
                                        instructions.clone().into_vec(),
                                    )
                                        .try_into()
                                        .expect("instructions that are already registered as an executable should be converted into a changeset");
                                    state::tr::ExecutableValue::Static(changeset)
                                }
                            };
                            let trigger_id = id.clone();
                            let condition_id = trigger_id.clone();
                            let executable_id = trigger_id.clone();

                            for (k, v) in [
                                node_key_value!(Trigger, trigger_id.clone(), trigger),
                                node_key_value!(
                                    Condition,
                                    condition_id.clone(),
                                    condition
                                ),
                                node_key_value!(
                                    Executable,
                                    executable_id.clone(),
                                    executable
                                ),
                                node_key_value!(
                                    TriggerCondition,
                                    trigger_id.clone(),
                                    condition_id,
                                    ()
                                ),
                                node_key_value!(
                                    TriggerExecutable,
                                    trigger_id.clone(),
                                    executable_id,
                                    ()
                                ),
                                node_key_value!(
                                    TriggerAdmin,
                                    trigger_id,
                                    action.authority.signatory.clone(),
                                    action.authority.domain.clone(),
                                    ()
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
