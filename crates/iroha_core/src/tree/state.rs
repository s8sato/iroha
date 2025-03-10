//! Transitional interface for [`iroha_tree::state`].

use std::rc::Rc;

use iroha_tree::{changeset, event, readset, state};
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

    /// SATO doc
    pub fn load(&self, readset: &readset::ReadSet) -> state::PartialState {
        let mut res = state::PartialState::default();
        for (k, _v) in readset.iter() {
            match k {
                NodeKey::Trigger(key) => {
                    self
                        .world()
                        .triggers()
                        .data_triggers() // SATO other than data triggers?
                        .iter()
                        .filter(|(k, _v)| key.as_ref().map_or(true, |key| **key == **k))
                        .for_each(|(k, v)| {
                            let id = Rc::new(k.clone());
                            // let admin_signatory = Rc::new(v.authority.signatory.clone());
                            // let admin_domain = Rc::new(v.authority.domain.clone());
                            let k0 = NodeKey::Trigger(Some(id.clone()));
                            let v0 = {
                                let receptor = v.filter.clone().into();
                                let executable = match v.executable() {
                                    ExecutableRef::Wasm(hash) => {
                                        state::tr::TriggerExecutable::Dynamic((*hash).into())
                                    }
                                    ExecutableRef::Instructions(instructions) => {
                                        let changeset = (
                                            v.authority.clone(),
                                            instructions.clone().into_vec(),
                                        )
                                            .try_into()
                                            .expect("instructions that are already registered as an executable should be converted into a changeset");
                                        state::tr::TriggerExecutable::Static(changeset)
                                    }
                                };
                                NodeValue::Trigger(state::tr::TriggerValue::new(
                                    receptor, executable, v.repeats,
                                ))
                            };
                            res.insert(k0, v0);
                            // let k1 = NodeKey::AccountTrigger((Some(admin_signatory), Some(admin_domain), Some(id.clone())));
                            // let v1 = NodeValue::AccountTrigger(());
                            // res.insert(k1, v1);
                        })
                }
                _ => unimplemented!("no use for now"),
            }
        }
        res
    }
}
