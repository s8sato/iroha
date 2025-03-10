use super::*;

pub type ReadSet = Tree<Read>;

#[derive(Debug, PartialEq, Eq)]
pub struct Read;

impl Mode for Read {
    type Authorizer = UnitR;
    type Parameter = UnitR;
    type Peer = UnitR;
    type Domain = UnitR;
    type Account = UnitR;
    type Asset = UnitR;
    type Nft = UnitR;
    type AccountAsset = UnitR;
    type Role = UnitR;
    type Permission = UnitR;
    type AccountRole = UnitR;
    type AccountPermission = UnitR;
    type RolePermission = UnitR;
    type Trigger = UnitR;
    type AccountTrigger = UnitR;
    type Executable = UnitR;
    type DomainMetadata = UnitR;
    type AccountMetadata = UnitR;
    type AssetMetadata = UnitR;
    type NftData = UnitR;
    type TriggerMetadata = UnitR;
}

pub type UnitR = ();

impl NodeReadWrite for ReadSet {
    type Status = event::Event;

    fn as_status(&self) -> Self::Status {
        self.iter()
            .map(|(k, read)| (k.clone(), read.into()))
            .collect()
    }
}

mod transitional {
    use iroha_core::{
        smartcontracts::triggers::{
            set::{ExecutableRef, SetReadOnly},
            specialized::LoadedActionTrait,
        },
        state::WorldReadOnly,
    };
    use mv::storage::StorageReadOnly;

    use super::*;
    use crate::state::transitional::TriggerExecutable;

    impl ReadSet {
        fn load(&self, state: &impl iroha_core::state::StateReadOnly) -> state::PartialState {
            let mut res = Tree::default();
            for (k, _v) in self.iter() {
                match k {
                    NodeKey::Trigger(key) => {
                        state
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
                                            TriggerExecutable::Dynamic((*hash).into())
                                        }
                                        ExecutableRef::Instructions(instructions) => {
                                            let changeset = (
                                                v.authority.clone(),
                                                instructions.clone().into_vec(),
                                            )
                                                .try_into()
                                                .expect("instructions that are already registered as an executable should be converted into a changeset");
                                            TriggerExecutable::Static(changeset)
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
}
