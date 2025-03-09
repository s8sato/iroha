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
    use super::*;

    impl ReadSet {
        fn load(&self, _state: &impl iroha_core::state::StateReadOnly) -> state::PartialState {
            todo!()
        }
    }
}
