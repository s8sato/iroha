use super::*;

pub type ReadSet = FuzzyTree<Read>;

#[derive(Debug, PartialEq, Eq, Decode, Encode)]
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
    type Condition = UnitR;
    type Executable = UnitR;
    type TriggerCondition = UnitR;
    type TriggerExecutable = UnitR;
    type DomainMetadata = UnitR;
    type AccountMetadata = UnitR;
    type AssetMetadata = UnitR;
    type NftData = UnitR;
    type TriggerMetadata = UnitR;
    type DomainAdmin = UnitR;
    type AssetAdmin = UnitR;
    type NftAdmin = UnitR;
    type NftOwner = UnitR;
    type TriggerAdmin = UnitR;
}

#[derive(Debug, PartialEq, Eq, Decode, Encode)]
pub struct UnitR;
