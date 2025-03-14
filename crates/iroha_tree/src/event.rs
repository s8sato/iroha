#![expect(trivial_numeric_casts)] // Why do Decode and Encode invoke this?

use super::*;

pub type Event = Tree<ReadWriteStatus>;

#[derive(Debug, PartialEq, Eq, Decode, Encode)]
pub struct ReadWriteStatus;

impl Mode for ReadWriteStatus {
    type Authorizer = AuthorizerS;
    type Parameter = ParameterS;
    type Peer = UnitS;
    type Domain = DomainS;
    type Account = UnitS;
    type Asset = AssetS;
    type Nft = NftS;
    type AccountAsset = AccountAssetS;
    type Role = UnitS;
    type Permission = PermissionS;
    type AccountRole = UnitS;
    type AccountPermission = UnitS;
    type RolePermission = UnitS;
    type Trigger = TriggerS;
    type Condition = ConditionS;
    type Executable = ExecutableS;
    type TriggerCondition = UnitS;
    type TriggerExecutable = UnitS;
    type DomainMetadata = MetadataS;
    type AccountMetadata = MetadataS;
    type AssetMetadata = MetadataS;
    type NftData = MetadataS;
    type TriggerMetadata = MetadataS;
    type DomainAdmin = UnitS;
    type AssetAdmin = UnitS;
    type NftAdmin = UnitS;
    type NftOwner = UnitS;
    type TriggerAdmin = UnitS;
}

/// An expansion of the CRUD status of the target node.
///
/// - Delete: removing something, either allowing repetition (Unset) or not (Delete)
/// - Create: creating something, either allowing repetition (Set) or not (Create)
/// - Burn or Decrease: reducing something, breaking total balance
/// - Mint or Increase: adding something, breaking total balance
/// - Update: utility slot for various updates
/// - Out, effectively Send: reducing something without breaking total balance
/// - In, effectively Receive: adding something without breaking total balance
/// - Read: accessing something without modifying it
pub const STATUS_CHARS: [char; 8] = ['d', 'c', 'b', 'm', 'u', 'o', 'i', 'r'];

macro_rules! u8_status {
    (d) => {
        0b1000_0000
    };
    (c) => {
        0b0100_0000
    };
    (b) => {
        0b0010_0000
    };
    (m) => {
        0b0001_0000
    };
    (u) => {
        0b0000_1000
    };
    (o) => {
        0b0000_0100
    };
    (i) => {
        0b0000_0010
    };
    (r) => {
        0b0000_0001
    };
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
#[repr(u8)]
pub enum AuthorizerS {
    Read = u8_status!(r),
    Set = u8_status!(c),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
#[repr(u8)]
pub enum UnitS {
    Read = u8_status!(r),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
#[repr(u8)]
pub enum ParameterS {
    Read = u8_status!(r),
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
#[repr(u8)]
pub enum DomainS {
    Read = u8_status!(r),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
#[repr(u8)]
pub enum AssetS {
    Read = u8_status!(r),
    MintabilityUpdate = u8_status!(u),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
#[repr(u8)]
pub enum NftS {
    Read = u8_status!(r),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
#[repr(u8)]
pub enum AccountAssetS {
    Read = u8_status!(r),
    Receive = u8_status!(i),
    Send = u8_status!(o),
    Mint = u8_status!(m),
    Burn = u8_status!(b),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
#[repr(u8)]
pub enum PermissionS {
    Read = u8_status!(r),
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
#[repr(u8)]
pub enum TriggerS {
    Read = u8_status!(r),
    Increase = u8_status!(m),
    Decrease = u8_status!(b),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
#[repr(u8)]
pub enum ConditionS {
    Read = u8_status!(r),
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
#[repr(u8)]
pub enum ExecutableS {
    Read = u8_status!(r),
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
#[repr(u8)]
pub enum MetadataS {
    Read = u8_status!(r),
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

macro_rules! impl_from_state_write_filtered {
    ($(($ty:ty, $state:ident, $write:ident: $($variant:ident)|+),)+) => {
        $(
        impl From<&state::tr::$state> for $ty {
            fn from(_value: &state::tr::$state) -> Self {
                Self::Read
            }
        }

        impl From<&changeset::$write> for $ty {
            fn from(value: &changeset::$write) -> Self {
                match value {
                    $(
                    changeset::$write::$variant(_) => Self::$variant,
                    )+
                }
            }
        }

        impl Filtered for $ty {
            type Filter = FilterU8;

            fn passes(&self, filter: &Self::Filter) -> Result<(), Self::Filter> {
                FilterU8::from(*self).passes(filter)
            }
        }

        impl From<$ty> for FilterU8 {
            fn from(value: $ty) -> Self {
                (value as u8).into()
            }
        }
        )+
    };
}

impl_from_state_write_filtered!(
    (AuthorizerS, AuthorizerV, AuthorizerW: Set),
    (UnitS, UnitV, UnitW: Create | Delete),
    (ParameterS, ParameterV, ParameterW: Set | Unset),
    (DomainS, DomainV, DomainW: Create | Delete),
    (AssetS, AssetV, AssetW: MintabilityUpdate | Create | Delete),
    (NftS, NftV, NftW: Create | Delete),
    (AccountAssetS, AccountAssetV, AccountAssetW: Receive | Send | Mint | Burn),
    (PermissionS, PermissionV, PermissionW: Set | Unset),
    (TriggerS, TriggerV, TriggerW: Increase | Decrease | Create | Delete),
    (ConditionS, ConditionV, ConditionW: Set | Unset),
    (ExecutableS, ExecutableV, ExecutableW: Set | Unset),
    (MetadataS, MetadataV, MetadataW: Set | Unset),
);

mod transitional {
    use super::*;

    impl From<dm::DataEvent> for Event {
        // Other information besides the identifier is abstracted into a status code, but that should be fine since events should be lightweight. Retrieving details should be the role of queries.
        fn from(value: dm::DataEvent) -> Self {
            use dm::{
                AccountEvent, AssetDefinitionEvent, AssetEvent, ConfigurationEvent, DataEvent::*,
                DomainEvent, ExecutorEvent, NftEvent, PeerEvent, RoleEvent, TriggerEvent,
            };

            let map: BTreeMap<_, _> = match value {
                Peer(event) => match event {
                    PeerEvent::Added(k) => [node!(Peer, k, UnitS::Create)].into(),
                    PeerEvent::Removed(k) => [node!(Peer, k, UnitS::Delete)].into(),
                },
                Domain(event) => match event {
                    DomainEvent::Created(v) => [node!(Domain, v.id, DomainS::Create)].into(),
                    DomainEvent::Deleted(k) => [node!(Domain, k, DomainS::Delete)].into(),
                    DomainEvent::AssetDefinition(event) => match event {
                        AssetDefinitionEvent::Created(v) => [node!(Asset, v.id.name, v.id.domain, AssetS::Create)].into(),
                        AssetDefinitionEvent::Deleted(k) => [node!(Asset, k.name, k.domain, AssetS::Delete)].into(),
                        AssetDefinitionEvent::MetadataInserted(m) => [node!(AssetMetadata, m.target.name, m.target.domain, m.key, MetadataS::Set)].into(),
                        AssetDefinitionEvent::MetadataRemoved(m) => [node!(AssetMetadata, m.target.name, m.target.domain, m.key, MetadataS::Unset)].into(),
                        AssetDefinitionEvent::MintabilityChanged(k) => [node!(Asset, k.name, k.domain, AssetS::MintabilityUpdate)].into(),
                        AssetDefinitionEvent::TotalQuantityChanged(_v) => unimplemented!("total quantities are a secondary state: listen for minting/burning instead"),
                        // Ownership is now implemented as roles.
                        AssetDefinitionEvent::OwnerChanged(v) => [
                            // Not implemented because there is no such field as `AssetDefinitionOwnerChanged::old_owner`.
                            // node_key_value!(AssetAdmin, v.asset_definition.name, v.asset_definition.domain, v.old_owner.signatory, v.old_owner.domain, UnitS::Delete),
                            node!(AssetAdmin, v.asset_definition.name, v.asset_definition.domain, v.new_owner.signatory, v.new_owner.domain, UnitS::Create),
                        ].into(),
                    },
                    DomainEvent::Nft(event) => match event {
                        NftEvent::Created(v) => [node!(Nft, v.id.name, v.id.domain, NftS::Create)].into(),
                        NftEvent::Deleted(k) => [node!(Nft, k.name, k.domain, NftS::Delete)].into(),
                        NftEvent::MetadataInserted(m) => [node!(NftData, m.target.name, m.target.domain, m.key, MetadataS::Set)].into(),
                        NftEvent::MetadataRemoved(m) => [node!(NftData, m.target.name, m.target.domain, m.key, MetadataS::Unset)].into(),
                        NftEvent::OwnerChanged(v) => [
                            // Not implemented because there is no such field as `NftOwnerChanged::old_owner`.
                            // node_key_value!(NftOwner, v.nft.name, v.nft.domain, v.old_owner.signatory, v.old_owner.domain, UnitS::Delete),
                            node!(NftOwner, v.nft.name, v.nft.domain, v.new_owner.signatory, v.new_owner.domain, UnitS::Create),
                        ].into(),
                    },
                    DomainEvent::Account(event) => match event {
                        AccountEvent::Created(v) => [node!(Account, v.id.signatory, v.id.domain, UnitS::Create)].into(),
                        AccountEvent::Deleted(k) => [node!(Account, k.signatory, k.domain, UnitS::Delete)].into(),
                        AccountEvent::Asset(event) => match event {
                            AssetEvent::Created(_v) => unimplemented!("ambiguous sources: Mint<Numeric, Asset>, Transfer<Asset, Numeric, Account>"),
                            AssetEvent::Deleted(_k) => unimplemented!("could be considered burned to zero by Unregister<AssetDefinition>"),
                            AssetEvent::Added(_v) => unimplemented!("ambiguous sources: Mint<Numeric, Asset>, Transfer<Asset, Numeric, Account>"),
                            AssetEvent::Removed(_v) => unimplemented!("ambiguous sources: Burn<Numeric, Asset>, Transfer<Asset, Numeric, Account>"),
                        },
                        AccountEvent::PermissionAdded(v) => [node!(AccountPermission, v.account.signatory, v.account.domain, (&v.permission).into(), UnitS::Create)].into(),
                        AccountEvent::PermissionRemoved(v) => [node!(AccountPermission, v.account.signatory, v.account.domain, (&v.permission).into(), UnitS::Delete)].into(),
                        AccountEvent::RoleGranted(v) => [node!(AccountRole, v.account.signatory, v.account.domain, v.role, UnitS::Create)].into(),
                        AccountEvent::RoleRevoked(v) => [node!(AccountRole, v.account.signatory, v.account.domain, v.role, UnitS::Delete)].into(),
                        AccountEvent::MetadataInserted(m) => [node!(AccountMetadata, m.target.signatory, m.target.domain, m.key, MetadataS::Set)].into(),
                        AccountEvent::MetadataRemoved(m) => [node!(AccountMetadata, m.target.signatory, m.target.domain, m.key, MetadataS::Unset)].into(),
                    },
                    DomainEvent::MetadataInserted(m) => [node!(DomainMetadata, m.target, m.key, MetadataS::Set)].into(),
                    DomainEvent::MetadataRemoved(m) => [node!(DomainMetadata, m.target, m.key, MetadataS::Unset)].into(),
                    DomainEvent::OwnerChanged(v) => [
                        // Not implemented because there is no such field as `DomainOwnerChanged::old_owner`.
                        // node_key_value!(DomainAdmin, v.domain, v.old_owner.signatory, v.old_owner.domain, UnitS::Delete),
                        node!(DomainAdmin, v.domain, v.new_owner.signatory, v.new_owner.domain, UnitS::Create),
                    ].into(),
                },
                Trigger(event) => match event {
                    TriggerEvent::Created(k) => [node!(Trigger, k, TriggerS::Create)].into(),
                    TriggerEvent::Deleted(k) => [node!(Trigger, k, TriggerS::Delete)].into(),
                    TriggerEvent::Extended(v) => [node!(Trigger, v.trigger, TriggerS::Increase)].into(),
                    TriggerEvent::Shortened(v) => [node!(Trigger, v.trigger, TriggerS::Decrease)].into(),
                    TriggerEvent::MetadataInserted(m) => [node!(TriggerMetadata, m.target, m.key, MetadataS::Set)].into(),
                    TriggerEvent::MetadataRemoved(m) => [node!(TriggerMetadata, m.target, m.key, MetadataS::Unset)].into(),
                },
                Role(event) => match event {
                    RoleEvent::Created(v) => [node!(Role, v.id, UnitS::Create)].into(),
                    RoleEvent::Deleted(k) => [node!(Role, k, UnitS::Delete)].into(),
                    RoleEvent::PermissionAdded(v) => [node!(RolePermission, v.role, (&v.permission).into(), UnitS::Create)].into(),
                    RoleEvent::PermissionRemoved(v) => [node!(RolePermission, v.role, (&v.permission).into(), UnitS::Delete)].into(),
                },
                Configuration(event) => match event {
                    ConfigurationEvent::Changed(_v) => [node!(Parameter, tr::ParameterId, ParameterS::Set)].into(),
                },
                // The executor is planned to be replaced with the authorizer. See the `iroha_authorizer` crate documentation for details.
                Executor(event) => match event {
                    ExecutorEvent::Upgraded(_v) => [node!(Authorizer, AuthorizerS::Set)].into(),
                },
            };

            map.into_iter().collect()
        }
    }
}
