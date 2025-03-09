use super::*;

pub type Event = Tree<WriteStatus>;

pub type EventRef<'a> = TreeRef<'a, WriteStatus>;

#[derive(Debug, PartialEq, Eq)]
pub struct WriteStatus;

impl Mode for WriteStatus {
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
    type AccountTrigger = UnitS;
    type Executable = ExecutableS;
    type DomainMetadata = MetadataS;
    type AccountMetadata = MetadataS;
    type AssetMetadata = MetadataS;
    type NftData = MetadataS;
    type TriggerMetadata = MetadataS;
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
const STATUS_CHARS: [char; 8] = ['d', 'c', 'b', 'm', 'u', 'o', 'i', 'r'];

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

// TODO impl SerializeDisplay and DeserializeFromStr for *S

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum AuthorizerS {
    Read = u8_status!(r),
    Set = u8_status!(c),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum UnitS {
    Read = u8_status!(r),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum ParameterS {
    Read = u8_status!(r),
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum DomainS {
    Read = u8_status!(r),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum AssetS {
    Read = u8_status!(r),
    MintabilityUpdate = u8_status!(u),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum NftS {
    Read = u8_status!(r),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum AccountAssetS {
    Read = u8_status!(r),
    Receive = u8_status!(i),
    Send = u8_status!(o),
    Mint = u8_status!(m),
    Burn = u8_status!(b),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum PermissionS {
    Read = u8_status!(r),
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum TriggerS {
    Read = u8_status!(r),
    Increase = u8_status!(m),
    Decrease = u8_status!(b),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum ExecutableS {
    Read = u8_status!(r),
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum MetadataS {
    Read = u8_status!(r),
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

macro_rules! impl_from_write_filtered {
    ($(($ty:ty, $write:ident: $($variant:ident)|+),)+) => {
        $(
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
                FilterU8::from(self).passes(filter)
            }
        }

        impl From<&$ty> for FilterU8 {
            fn from(value: &$ty) -> Self {
                ((*value) as u8).into()
            }
        }
        )+
    };
}

impl_from_write_filtered!(
    (AuthorizerS, AuthorizerW: Set),
    (UnitS, UnitW: Create | Delete),
    (ParameterS, ParameterW: Set | Unset),
    (DomainS, DomainW: Create | Delete),
    (AssetS, AssetW: MintabilityUpdate | Create | Delete),
    (NftS, NftW: Create | Delete),
    (AccountAssetS, AccountAssetW: Receive | Send | Mint | Burn),
    (PermissionS, PermissionW: Set | Unset),
    (TriggerS, TriggerW: Increase | Decrease | Create | Delete),
    (ExecutableS, ExecutableW: Set | Unset),
    (MetadataS, MetadataW: Set | Unset),
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

            let map: HashMap<_, _> = match value {
                Peer(event) => match event {
                    PeerEvent::Added(k) => [node_key_value!(Peer, k, UnitS::Create)].into(),
                    PeerEvent::Removed(k) => [node_key_value!(Peer, k, UnitS::Delete)].into(),
                },
                Domain(event) => match event {
                    DomainEvent::Created(v) => [node_key_value!(Domain, v.id, DomainS::Create)].into(),
                    DomainEvent::Deleted(k) => [node_key_value!(Domain, k, DomainS::Delete)].into(),
                    DomainEvent::AssetDefinition(event) => match event {
                        AssetDefinitionEvent::Created(v) => [node_key_value!(Asset, v.id.name, v.id.domain, AssetS::Create)].into(),
                        AssetDefinitionEvent::Deleted(k) => [node_key_value!(Asset, k.name, k.domain, AssetS::Delete)].into(),
                        AssetDefinitionEvent::MetadataInserted(m) => [node_key_value!(AssetMetadata, m.target.name, m.target.domain, m.key, MetadataS::Set)].into(),
                        AssetDefinitionEvent::MetadataRemoved(m) => [node_key_value!(AssetMetadata, m.target.name, m.target.domain, m.key, MetadataS::Unset)].into(),
                        AssetDefinitionEvent::MintabilityChanged(k) => [node_key_value!(Asset, k.name, k.domain, AssetS::MintabilityUpdate)].into(),
                        AssetDefinitionEvent::TotalQuantityChanged(_v) => unimplemented!("total quantities are a secondary state: listen for minting/burning instead"),
                        // Ownership is now implemented as roles.
                        AssetDefinitionEvent::OwnerChanged(v) => [
                            // Not implemented because there is no such field as `AssetDefinitionOwnerChanged::old_owner`.
                            // node_key_status!(AccountRole, v.old_owner.signatory, v.old_owner.domain, tr::RoleId::AssetAdmin(v.asset_definition), UnitS::Delete),
                            node_key_value!(AccountRole, v.new_owner.signatory, v.new_owner.domain, tr::RoleId::AssetAdmin(v.asset_definition), UnitS::Create),
                        ].into(),
                    },
                    DomainEvent::Nft(event) => match event {
                        NftEvent::Created(v) => [node_key_value!(Nft, v.id.name, v.id.domain, NftS::Create)].into(),
                        NftEvent::Deleted(k) => [node_key_value!(Nft, k.name, k.domain, NftS::Delete)].into(),
                        NftEvent::MetadataInserted(m) => [node_key_value!(NftData, m.target.name, m.target.domain, m.key, MetadataS::Set)].into(),
                        NftEvent::MetadataRemoved(m) => [node_key_value!(NftData, m.target.name, m.target.domain, m.key, MetadataS::Unset)].into(),
                        NftEvent::OwnerChanged(v) => [
                            // Not implemented because there is no such field as `NftOwnerChanged::old_owner`.
                            // node_key_status!(AccountRole, v.old_owner.signatory, v.old_owner.domain, tr::RoleId::NftOwner(v.nft), UnitS::Delete),
                            node_key_value!(AccountRole, v.new_owner.signatory, v.new_owner.domain, tr::RoleId::NftOwner(v.nft), UnitS::Create),
                        ].into(),
                    },
                    DomainEvent::Account(event) => match event {
                        AccountEvent::Created(v) => [node_key_value!(Account, v.id.signatory, v.id.domain, UnitS::Create)].into(),
                        AccountEvent::Deleted(k) => [node_key_value!(Account, k.signatory, k.domain, UnitS::Delete)].into(),
                        AccountEvent::Asset(event) => match event {
                            AssetEvent::Created(_v) => unimplemented!("ambiguous sources: Mint<Numeric, Asset>, Transfer<Asset, Numeric, Account>"),
                            AssetEvent::Deleted(_k) => unimplemented!("ambiguous sources: Unregister<AssetDefinition>"),
                            AssetEvent::Added(_v) => unimplemented!("ambiguous sources: Mint<Numeric, Asset>, Transfer<Asset, Numeric, Account>"),
                            AssetEvent::Removed(_v) => unimplemented!("ambiguous sources: Burn<Numeric, Asset>, Transfer<Asset, Numeric, Account>"),
                        },
                        AccountEvent::PermissionAdded(v) => [node_key_value!(AccountPermission, v.account.signatory, v.account.domain, v.permission.name.into(), UnitS::Create)].into(),
                        AccountEvent::PermissionRemoved(v) => [node_key_value!(AccountPermission, v.account.signatory, v.account.domain, v.permission.name.into(), UnitS::Delete)].into(),
                        AccountEvent::RoleGranted(v) => [node_key_value!(AccountRole, v.account.signatory, v.account.domain, tr::RoleId::Named(v.role.name), UnitS::Create)].into(),
                        AccountEvent::RoleRevoked(v) => [node_key_value!(AccountRole, v.account.signatory, v.account.domain, tr::RoleId::Named(v.role.name), UnitS::Delete)].into(),
                        AccountEvent::MetadataInserted(m) => [node_key_value!(AccountMetadata, m.target.signatory, m.target.domain, m.key, MetadataS::Set)].into(),
                        AccountEvent::MetadataRemoved(m) => [node_key_value!(AccountMetadata, m.target.signatory, m.target.domain, m.key, MetadataS::Unset)].into(),
                    },
                    DomainEvent::MetadataInserted(m) => [node_key_value!(DomainMetadata, m.target, m.key, MetadataS::Set)].into(),
                    DomainEvent::MetadataRemoved(m) => [node_key_value!(DomainMetadata, m.target, m.key, MetadataS::Unset)].into(),
                    DomainEvent::OwnerChanged(v) => [
                        // Not implemented because there is no such field as `DomainOwnerChanged::old_owner`.
                        // node_key_status!(AccountRole, v.old_owner.signatory, v.old_owner.domain, tr::RoleId::DomainAdmin(v.domain), UnitS::Delete),
                        node_key_value!(AccountRole, v.new_owner.signatory, v.new_owner.domain, tr::RoleId::DomainAdmin(v.domain), UnitS::Create),
                    ].into(),
                },
                Trigger(event) => match event {
                    TriggerEvent::Created(k) => [node_key_value!(Trigger, k, TriggerS::Create)].into(),
                    TriggerEvent::Deleted(k) => [node_key_value!(Trigger, k, TriggerS::Delete)].into(),
                    TriggerEvent::Extended(v) => [node_key_value!(Trigger, v.trigger, TriggerS::Increase)].into(),
                    TriggerEvent::Shortened(v) => [node_key_value!(Trigger, v.trigger, TriggerS::Decrease)].into(),
                    TriggerEvent::MetadataInserted(m) => [node_key_value!(TriggerMetadata, m.target, m.key, MetadataS::Set)].into(),
                    TriggerEvent::MetadataRemoved(m) => [node_key_value!(TriggerMetadata, m.target, m.key, MetadataS::Unset)].into(),
                },
                Role(event) => match event {
                    RoleEvent::Created(v) => [node_key_value!(Role, tr::RoleId::Named(v.id.name), UnitS::Create)].into(),
                    RoleEvent::Deleted(k) => [node_key_value!(Role, tr::RoleId::Named(k.name), UnitS::Delete)].into(),
                    RoleEvent::PermissionAdded(v) => [node_key_value!(RolePermission, tr::RoleId::Named(v.role.name), v.permission.name.into(), UnitS::Create)].into(),
                    RoleEvent::PermissionRemoved(v) => [node_key_value!(RolePermission, tr::RoleId::Named(v.role.name), v.permission.name.into(), UnitS::Delete)].into(),
                },
                Configuration(event) => match event {
                    ConfigurationEvent::Changed(_v) => [node_key_value!(Parameter, tr::ParameterId::Any, ParameterS::Set)].into(),
                },
                // The executor is planned to be replaced with the authorizer. See the `iroha_authorizer` crate documentation for details.
                Executor(event) => match event {
                    ExecutorEvent::Upgraded(_v) => [node_key_value!(Authorizer, AuthorizerS::Set)].into(),
                },
            };

            map.into()
        }
    }
}
