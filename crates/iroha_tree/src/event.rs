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
    type Command = CommandS;
    type Trigger = TriggerS;
    type Executable = ExecutableS;
    type Metadata = MetadataS;
}

/// SATO move ownerships to roles and replace Transfer with AssetSpecChange (for mint-ability)
/// An expansion of the CRUD status of the target node.
///
/// - Delete: removing something, either allowing repetition (Unset) or not (Delete)
/// - Create: creating something, either allowing repetition (Set) or not (Create)
/// - Burn or Decrease: reducing something, breaking total balance
/// - Mint or Increase: adding something, breaking total balance
/// - Transfer: changing ownerships
/// - Out, effectively Send: reducing something without breaking total balance
/// - In, effectively Receive: adding something without breaking total balance
/// - Read: reading something without modifying it
const STATUS_CHARS: [char; 8] = ['d', 'c', 'b', 'm', 't', 'o', 'i', 'r'];

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
    (t) => {
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
    Transfer = u8_status!(t),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum AssetS {
    Read = u8_status!(r),
    Transfer = u8_status!(t),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum NftS {
    Read = u8_status!(r),
    Transfer = u8_status!(t),
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
pub enum CommandS {
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

impl Filtered for Event {
    type Filter = receptor::Receptor;

    fn as_filter(&self) -> Self::Filter {
        self.iter()
            .map(|(k, write_status)| (k.clone(), write_status.into()))
            .collect()
    }
}

macro_rules! impl_from_write_filtered {
    ($(($ty:ty, $write:ident: $($variant:ident)|+),)+) => {
        $(
        use changeset::$write;

        impl From<&$write> for $ty {
            fn from(value: &$write) -> Self {
                match value {
                    $(
                    $write::$variant(_) => Self::$variant,
                    )+
                }
            }
        }

        impl Filtered for $ty {
            type Filter = FilterU8;

            fn as_filter(&self) -> Self::Filter {
                ((*self) as u8).into()
            }
        }
        )+
    };
}

impl_from_write_filtered!(
    (AuthorizerS, AuthorizerW: Set),
    (UnitS, UnitW: Create | Delete),
    (ParameterS, ParameterW: Set | Unset),
    (DomainS, DomainW: Transfer | Create | Delete),
    (AssetS, AssetW: Transfer | Create | Delete),
    (NftS, NftW: Transfer | Create | Delete),
    (AccountAssetS, AccountAssetW: Receive | Send | Mint | Burn),
    (PermissionS, PermissionW: Set | Unset),
    (CommandS, CommandW: Set | Unset),
    (TriggerS, TriggerW: Increase | Decrease | Create | Delete),
    (ExecutableS, ExecutableW: Set | Unset),
    (MetadataS, MetadataW: Set | Unset),
);

mod transitional {
    use super::*;

    #[expect(unused_macro_rules)] // TODO Remove this line when rule #5 is applied to `NodeKey::AccountAsset`.
    macro_rules! node_key_status {
        (_ $node:ident, $key:expr, $value:expr) => {
            (NodeKey::$node($key), NodeValue::$node($value))
        };
        ($node:ident, $k0:expr, $value:expr) => {
            node_key_status!(_ $node, Some($k0), $value)
        };
        ($node:ident, $k0:expr, $k1:expr, $value:expr) => {
            node_key_status!(_ $node, (Some($k0), Some($k1)), $value)
        };
        ($node:ident, $k0:expr, $k1:expr, $k2:expr, $value:expr) => {
            node_key_status!(_ $node, ((Some($k0), Some($k1)), Some($k2)), $value)
        };
        ($node:ident, $k0:expr, $k1:expr, $k2:expr, $k3:expr, $value:expr) => {
            node_key_status!(_ $node, ((Some($k0), Some($k1)), (Some($k2), Some($k3))), $value)
        };
    }

    impl From<dm::DataEvent> for Event {
        // Other information besides the identifier is abstracted into a status code, but that should be fine since events should be lightweight. Retrieving details should be the role of queries.
        // TODO Remove unreachable match arms required by #[non_exhaustive] attributes.
        fn from(value: dm::DataEvent) -> Self {
            use dm::{
                AccountEvent, AssetDefinitionEvent, AssetEvent, ConfigurationEvent, DataEvent::*,
                DomainEvent, ExecutorEvent, PeerEvent, RoleEvent, TriggerEvent,
            };

            let map: HashMap<_, _> = match value {
                Peer(event) => match event {
                    PeerEvent::Added(k) => [node_key_status!(Peer, k, UnitS::Create)].into(),
                    PeerEvent::Removed(k) => [node_key_status!(Peer, k, UnitS::Delete)].into(),
                    _ => unreachable!(),
                },
                Domain(event) => match event {
                    DomainEvent::Created(v) => [node_key_status!(Domain, v.id, DomainS::Create)].into(),
                    DomainEvent::Deleted(k) => [node_key_status!(Domain, k, DomainS::Delete)].into(),
                    DomainEvent::AssetDefinition(event) => match event {
                        AssetDefinitionEvent::Created(_v) => unimplemented!("ambiguous sources: FT/NFT Register<AssetDefinition>"),
                        AssetDefinitionEvent::Deleted(_k) => unimplemented!("ambiguous sources: FT/NFT Unregister<AssetDefinition>"),
                        AssetDefinitionEvent::MetadataInserted(m) => [node_key_status!(AssetMetadata, m.target.name, m.target.domain, m.key, MetadataS::Set)].into(),
                        AssetDefinitionEvent::MetadataRemoved(m) => [node_key_status!(AssetMetadata, m.target.name, m.target.domain, m.key, MetadataS::Unset)].into(),
                        // SATO MintabilityChanged
                        // AssetDefinitionEvent::MintabilityChanged(k) => [node_key_status!(Asset, k, AssetS::Update)].into(),
                        // SATO TotalQuantityChanged
                        // AssetDefinitionEvent::TotalQuantityChanged(v) => [node_key_status!(Asset, v.asset_definition.name, v.asset_definition.domain, AssetS::Mint | AssetS::Burn)].into(),
                        AssetDefinitionEvent::OwnerChanged(_v) => unimplemented!("ambiguous sources: FT/NFT Transfer<Account, AssetDefinitionId, Account>"),
                        _ => unreachable!(),
                    },
                    DomainEvent::Account(event) => match event {
                        AccountEvent::Created(v) => [node_key_status!(Account, v.id.signatory, v.id.domain, UnitS::Create)].into(),
                        AccountEvent::Deleted(k) => [node_key_status!(Account, k.signatory, k.domain, UnitS::Delete)].into(),
                        AccountEvent::Asset(event) => match event {
                            // This section highlights one of the reasons why the current asset and event structures should be reorganized.
                            AssetEvent::Created(_v) => unimplemented!("ambiguous sources: Transfer<Asset, Metadata, Account>, SetKeyValue<Asset>, Register<Asset>, Mint<Numeric, Asset>, Transfer<Asset, Numeric, Account>"),
                            AssetEvent::Deleted(_k) => unimplemented!("ambiguous sources: Transfer<Asset, Metadata, Account>, Unregister<AssetDefinition>"),
                            AssetEvent::Added(_v) => unimplemented!("ambiguous sources: Transfer<Asset, Numeric, Account>, Mint<Numeric, Asset>"),
                            AssetEvent::Removed(_v) => unimplemented!("ambiguous sources: Transfer<Asset, Numeric, Account>, Burn<Numeric, Asset>, Unregister<Asset>"),
                            AssetEvent::MetadataInserted(m) => [node_key_status!(NftData, m.target.definition.name, m.target.definition.domain, m.key, MetadataS::Set)].into(),
                            AssetEvent::MetadataRemoved(m) => [node_key_status!(NftData, m.target.definition.name, m.target.definition.domain, m.key, MetadataS::Unset)].into(),
                            _ => unreachable!(),
                        },
                        AccountEvent::PermissionAdded(v) => [node_key_status!(AccountPermission, v.account.signatory, v.account.domain, v.permission.name, UnitS::Create)].into(),
                        AccountEvent::PermissionRemoved(v) => [node_key_status!(AccountPermission, v.account.signatory, v.account.domain, v.permission.name, UnitS::Delete)].into(),
                        AccountEvent::RoleGranted(v) => [node_key_status!(AccountRole, v.account.signatory, v.account.domain, v.role, UnitS::Create)].into(),
                        AccountEvent::RoleRevoked(v) => [node_key_status!(AccountRole, v.account.signatory, v.account.domain, v.role, UnitS::Delete)].into(),
                        AccountEvent::MetadataInserted(m) => [node_key_status!(AccountMetadata, m.target.signatory, m.target.domain, m.key, MetadataS::Set)].into(),
                        AccountEvent::MetadataRemoved(m) => [node_key_status!(AccountMetadata, m.target.signatory, m.target.domain, m.key, MetadataS::Unset)].into(),
                        _ => unreachable!(),
                    },
                    DomainEvent::MetadataInserted(m) => [node_key_status!(DomainMetadata, m.target, m.key, MetadataS::Set)].into(),
                    DomainEvent::MetadataRemoved(m) => [node_key_status!(DomainMetadata, m.target, m.key, MetadataS::Unset)].into(),
                    // SATO OwnerChanged
                    // Ownership is now implemented as roles.
                    DomainEvent::OwnerChanged(_v) => todo!(),
                    _ => unreachable!(),
                },
                Trigger(event) => match event {
                    TriggerEvent::Created(k) => [node_key_status!(Trigger, k, TriggerS::Create)].into(),
                    TriggerEvent::Deleted(k) => [node_key_status!(Trigger, k, TriggerS::Delete)].into(),
                    TriggerEvent::Extended(v) => [node_key_status!(Trigger, v.trigger, TriggerS::Increase)].into(),
                    TriggerEvent::Shortened(v) => [node_key_status!(Trigger, v.trigger, TriggerS::Decrease)].into(),
                    TriggerEvent::MetadataInserted(m) => [node_key_status!(TriggerMetadata, m.target, m.key, MetadataS::Set)].into(),
                    TriggerEvent::MetadataRemoved(m) => [node_key_status!(TriggerMetadata, m.target, m.key, MetadataS::Unset)].into(),
                    _ => unreachable!(),
                },
                Role(event) => match event {
                    RoleEvent::Created(v) => [node_key_status!(Role, v.id, UnitS::Create)].into(),
                    RoleEvent::Deleted(k) => [node_key_status!(Role, k, UnitS::Delete)].into(),
                    RoleEvent::PermissionAdded(v) => [node_key_status!(RolePermission, v.role, v.permission.name, UnitS::Create)].into(),
                    RoleEvent::PermissionRemoved(v) => [node_key_status!(RolePermission, v.role, v.permission.name, UnitS::Delete)].into(),
                    _ => unreachable!(),
                },
                Configuration(event) => match event {
                    ConfigurationEvent::Changed(_v) => [node_key_status!(Parameter, tr::ParameterId::Any, ParameterS::Set)].into(),
                },
                // The executor is planned to be replaced with the authorizer. See the `iroha_authorizer` crate documentation for details.
                Executor(event) => match event {
                    ExecutorEvent::Upgraded(_v) => [(NodeKey::Authorizer, NodeValue::Authorizer(AuthorizerS::Set))].into(),
                    _ => unreachable!(),
                },
            };

            map.into()
        }
    }
}
