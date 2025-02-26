use super::*;

pub type Event = Tree<WriteStatus>;

pub type EventRef<'a> = TreeRef<'a, WriteStatus>;

#[derive(Debug, PartialEq, Eq)]
pub struct WriteStatus;

impl Mode for WriteStatus {
    type Authorizer = AuthorizerWS;
    type Parameter = ParameterWS;
    type Peer = UnitWS;
    type Domain = DomainWS;
    type Account = UnitWS;
    type Asset = AssetWS;
    type Nft = NftWS;
    type AccountAsset = AccountAssetWS;
    type Role = UnitWS;
    type Permission = PermissionWS;
    type AccountRole = UnitWS;
    type AccountPermission = UnitWS;
    type RolePermission = UnitWS;
    type Command = CommandWS;
    type Trigger = TriggerWS;
    type Executable = ExecutableWS;
    type Metadata = MetadataWS;
}

/// - Delete
/// - Create
/// - Burn
/// - Mint
/// - Transfer
/// - Out
/// - In
/// - Read
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
    }; // (r) => { 0b0000_0001 };
}

// TODO impl SerializeDisplay and DeserializeFromStr for *WS

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum AuthorizerWS {
    Set = u8_status!(c),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum UnitWS {
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum ParameterWS {
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum DomainWS {
    Transfer = u8_status!(t),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum AssetWS {
    Transfer = u8_status!(t),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum NftWS {
    Transfer = u8_status!(t),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum AccountAssetWS {
    Receive = u8_status!(i),
    Send = u8_status!(o),
    Mint = u8_status!(m),
    Burn = u8_status!(b),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum PermissionWS {
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum CommandWS {
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum TriggerWS {
    Increase = u8_status!(m),
    Decrease = u8_status!(b),
    Create = u8_status!(c),
    Delete = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum ExecutableWS {
    Set = u8_status!(c),
    Unset = u8_status!(d),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum MetadataWS {
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
    (AuthorizerWS, AuthorizerW: Set),
    (UnitWS, UnitW: Create | Delete),
    (ParameterWS, ParameterW: Set | Unset),
    (DomainWS, DomainW: Transfer | Create | Delete),
    (AssetWS, AssetW: Transfer | Create | Delete),
    (NftWS, NftW: Transfer | Create | Delete),
    (AccountAssetWS, AccountAssetW: Receive | Send | Mint | Burn),
    (PermissionWS, PermissionW: Set | Unset),
    (CommandWS, CommandW: Set | Unset),
    (TriggerWS, TriggerW: Increase | Decrease | Create | Delete),
    (ExecutableWS, ExecutableW: Set | Unset),
    (MetadataWS, MetadataW: Set | Unset),
);

mod transitional {
    use super::*;

    impl From<dm::DataEvent> for Event {
        fn from(_value: dm::DataEvent) -> Self {
            todo!()
        }
    }
}
