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

    impl From<dm::DataEvent> for Event {
        fn from(_value: dm::DataEvent) -> Self {
            todo!()
        }
    }
}
