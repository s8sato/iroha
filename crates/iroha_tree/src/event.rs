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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum AuthorizerWS {
    Set = 0b0000_0010,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum UnitWS {
    Create = 0b0000_0010,
    Delete = 0b0000_0100,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum ParameterWS {
    Set = 0b0000_0010,
    Unset = 0b0000_0100,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum DomainWS {
    Transfer = 0b0000_0010,
    Create = 0b0000_0100,
    Delete = 0b0000_1000,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum AssetWS {
    Transfer = 0b0000_0010,
    Create = 0b0000_0100,
    Delete = 0b0000_1000,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum NftWS {
    Transfer = 0b0000_0010,
    Create = 0b0000_0100,
    Delete = 0b0000_1000,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum AccountAssetWS {
    Receive = 0b0000_0010,
    Send = 0b0000_0100,
    Mint = 0b0000_1000,
    Burn = 0b0001_0000,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum PermissionWS {
    Set = 0b0000_0010,
    Unset = 0b0000_0100,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum CommandWS {
    Set = 0b0000_0010,
    Unset = 0b0000_0100,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum TriggerWS {
    Increase = 0b0000_0010,
    Decrease = 0b0000_0100,
    Create = 0b0000_1000,
    Delete = 0b0001_0000,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum ExecutableWS {
    Set = 0b0000_0010,
    Unset = 0b0000_0100,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum MetadataWS {
    Set = 0b0000_0010,
    Unset = 0b0000_0100,
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
