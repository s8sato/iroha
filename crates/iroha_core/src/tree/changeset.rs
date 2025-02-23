use std::ops::Add;

use super::*;

pub type ChangeSet = Tree<Write>;

#[derive(Debug, PartialEq, Eq)]
pub struct Write;

impl Mode for Write {
    // Rank 1
    type Authorizer = ();
    type Parameters = ();
    type Peers = ();
    type Domains = ();
    type Accounts = ();
    type Assets = ();
    type Nfts = ();
    type AccountAssets = ();
    type Roles = ();
    type Permissions = ();
    type AccountRoles = ();
    type AccountPermissions = ();
    type RolePermissions = ();
    type Commands = ();
    type Triggers = ();
    type Executables = ();
    // Rank 2
    type Parameter = ParameterW;
    type Peer = UnitW;
    type Domain = DomainW;
    type Account = UnitW;
    type Asset = AssetW;
    type Nft = NftW;
    type AccountAsset = AccountAssetW;
    type Role = UnitW;
    type Permission = PermissionW;
    type AccountRole = UnitW;
    type AccountPermission = UnitW;
    type RolePermission = UnitW;
    type Command = CommandW;
    type Trigger = TriggerW;
    type Executable = ExecutableW;
    // Rank 3
    type Metadata = MetadataW;
}

macro_rules! impl_node_write {
    ($(($ty:ty, $status:ident),)+) => {
        $(
        impl NodeWrite for $ty {
            type Status = event::$status;

            fn as_status(&self) -> Self::Status {
                self.into()
            }
        }

        impl Filtered for $ty {
            type Filter = super::FilterU8;

            fn as_filter(&self) -> Self::Filter {
                let status = NodeWrite::as_status(self);
                Filtered::as_filter(&status)
            }
        }
        )+
    };
}

impl_node_write!(
    // Rank 1
    (AuthorizerW, AuthorizerWS),
    // Rank 2
    (UnitW, UnitWS),
    (ParameterW, ParameterWS),
    (DomainW, DomainWS),
    (AssetW, AssetWS),
    (NftW, NftWS),
    (AccountAssetW, AccountAssetWS),
    (PermissionW, PermissionWS),
    (CommandW, CommandWS),
    (TriggerW, TriggerWS),
    (ExecutableW, ExecutableWS),
    // Rank 3
    (MetadataW, MetadataWS),
);

#[derive(Debug, PartialEq, Eq)]
pub enum AuthorizerW {
    Set(state::tr::AuthorizerValue),
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnitW {
    Create(()),
    Delete(()),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParameterW {
    Set(state::tr::ParameterValue),
    Unset(dm::CustomParameterId),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DomainW {
    Transfer(dm::AccountId),
    Create(state::tr::DomainValue),
    Delete(()),
}

#[derive(Debug, PartialEq, Eq)]
pub enum AssetW {
    Transfer(dm::AccountId),
    Create(state::tr::AssetValue),
    Delete(()),
}

#[derive(Debug, PartialEq, Eq)]
pub enum NftW {
    Transfer(dm::AccountId),
    Create(state::tr::NftValue),
    Delete(()),
}

#[derive(Debug, PartialEq, Eq)]
pub enum AccountAssetW {
    Receive(dm::Numeric),
    Send(dm::Numeric),
    Mint(dm::Numeric),
    Burn(dm::Numeric),
}

#[derive(Debug, PartialEq, Eq)]
pub enum PermissionW {
    Set(state::tr::PermissionValue),
    Unset(()),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CommandW {
    Set(state::tr::CommandValue),
    Unset(()),
}

#[derive(Debug, PartialEq, Eq)]
pub enum TriggerW {
    Increase(u32),
    Decrease(u32),
    Create(state::tr::TriggerValue),
    Delete(()),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExecutableW {
    Set(state::tr::ExecutableValue),
    Unset(()),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MetadataW {
    Set(state::tr::MetadataValue),
    Unset(()),
}

impl NodeWrite for ChangeSet {
    type Status = event::Event;

    fn as_status(&self) -> Self::Status {
        todo!()
    }
}

impl Filtered for ChangeSet {
    type Filter = permission::Permission;

    fn as_filter(&self) -> Self::Filter {
        todo!()
    }
}

impl Add for ChangeSet {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

mod transitional {
    use super::*;

    type State<'block, 'state> = crate::state::StateTransaction<'block, 'state>;

    impl<'block, 'state> ChangeSet {
        fn apply(
            self,
            _state: &mut State<'block, 'state>,
        ) -> Result<event::Event, InvariantsViolation> {
            todo!()
        }
    }

    struct InvariantsViolation;

    impl Default for ChangeSet {
        fn default() -> Self {
            todo!()
        }
    }

    impl TryFrom<Vec<dm::InstructionBox>> for ChangeSet {
        type Error = (Self, Self);

        fn try_from(value: Vec<dm::InstructionBox>) -> Result<Self, Self::Error> {
            value
                .into_iter()
                .try_fold(Self::default(), |acc, x| acc + Self::from(x))
        }
    }

    impl From<dm::InstructionBox> for ChangeSet {
        fn from(_value: dm::InstructionBox) -> Self {
            todo!()
        }
    }
}
