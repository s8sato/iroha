use std::ops::Add;

use super::*;

pub type ChangeSet = Tree<Write>;

#[derive(Debug, PartialEq)]
pub struct Write;

impl Mode for Write {
    // Rank 1
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
    type Authorizers = ();
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
    type Authorizer = AuthorizerW;
    // Rank 3
    type Metadata = MetadataW;
}

impl_node_values!(
    // Rank 1
    (Write, Parameters, ParameterW),
    (Write, Peers, UnitW),
    (Write, Domains, DomainW),
    (Write, Accounts, UnitW),
    (Write, Assets, AssetW),
    (Write, Nfts, NftW),
    (Write, AccountAssets, AccountAssetW),
    (Write, Roles, UnitW),
    (Write, Permissions, PermissionW),
    (Write, AccountRoles, UnitW),
    (Write, AccountPermissions, UnitW),
    (Write, RolePermissions, UnitW),
    (Write, Commands, CommandW),
    (Write, Triggers, TriggerW),
    (Write, Executables, ExecutableW),
    (Write, Authorizers, AuthorizerW),
    // Rank 2
    (ParameterW, Parameter, ()),
    (UnitW, Peer, ()),
    (DomainW, Domain, MetadataW),
    (UnitW, Account, MetadataW),
    (AssetW, Asset, MetadataW),
    (NftW, Nft, MetadataW),
    (AccountAssetW, AccountAsset, ()),
    (UnitW, Role, ()),
    (PermissionW, Permission, ()),
    (UnitW, AccountRole, ()),
    (UnitW, AccountPermission, ()),
    (UnitW, RolePermission, ()),
    (CommandW, Command, ()),
    (TriggerW, Trigger, MetadataW),
    (ExecutableW, Executable, ()),
    (AuthorizerW, Authorizer, ()),
    // Rank 3
    (MetadataW, Metadata, ()),
);

macro_rules! impl_node_write {
    ($(($ty:ty, $key:ty, $status:ident),)+) => {
        $(
        impl NodeWrite<$key> for $ty {
            type Status = event::$status;

            fn as_status(&self) -> Self::Status {
                self.into()
            }
        }

        impl Filtered<$key> for $ty {
            type Filter = super::FilterU8;

            fn as_filter(&self) -> Self::Filter {
                let status = NodeWrite::<$key>::as_status(self);
                Filtered::<$key>::as_filter(&status)
            }
        }
        )+
    };
}

impl_node_write!(
    // Rank 2
    (ParameterW, Parameter, ParameterWS),
    (UnitW, Peer, UnitWS),
    (DomainW, Domain, DomainWS),
    (UnitW, Account, UnitWS),
    (AssetW, Asset, AssetWS),
    (NftW, Nft, NftWS),
    (AccountAssetW, AccountAsset, AccountAssetWS),
    (UnitW, Role, UnitWS),
    (PermissionW, Permission, PermissionWS),
    (UnitW, AccountRole, UnitWS),
    (UnitW, AccountPermission, UnitWS),
    (UnitW, RolePermission, UnitWS),
    (CommandW, Command, CommandWS),
    (TriggerW, Trigger, TriggerWS),
    (ExecutableW, Executable, ExecutableWS),
    (AuthorizerW, Authorizer, AuthorizerWS),
    // Rank 3
    (MetadataW, Metadata, MetadataWS),
);

#[derive(Debug, PartialEq)]
pub enum UnitW {
    Create(()),
    Delete(()),
}

#[derive(Debug, PartialEq)]
pub enum ParameterW {
    Set(state::tr::ParameterValue),
    Unset(dm::CustomParameterId),
}

#[derive(Debug, PartialEq)]
pub enum DomainW {
    Transfer(dm::AccountId),
    Create(state::tr::DomainValue),
    Delete(()),
}

#[derive(Debug, PartialEq)]
pub enum AssetW {
    Transfer(dm::AccountId),
    Create(state::tr::AssetValue),
    Delete(()),
}

#[derive(Debug, PartialEq)]
pub enum NftW {
    Transfer(dm::AccountId),
    Create(state::tr::NftValue),
    Delete(()),
}

#[derive(Debug, PartialEq)]
pub enum AccountAssetW {
    Receive(dm::Numeric),
    Send(dm::Numeric),
    Mint(dm::Numeric),
    Burn(dm::Numeric),
}

#[derive(Debug, PartialEq)]
pub enum PermissionW {
    Set(Box<state::tr::PermissionValue>),
    Unset(()),
}

#[derive(Debug, PartialEq)]
pub enum CommandW {
    Set(Box<state::tr::CommandValue>),
    Unset(()),
}

#[derive(Debug, PartialEq)]
pub enum TriggerW {
    Increase(u32),
    Decrease(u32),
    Create(Box<state::tr::TriggerValue>),
    Delete(()),
}

#[derive(Debug, PartialEq)]
pub enum ExecutableW {
    Set(Box<state::tr::ExecutableValue>),
    Unset(()),
}

#[derive(Debug, PartialEq)]
pub enum AuthorizerW {
    Set(state::tr::AuthorizerValue),
    Unset(()),
}

#[derive(Debug, PartialEq)]
pub enum MetadataW {
    Set(state::tr::MetadataValue),
    Unset(()),
}

impl NodeWrite<Root> for ChangeSet {
    type Status = event::Event;

    fn as_status(&self) -> Self::Status {
        todo!()
    }
}

impl Filtered<Root> for ChangeSet {
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
            value.into_iter().fold(Ok(Self::default()), |acc, x| {
                acc.and_then(|changeset| changeset + Self::from(x))
            })
        }
    }

    impl From<dm::InstructionBox> for ChangeSet {
        fn from(_value: dm::InstructionBox) -> Self {
            todo!()
        }
    }
}
