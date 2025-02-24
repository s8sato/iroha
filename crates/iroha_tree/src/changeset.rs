use super::*;

pub type ChangeSet = Tree<Write>;

pub type ChangeSetRef<'a> = TreeRef<'a, Write>;

#[derive(Debug, PartialEq, Eq)]
pub struct Write;

impl Mode for Write {
    type Authorizer = AuthorizerW;
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
    type Metadata = MetadataW;
}

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
    Unset(()),
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
        self.iter()
            // SATO remove clone
            .map(|(k, write)| (k.clone(), write.into()))
            .collect()
    }
}

impl Filtered for ChangeSet {
    type Filter = permission::Permission;

    fn as_filter(&self) -> Self::Filter {
        self.iter()
            .map(|(k, write)| (k.clone(), write.into()))
            .collect()
    }
}

impl Add for ChangeSet {
    type Output = Result<Self, (NodeKey, NodeValue<Write>, NodeValue<Write>)>;

    fn add(self, mut rhs: Self) -> Self::Output {
        for (k, v0) in self.into_iter() {
            let v = match rhs.remove(&k) {
                None => v0,
                Some(v1) => match v0 + v1 {
                    Ok(v) => v,
                    Err((v0, v1)) => return Err((k, v0, v1)),
                },
            };
            rhs.insert(k, v);
        }
        Ok(rhs)
    }
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
                self.as_status().as_filter()
            }
        }
        )+
    };
}

impl_node_write!(
    (AuthorizerW, AuthorizerWS),
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
    (MetadataW, MetadataWS),
);

impl Add for AuthorizerW {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, rhs: Self) -> Self::Output {
        Ok(rhs)
    }
}

impl Add for UnitW {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, rhs: Self) -> Self::Output {
        Err((self, rhs))
    }
}

impl Add for ParameterW {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, rhs: Self) -> Self::Output {
        Ok(rhs)
    }
}

impl Add for DomainW {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, rhs: Self) -> Self::Output {
        Err((self, rhs))
    }
}

impl Add for AssetW {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, rhs: Self) -> Self::Output {
        Err((self, rhs))
    }
}

impl Add for NftW {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, rhs: Self) -> Self::Output {
        Err((self, rhs))
    }
}

impl Add for AccountAssetW {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, rhs: Self) -> Self::Output {
        let add = match (self, rhs) {
            (Self::Receive(l), Self::Receive(r)) => match l.checked_add(r) {
                Some(add) => Self::Receive(add),
                _ => return Err((Self::Receive(l), Self::Receive(r))),
            },
            (Self::Send(l), Self::Send(r)) => match l.checked_add(r) {
                Some(add) => Self::Send(add),
                _ => return Err((Self::Send(l), Self::Send(r))),
            },
            (Self::Mint(l), Self::Mint(r)) => match l.checked_add(r) {
                Some(add) => Self::Mint(add),
                _ => return Err((Self::Mint(l), Self::Mint(r))),
            },
            (Self::Burn(l), Self::Burn(r)) => match l.checked_add(r) {
                Some(add) => Self::Burn(add),
                _ => return Err((Self::Burn(l), Self::Burn(r))),
            },
            (l, r) => return Err((l, r)),
        };
        Ok(add)
    }
}

impl Add for PermissionW {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, rhs: Self) -> Self::Output {
        Ok(rhs)
    }
}

impl Add for CommandW {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, rhs: Self) -> Self::Output {
        Ok(rhs)
    }
}

impl Add for TriggerW {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, rhs: Self) -> Self::Output {
        let add = match (self, rhs) {
            (Self::Increase(l), Self::Increase(r)) => match l.checked_add(r) {
                Some(add) => Self::Increase(add),
                _ => return Err((Self::Increase(l), Self::Increase(r))),
            },
            (Self::Decrease(l), Self::Decrease(r)) => match l.checked_add(r) {
                Some(add) => Self::Decrease(add),
                _ => return Err((Self::Decrease(l), Self::Decrease(r))),
            },
            (l, r) => return Err((l, r)),
        };
        Ok(add)
    }
}

impl Add for ExecutableW {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, rhs: Self) -> Self::Output {
        Ok(rhs)
    }
}

impl Add for MetadataW {
    type Output = Result<Self, (Self, Self)>;

    fn add(self, rhs: Self) -> Self::Output {
        Ok(rhs)
    }
}

mod transitional {
    use super::*;

    type State<'block, 'state> = iroha_core::state::StateTransaction<'block, 'state>;

    impl<'block, 'state> ChangeSet {
        fn apply(
            self,
            _state: &mut State<'block, 'state>,
        ) -> Result<event::Event, InvariantsViolation> {
            todo!()
        }
    }

    struct InvariantsViolation;

    impl TryFrom<Vec<dm::InstructionBox>> for ChangeSet {
        type Error = (NodeKey, NodeValue<Write>, NodeValue<Write>);

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
