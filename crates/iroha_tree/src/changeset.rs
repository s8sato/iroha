use super::*;

pub type ChangeSet = Tree<Write>;

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
    type Trigger = TriggerW;
    type AccountTrigger = UnitW;
    type Executable = ExecutableW;
    type DomainMetadata = MetadataW;
    type AccountMetadata = MetadataW;
    type AssetMetadata = MetadataW;
    type NftData = MetadataW;
    type TriggerMetadata = MetadataW;
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
    Create(state::tr::DomainValue),
    Delete(()),
}

#[derive(Debug, PartialEq, Eq)]
pub enum AssetW {
    MintabilityUpdate(dm::Mintable),
    Create(state::tr::AssetValue),
    Delete(()),
}

#[derive(Debug, PartialEq, Eq)]
pub enum NftW {
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
pub enum TriggerW {
    Increase(u32),
    Decrease(u32),
    Create(state::tr::TriggerValue),
    Delete(()),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExecutableW {
    Set(state::tr::WasmExecutableValue),
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
            type Filter = FilterU8;

            fn passes(&self, filter: &Self::Filter) -> Result<(), Self::Filter> {
                self.as_status().passes(filter)
            }
        }
        )+
    };
}

impl_node_write!(
    (AuthorizerW, AuthorizerS),
    (UnitW, UnitS),
    (ParameterW, ParameterS),
    (DomainW, DomainS),
    (AssetW, AssetS),
    (NftW, NftS),
    (AccountAssetW, AccountAssetS),
    (PermissionW, PermissionS),
    (TriggerW, TriggerS),
    (ExecutableW, ExecutableS),
    (MetadataW, MetadataS),
);

macro_rules! impl_add_err {
    ($($ty:ty,)+) => {
        $(
        impl Add for $ty {
            type Output = Result<Self, (Self, Self)>;

            fn add(self, rhs: Self) -> Self::Output {
                Err((self, rhs))
            }
        }
        )+
    };
}

// Multiple modifications to the same node within a single transaction are generally not allowed.
impl_add_err!(
    AuthorizerW,
    UnitW,
    ParameterW,
    DomainW,
    AssetW,
    NftW,
    PermissionW,
    ExecutableW,
    MetadataW,
);

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

mod transitional {
    use iroha_core::tx;

    use super::*;

    type State<'block, 'state> = iroha_core::state::StateTransaction<'block, 'state>;

    impl<'block, 'state> ChangeSet {
        /// Unordered reflection to state, allowing inconsistencies between nodes.
        fn apply(
            self,
            state: &mut State<'block, 'state>,
        ) -> Result<event::Event, InvariantsViolation> {
            let event = self.as_status();

            #[expect(clippy::never_loop)]
            for (_k, _v) in self.into_iter() {
                unimplemented!(
                    "todo when instructions as an executable were replaced with a changeset"
                )
            }

            event.sanitize(state)?;
            Ok(event)
        }
    }

    impl<'block, 'state> event::Event {
        /// Scan and resolve inconsistencies based on events.
        #[expect(clippy::unused_self)]
        fn sanitize(&self, _state: &mut State<'block, 'state>) -> Result<(), InvariantsViolation> {
            // TODO #4672 Cascade or restrict on delete.
            unimplemented!("todo when instructions as an executable were replaced with a changeset")
        }
    }

    struct InvariantsViolation;

    impl TryFrom<(dm::AccountId, Vec<dm::InstructionBox>)> for ChangeSet {
        type Error = (NodeKey, NodeValue<Write>, NodeValue<Write>);

        fn try_from(
            (auth, instructions): (dm::AccountId, Vec<dm::InstructionBox>),
        ) -> Result<Self, Self::Error> {
            instructions
                .into_iter()
                .try_fold(Self::default(), |acc, x| {
                    acc + (auth.clone(), x).try_into()?
                })
        }
    }

    impl TryFrom<(dm::AccountId, dm::InstructionBox)> for ChangeSet {
        type Error = (NodeKey, NodeValue<Write>, NodeValue<Write>);

        #[expect(clippy::too_many_lines)]
        fn try_from(
            (auth, instruction): (dm::AccountId, dm::InstructionBox),
        ) -> Result<Self, Self::Error> {
            use dm::{
                numeric, BurnBox, EventFilterBox, GrantBox, InstructionBox, MintBox, Numeric,
                RegisterBox, RemoveKeyValueBox, RevokeBox, SetKeyValueBox, TransferBox,
                UnregisterBox,
            };

            let map: HashMap<_, _> = match instruction {
                InstructionBox::Register(inst) => match inst {
                    RegisterBox::Peer(inst) => {
                        [node_key_value!(Peer, inst.object, UnitW::Create(()))].into()
                    }
                    RegisterBox::Domain(inst) => [
                        node_key_value!(
                            AccountRole,
                            auth.signatory,
                            auth.domain,
                            tr::RoleId::DomainAdmin(inst.object.id.clone()),
                            UnitW::Create(())
                        ),
                        node_key_value!(
                            Domain,
                            inst.object.id,
                            DomainW::Create(inst.object.logo.into())
                        ),
                    ]
                    .into(),
                    RegisterBox::Account(inst) => [node_key_value!(
                        Account,
                        inst.object.id.signatory,
                        inst.object.id.domain,
                        UnitW::Create(())
                    )]
                    .into(),
                    RegisterBox::AssetDefinition(inst) => [
                        node_key_value!(
                            AccountRole,
                            auth.signatory,
                            auth.domain,
                            tr::RoleId::AssetAdmin(inst.object.id.clone()),
                            UnitW::Create(())
                        ),
                        node_key_value!(
                            Asset,
                            inst.object.id.name,
                            inst.object.id.domain,
                            AssetW::Create(state::tr::AssetValue::new(
                                numeric!(0),
                                inst.object.mintable,
                                inst.object.logo
                            ))
                        ),
                    ]
                    .into(),
                    RegisterBox::Nft(inst) => [
                        node_key_value!(
                            AccountRole,
                            auth.signatory.clone(),
                            auth.domain.clone(),
                            tr::RoleId::NftAdmin(inst.object.id.clone()),
                            UnitW::Create(())
                        ),
                        node_key_value!(
                            AccountRole,
                            auth.signatory,
                            auth.domain,
                            tr::RoleId::NftOwner(inst.object.id.clone()),
                            UnitW::Create(())
                        ),
                        node_key_value!(
                            Nft,
                            inst.object.id.name.clone(),
                            inst.object.id.domain.clone(),
                            NftW::Create(state::tr::NftValue)
                        ),
                    ]
                    .into_iter()
                    .chain(inst.object.content.iter().map(|(k, v)| {
                        node_key_value!(
                            NftData,
                            inst.object.id.name.clone(),
                            inst.object.id.domain.clone(),
                            k.clone(),
                            MetadataW::Set(v.clone().into())
                        )
                    }))
                    .collect(),
                    RegisterBox::Role(inst) => [node_key_value!(
                        Role,
                        tr::RoleId::Named(inst.object.inner.id.name),
                        UnitW::Create(())
                    )]
                    .into(),
                    RegisterBox::Trigger(inst) => {
                        let mut map = HashMap::new();
                        let receptor: receptor::Receptor = match inst.object.action.filter {
                            EventFilterBox::Data(filter) => filter.into(),
                            EventFilterBox::Time(_filter) => {
                                todo!("extend receptors to accommodate time events?")
                            }
                            _ => {
                                unimplemented!("other event types should not be used for triggers")
                            }
                        };
                        let executable: state::tr::TriggerExecutable =
                            match inst.object.action.executable {
                                tx::Executable::Instructions(instructions) => {
                                    ChangeSet::try_from((auth.clone(), instructions.into_vec()))?
                                        .into()
                                }
                                tx::Executable::Wasm(wasm) => {
                                    let wasm_id: crate::tr::WasmExecutableId =
                                        tx::HashOf::new(&wasm).into();
                                    let (k, v) = node_key_value!(
                                        Executable,
                                        wasm_id.clone(),
                                        ExecutableW::Set(wasm)
                                    );
                                    map.insert(k, v);
                                    wasm_id.into()
                                }
                            };
                        let (k, v) = node_key_value!(
                            Trigger,
                            inst.object.id.clone(),
                            TriggerW::Create(state::tr::TriggerValue::new(
                                receptor,
                                executable,
                                inst.object.action.repeats,
                            ))
                        );
                        map.insert(k, v);
                        let (k, v) = node_key_value!(
                            AccountTrigger,
                            auth.signatory,
                            auth.domain,
                            inst.object.id,
                            UnitW::Create(())
                        );
                        map.insert(k, v);
                        map
                    }
                },
                InstructionBox::Unregister(inst) => match inst {
                    UnregisterBox::Peer(inst) => {
                        [node_key_value!(Peer, inst.object, UnitW::Delete(()))].into()
                    }
                    UnregisterBox::Domain(inst) => {
                        [node_key_value!(Domain, inst.object, DomainW::Delete(()))].into()
                    }
                    UnregisterBox::Account(inst) => [node_key_value!(
                        Account,
                        inst.object.signatory,
                        inst.object.domain,
                        UnitW::Delete(())
                    )]
                    .into(),
                    UnregisterBox::AssetDefinition(inst) => [node_key_value!(
                        Asset,
                        inst.object.name,
                        inst.object.domain,
                        AssetW::Delete(())
                    )]
                    .into(),
                    UnregisterBox::Nft(inst) => [node_key_value!(
                        Nft,
                        inst.object.name,
                        inst.object.domain,
                        NftW::Delete(())
                    )]
                    .into(),
                    UnregisterBox::Role(inst) => [node_key_value!(
                        Role,
                        tr::RoleId::Named(inst.object.name),
                        UnitW::Delete(())
                    )]
                    .into(),
                    UnregisterBox::Trigger(inst) => {
                        [node_key_value!(Trigger, inst.object, TriggerW::Delete(()))].into()
                    }
                },
                InstructionBox::Mint(inst) => match inst {
                    MintBox::Asset(inst) => [node_key_value!(
                        AccountAsset,
                        inst.destination.account.signatory,
                        inst.destination.account.domain,
                        inst.destination.definition.name,
                        inst.destination.definition.domain,
                        AccountAssetW::Mint(inst.object)
                    )]
                    .into(),
                    MintBox::TriggerRepetitions(inst) => [node_key_value!(
                        Trigger,
                        inst.destination,
                        TriggerW::Increase(inst.object)
                    )]
                    .into(),
                },
                InstructionBox::Burn(inst) => match inst {
                    BurnBox::Asset(inst) => [node_key_value!(
                        AccountAsset,
                        inst.destination.account.signatory,
                        inst.destination.account.domain,
                        inst.destination.definition.name,
                        inst.destination.definition.domain,
                        AccountAssetW::Burn(inst.object)
                    )]
                    .into(),
                    BurnBox::TriggerRepetitions(inst) => [node_key_value!(
                        Trigger,
                        inst.destination,
                        TriggerW::Increase(inst.object)
                    )]
                    .into(),
                },
                InstructionBox::Transfer(inst) => match inst {
                    TransferBox::Domain(inst) => [
                        node_key_value!(
                            AccountRole,
                            inst.source.signatory,
                            inst.source.domain,
                            tr::RoleId::DomainAdmin(inst.object.clone()),
                            UnitW::Delete(())
                        ),
                        node_key_value!(
                            AccountRole,
                            inst.destination.signatory,
                            inst.destination.domain,
                            tr::RoleId::DomainAdmin(inst.object),
                            UnitW::Create(())
                        ),
                    ]
                    .into(),
                    TransferBox::AssetDefinition(inst) => [
                        node_key_value!(
                            AccountRole,
                            inst.source.signatory,
                            inst.source.domain,
                            tr::RoleId::AssetAdmin(inst.object.clone()),
                            UnitW::Delete(())
                        ),
                        node_key_value!(
                            AccountRole,
                            inst.destination.signatory,
                            inst.destination.domain,
                            tr::RoleId::AssetAdmin(inst.object),
                            UnitW::Create(())
                        ),
                    ]
                    .into(),
                    TransferBox::Nft(inst) => [
                        node_key_value!(
                            AccountRole,
                            inst.source.signatory,
                            inst.source.domain,
                            tr::RoleId::NftOwner(inst.object.clone()),
                            UnitW::Delete(())
                        ),
                        node_key_value!(
                            AccountRole,
                            inst.destination.signatory,
                            inst.destination.domain,
                            tr::RoleId::NftOwner(inst.object),
                            UnitW::Create(())
                        ),
                    ]
                    .into(),
                    TransferBox::Asset(inst) => [
                        node_key_value!(
                            AccountAsset,
                            inst.source.account.signatory,
                            inst.source.account.domain,
                            inst.source.definition.name.clone(),
                            inst.source.definition.domain.clone(),
                            AccountAssetW::Send(inst.object)
                        ),
                        node_key_value!(
                            AccountAsset,
                            inst.destination.signatory,
                            inst.destination.domain,
                            inst.source.definition.name,
                            inst.source.definition.domain,
                            AccountAssetW::Receive(inst.object)
                        ),
                    ]
                    .into(),
                },
                InstructionBox::SetKeyValue(inst) => match inst {
                    SetKeyValueBox::Domain(inst) => [node_key_value!(
                        DomainMetadata,
                        inst.object,
                        inst.key,
                        MetadataW::Set(inst.value.into())
                    )]
                    .into(),
                    SetKeyValueBox::Account(inst) => [node_key_value!(
                        AccountMetadata,
                        inst.object.signatory,
                        inst.object.domain,
                        inst.key,
                        MetadataW::Set(inst.value.into())
                    )]
                    .into(),
                    SetKeyValueBox::AssetDefinition(inst) => [node_key_value!(
                        AssetMetadata,
                        inst.object.name,
                        inst.object.domain,
                        inst.key,
                        MetadataW::Set(inst.value.into())
                    )]
                    .into(),
                    SetKeyValueBox::Nft(inst) => [node_key_value!(
                        NftData,
                        inst.object.name,
                        inst.object.domain,
                        inst.key,
                        MetadataW::Set(inst.value.into())
                    )]
                    .into(),
                    SetKeyValueBox::Trigger(inst) => [node_key_value!(
                        TriggerMetadata,
                        inst.object,
                        inst.key,
                        MetadataW::Set(inst.value.into())
                    )]
                    .into(),
                },
                InstructionBox::RemoveKeyValue(inst) => match inst {
                    RemoveKeyValueBox::Domain(inst) => [node_key_value!(
                        DomainMetadata,
                        inst.object,
                        inst.key,
                        MetadataW::Unset(())
                    )]
                    .into(),
                    RemoveKeyValueBox::Account(inst) => [node_key_value!(
                        AccountMetadata,
                        inst.object.signatory,
                        inst.object.domain,
                        inst.key,
                        MetadataW::Unset(())
                    )]
                    .into(),
                    RemoveKeyValueBox::AssetDefinition(inst) => [node_key_value!(
                        AssetMetadata,
                        inst.object.name,
                        inst.object.domain,
                        inst.key,
                        MetadataW::Unset(())
                    )]
                    .into(),
                    RemoveKeyValueBox::Nft(inst) => [node_key_value!(
                        NftData,
                        inst.object.name,
                        inst.object.domain,
                        inst.key,
                        MetadataW::Unset(())
                    )]
                    .into(),
                    RemoveKeyValueBox::Trigger(inst) => [node_key_value!(
                        TriggerMetadata,
                        inst.object,
                        inst.key,
                        MetadataW::Unset(())
                    )]
                    .into(),
                },
                InstructionBox::Grant(inst) => match inst {
                    GrantBox::Permission(inst) => [node_key_value!(
                        AccountPermission,
                        inst.destination.signatory,
                        inst.destination.domain,
                        inst.object.name.into(),
                        UnitW::Create(())
                    )]
                    .into(),
                    GrantBox::Role(inst) => [node_key_value!(
                        AccountRole,
                        inst.destination.signatory,
                        inst.destination.domain,
                        tr::RoleId::Named(inst.object.name),
                        UnitW::Create(())
                    )]
                    .into(),
                    GrantBox::RolePermission(inst) => [node_key_value!(
                        RolePermission,
                        tr::RoleId::Named(inst.destination.name),
                        inst.object.name.into(),
                        UnitW::Create(())
                    )]
                    .into(),
                },
                InstructionBox::Revoke(inst) => match inst {
                    RevokeBox::Permission(inst) => [node_key_value!(
                        AccountPermission,
                        inst.destination.signatory,
                        inst.destination.domain,
                        inst.object.name.into(),
                        UnitW::Delete(())
                    )]
                    .into(),
                    RevokeBox::Role(inst) => [node_key_value!(
                        AccountRole,
                        inst.destination.signatory,
                        inst.destination.domain,
                        tr::RoleId::Named(inst.object.name),
                        UnitW::Delete(())
                    )]
                    .into(),
                    RevokeBox::RolePermission(inst) => [node_key_value!(
                        RolePermission,
                        tr::RoleId::Named(inst.destination.name),
                        inst.object.name.into(),
                        UnitW::Delete(())
                    )]
                    .into(),
                },
                InstructionBox::ExecuteTrigger(_inst) => unimplemented!(
                    "planned to be replaced with calls to pre-registered executables"
                ),
                InstructionBox::SetParameter(inst) => [node_key_value!(
                    Parameter,
                    tr::ParameterId::Any,
                    ParameterW::Set(inst.0.into())
                )]
                .into(),
                InstructionBox::Upgrade(_inst) => [node_key_value!(
                    Authorizer,
                    AuthorizerW::Set(state::tr::AuthorizerValue)
                )]
                .into(),
                InstructionBox::Log(inst) => {
                    const TARGET: &str = "log_isi";
                    match inst.level {
                        dm::Level::TRACE => iroha_logger::trace!(target: TARGET, "{}", inst.msg),
                        dm::Level::DEBUG => iroha_logger::debug!(target: TARGET, "{}", inst.msg),
                        dm::Level::INFO => iroha_logger::info!(target: TARGET, "{}", inst.msg),
                        dm::Level::WARN => iroha_logger::warn!(target: TARGET, "{}", inst.msg),
                        dm::Level::ERROR => iroha_logger::error!(target: TARGET, "{}", inst.msg),
                    }
                    [].into()
                }
                InstructionBox::Custom(_inst) => unimplemented!(
                    "planned to be replaced with calls to pre-registered executables"
                ),
            };

            Ok(map.into_iter().collect())
        }
    }
}
