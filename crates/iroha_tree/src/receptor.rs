use std::collections::HashSet;

use super::*;

pub type Receptor = Tree<ReadWriteStatusFilter>;

#[derive(Debug, PartialEq, Eq)]
pub struct ReadWriteStatusFilter;

impl Mode for ReadWriteStatusFilter {
    type Authorizer = FilterU8;
    type Parameter = FilterU8;
    type Peer = FilterU8;
    type Domain = FilterU8;
    type Account = FilterU8;
    type Asset = FilterU8;
    type Nft = FilterU8;
    type AccountAsset = FilterU8;
    type Role = FilterU8;
    type Permission = FilterU8;
    type AccountRole = FilterU8;
    type AccountPermission = FilterU8;
    type RolePermission = FilterU8;
    type Trigger = FilterU8;
    type AccountTrigger = FilterU8;
    type Executable = FilterU8;
    type DomainMetadata = FilterU8;
    type AccountMetadata = FilterU8;
    type AssetMetadata = FilterU8;
    type NftData = FilterU8;
    type TriggerMetadata = FilterU8;
}

impl Filtered for event::Event {
    type Filter = Receptor;

    fn passes(&self, filter: &Self::Filter) -> Result<(), Self::Filter> {
        let mut obstacle = Tree::default();
        for (key, signal) in self.iter() {
            let signal: FilterU8 = signal.into();
            let receptor_keys = key.receptor_keys();
            let receptor_union = filter
                .iter()
                .filter_map(|(k, v)| receptor_keys.contains(k).then_some(v).map(FilterU8::from))
                .fold(FilterU8::DENY, |acc, x| acc | x);
            if let Err(obs) = signal.passes(&receptor_union) {
                obstacle.insert(key.clone(), NodeValue::from((key, obs)));
            }
        }
        if obstacle.is_empty() {
            Ok(())
        } else {
            Err(obstacle)
        }
    }
}

macro_rules! receptor_keys {
    (0 $node:ident) => {
        [$node(())].into()
    };
    (1 $node:ident, $key:expr) => {
        match $key {
            Some(k) => [$node(Some(k.clone())), $node(None)].into(),
            _ => unreachable!(),
        }
    };
    (2 $node:ident, $key:expr) => {
        match $key {
            (Some(k0), Some(k1)) => [
                $node((Some(k0.clone()), Some(k1.clone()))),
                $node((Some(k0.clone()), None)),
                $node((None, Some(k1.clone()))),
                $node((None, None)),
            ]
            .into(),
            _ => unreachable!(),
        }
    };
    (3 $node:ident, $key:expr) => {
        match $key {
            (Some(k0), Some(k1), Some(k2)) => [
                $node((Some(k0.clone()), Some(k1.clone()), Some(k2.clone()))),
                $node((Some(k0.clone()), Some(k1.clone()), None)),
                $node((Some(k0.clone()), None, Some(k2.clone()))),
                $node((Some(k0.clone()), None, None)),
                $node((None, Some(k1.clone()), Some(k2.clone()))),
                $node((None, Some(k1.clone()), None)),
                $node((None, None, Some(k2.clone()))),
                $node((None, None, None)),
            ]
            .into(),
            _ => unreachable!(),
        }
    };
    (4 $node:ident, $key:expr) => {
        match $key {
            (Some(k0), Some(k1), Some(k2), Some(k3)) => [
                $node((
                    Some(k0.clone()),
                    Some(k1.clone()),
                    Some(k2.clone()),
                    Some(k3.clone()),
                )),
                $node((Some(k0.clone()), Some(k1.clone()), Some(k2.clone()), None)),
                $node((Some(k0.clone()), Some(k1.clone()), None, Some(k3.clone()))),
                $node((Some(k0.clone()), Some(k1.clone()), None, None)),
                $node((Some(k0.clone()), None, Some(k2.clone()), Some(k3.clone()))),
                $node((Some(k0.clone()), None, Some(k2.clone()), None)),
                $node((Some(k0.clone()), None, None, Some(k3.clone()))),
                $node((Some(k0.clone()), None, None, None)),
                $node((None, Some(k1.clone()), Some(k2.clone()), Some(k3.clone()))),
                $node((None, Some(k1.clone()), Some(k2.clone()), None)),
                $node((None, Some(k1.clone()), None, Some(k3.clone()))),
                $node((None, Some(k1.clone()), None, None)),
                $node((None, None, Some(k2.clone()), Some(k3.clone()))),
                $node((None, None, Some(k2.clone()), None)),
                $node((None, None, None, Some(k3.clone()))),
                $node((None, None, None, None)),
            ]
            .into(),
            _ => unreachable!(),
        }
    };
}

impl NodeKey {
    fn receptor_keys(&self) -> HashSet<NodeKey> {
        use NodeKey::*;
        match self {
            Authorizer(()) => receptor_keys!(0 Authorizer),
            Parameter(key) => receptor_keys!(1 Parameter, key),
            Peer(key) => receptor_keys!(1 Peer, key),
            Domain(key) => receptor_keys!(1 Domain, key),
            Account(key) => receptor_keys!(2 Account, key),
            Asset(key) => receptor_keys!(2 Asset, key),
            Nft(key) => receptor_keys!(2 Nft, key),
            AccountAsset(key) => receptor_keys!(4 AccountAsset, key),
            Role(key) => receptor_keys!(1 Role, key),
            Permission(key) => receptor_keys!(1 Permission, key),
            AccountRole(key) => receptor_keys!(3 AccountRole, key),
            AccountPermission(key) => receptor_keys!(3 AccountPermission, key),
            RolePermission(key) => receptor_keys!(2 RolePermission, key),
            Trigger(key) => receptor_keys!(1 Trigger, key),
            AccountTrigger(key) => receptor_keys!(3 AccountTrigger, key),
            Executable(key) => receptor_keys!(1 Executable, key),
            DomainMetadata(key) => receptor_keys!(2 DomainMetadata, key),
            AccountMetadata(key) => receptor_keys!(3 AccountMetadata, key),
            AssetMetadata(key) => receptor_keys!(3 AssetMetadata, key),
            NftData(key) => receptor_keys!(3 NftData, key),
            TriggerMetadata(key) => receptor_keys!(2 TriggerMetadata, key),
        }
    }
}

mod transitional {
    use super::*;
    use crate::event::*;

    impl From<dm::EventFilterBox> for Receptor {
        fn from(value: dm::EventFilterBox) -> Self {
            use dm::EventFilterBox;
            match value {
                EventFilterBox::Data(filter) => filter.into(),
                EventFilterBox::Pipeline(_) | EventFilterBox::Time(_) => {
                    todo!("extend receptors to accommodate pipeline and time events?")
                }
                _ => {
                    unimplemented!("other event types should be deprecated")
                }
            }
        }
    }

    macro_rules! node_key_filter {
        (_ $node:ident, $key:expr, $status:expr) => {
            (NodeKey::$node($key), NodeValue::<ReadWriteStatusFilter>::$node($status.into()))
        };
        ($node:ident, $status:expr) => {
            node_key_filter!(_ $node, (), $status)
        };
        ($node:ident, $k0:expr, $status:expr) => {
            node_key_filter!(_ $node, $k0, $status)
        };
        ($node:ident, $k0:expr, $k1:expr, $status:expr) => {
            node_key_filter!(_ $node, ($k0, $k1), $status)
        };
        ($node:ident, $k0:expr, $k1:expr, $k2:expr, $status:expr) => {
            node_key_filter!(_ $node, ($k0, $k1, $k2), $status)
        };
        ($node:ident, $k0:expr, $k1:expr, $k2:expr, $k3:expr, $status:expr) => {
            node_key_filter!(_ $node, ($k0, $k1, $k2, $k3), $status)
        };
    }

    impl From<dm::DataEventFilter> for Receptor {
        #[expect(clippy::too_many_lines)]
        fn from(value: dm::DataEventFilter) -> Self {
            use dm::{
                AccountEventSet, AssetDefinitionEventSet, ConfigurationEventSet,
                DataEventFilter::*, DomainEventSet, ExecutorEventSet, NftEventSet, PeerEventSet,
                RoleEventSet, TriggerEventSet,
            };

            let map: HashMap<_, _> = match value {
                Any => [
                    node_key_filter!(Authorizer, FilterU8::ANY),
                    node_key_filter!(Parameter, None, FilterU8::ANY),
                    node_key_filter!(Peer, None, FilterU8::ANY),
                    node_key_filter!(Domain, None, FilterU8::ANY),
                    node_key_filter!(Account, None, None, FilterU8::ANY),
                    node_key_filter!(Asset, None, None, FilterU8::ANY),
                    node_key_filter!(Nft, None, None, FilterU8::ANY),
                    node_key_filter!(AccountAsset, None, None, None, None, FilterU8::ANY),
                    node_key_filter!(Role, None, FilterU8::ANY),
                    node_key_filter!(Permission, None, FilterU8::ANY),
                    node_key_filter!(AccountRole, None, None, None, FilterU8::ANY),
                    node_key_filter!(AccountPermission, None, None, None, FilterU8::ANY),
                    node_key_filter!(RolePermission, None, None, FilterU8::ANY),
                    node_key_filter!(Trigger, None, FilterU8::ANY),
                    node_key_filter!(AccountTrigger, None, None, None, FilterU8::ANY),
                    node_key_filter!(Executable, None, FilterU8::ANY),
                    node_key_filter!(DomainMetadata, None, None, FilterU8::ANY),
                    node_key_filter!(AccountMetadata, None, None, None, FilterU8::ANY),
                    node_key_filter!(AssetMetadata, None, None, None, FilterU8::ANY),
                    node_key_filter!(NftData, None, None, None, FilterU8::ANY),
                    node_key_filter!(TriggerMetadata, None, None, FilterU8::ANY),
                ]
                .into(),
                Peer(ef) => {
                    let id = ef.id_matcher.map(Rc::new);
                    ef.event_set
                        .decompose()
                        .into_iter()
                        .map(|es| match es {
                            PeerEventSet::Added => {
                                node_key_filter!(Peer, id.clone(), UnitS::Create)
                            }
                            PeerEventSet::Removed => {
                                node_key_filter!(Peer, id.clone(), UnitS::Delete)
                            }
                            _ => unreachable!(),
                        })
                        .collect()
                }
                Domain(ef) => {
                    let (domain, admin) = ef.id_matcher.map_or_else(
                        || (None, None),
                        |id| {
                            (
                                Some(Rc::new(id.clone())),
                                Some(Rc::new(tr::RoleId::DomainAdmin(id))),
                            )
                        },
                    );
                    ef.event_set
                        .decompose()
                        .into_iter()
                        .map(|es| match es {
                            DomainEventSet::Created => {
                                node_key_filter!(Domain, domain.clone(), DomainS::Create)
                            }
                            DomainEventSet::Deleted => {
                                node_key_filter!(Domain, domain.clone(), DomainS::Delete)
                            }
                            DomainEventSet::MetadataInserted => node_key_filter!(
                                DomainMetadata,
                                domain.clone(),
                                None,
                                MetadataS::Set
                            ),
                            DomainEventSet::MetadataRemoved => node_key_filter!(
                                DomainMetadata,
                                domain.clone(),
                                None,
                                MetadataS::Unset
                            ),
                            DomainEventSet::OwnerChanged => node_key_filter!(
                                AccountRole,
                                None,
                                None,
                                admin.clone(),
                                UnitS::Create as u8 | UnitS::Delete as u8
                            ),
                            _ => unreachable!(),
                        })
                        .collect()
                }
                Account(ef) => {
                    let (signatory, domain) = match ef.id_matcher {
                        None => (None, None),
                        Some(id) => (Some(Rc::new(id.signatory)), Some(Rc::new(id.domain))),
                    };
                    ef.event_set
                        .decompose()
                        .into_iter()
                        .map(|es| match es {
                            AccountEventSet::Created => node_key_filter!(
                                Account,
                                signatory.clone(),
                                domain.clone(),
                                UnitS::Create
                            ),
                            AccountEventSet::Deleted => node_key_filter!(
                                Account,
                                signatory.clone(),
                                domain.clone(),
                                UnitS::Delete
                            ),
                            AccountEventSet::PermissionAdded => node_key_filter!(
                                AccountPermission,
                                signatory.clone(),
                                domain.clone(),
                                None,
                                UnitS::Create
                            ),
                            AccountEventSet::PermissionRemoved => node_key_filter!(
                                AccountPermission,
                                signatory.clone(),
                                domain.clone(),
                                None,
                                UnitS::Delete
                            ),
                            AccountEventSet::RoleGranted => node_key_filter!(
                                AccountRole,
                                signatory.clone(),
                                domain.clone(),
                                None,
                                UnitS::Create
                            ),
                            AccountEventSet::RoleRevoked => node_key_filter!(
                                AccountRole,
                                signatory.clone(),
                                domain.clone(),
                                None,
                                UnitS::Delete
                            ),
                            AccountEventSet::MetadataInserted => node_key_filter!(
                                AccountMetadata,
                                signatory.clone(),
                                domain.clone(),
                                None,
                                MetadataS::Set
                            ),
                            AccountEventSet::MetadataRemoved => node_key_filter!(
                                AccountMetadata,
                                signatory.clone(),
                                domain.clone(),
                                None,
                                MetadataS::Unset
                            ),
                            _ => unreachable!(),
                        })
                        .collect()
                }
                Asset(_ef) => unimplemented!("unless AssetEvent is disambiguated"),
                AssetDefinition(ef) => {
                    let (name, domain, admin) = match ef.id_matcher {
                        None => (None, None, None),
                        Some(id) => (
                            Some(Rc::new(id.name.clone())),
                            Some(Rc::new(id.domain.clone())),
                            Some(Rc::new(tr::RoleId::AssetAdmin(id))),
                        ),
                    };
                    ef.event_set
                        .decompose()
                        .into_iter()
                        .map(|es| match es {
                            AssetDefinitionEventSet::Created => node_key_filter!(
                                Asset,
                                name.clone(),
                                domain.clone(),
                                AssetS::Create
                            ),
                            AssetDefinitionEventSet::Deleted => node_key_filter!(
                                Asset,
                                name.clone(),
                                domain.clone(),
                                AssetS::Delete
                            ),
                            AssetDefinitionEventSet::MetadataInserted => node_key_filter!(
                                AssetMetadata,
                                name.clone(),
                                domain.clone(),
                                None,
                                MetadataS::Set
                            ),
                            AssetDefinitionEventSet::MetadataRemoved => node_key_filter!(
                                AssetMetadata,
                                name.clone(),
                                domain.clone(),
                                None,
                                MetadataS::Unset
                            ),
                            AssetDefinitionEventSet::MintabilityChanged => node_key_filter!(
                                Asset,
                                name.clone(),
                                domain.clone(),
                                AssetS::MintabilityUpdate
                            ),
                            AssetDefinitionEventSet::TotalQuantityChanged => node_key_filter!(
                                AccountAsset,
                                None,
                                None,
                                name.clone(),
                                domain.clone(),
                                AccountAssetS::Mint as u8 | AccountAssetS::Burn as u8
                            ),
                            AssetDefinitionEventSet::OwnerChanged => node_key_filter!(
                                AccountRole,
                                None,
                                None,
                                admin.clone(),
                                UnitS::Create as u8 | UnitS::Delete as u8
                            ),
                            _ => unreachable!(),
                        })
                        .collect()
                }
                Nft(ef) => {
                    let (name, domain, owner) = match ef.id_matcher {
                        None => (None, None, None),
                        Some(id) => (
                            Some(Rc::new(id.name.clone())),
                            Some(Rc::new(id.domain.clone())),
                            Some(Rc::new(tr::RoleId::NftOwner(id))),
                        ),
                    };
                    ef.event_set
                        .decompose()
                        .into_iter()
                        .map(|es| match es {
                            NftEventSet::Created => {
                                node_key_filter!(Nft, name.clone(), domain.clone(), NftS::Create)
                            }
                            NftEventSet::Deleted => {
                                node_key_filter!(Nft, name.clone(), domain.clone(), NftS::Delete)
                            }
                            NftEventSet::MetadataInserted => node_key_filter!(
                                NftData,
                                name.clone(),
                                domain.clone(),
                                None,
                                MetadataS::Set
                            ),
                            NftEventSet::MetadataRemoved => node_key_filter!(
                                NftData,
                                name.clone(),
                                domain.clone(),
                                None,
                                MetadataS::Unset
                            ),
                            NftEventSet::OwnerChanged => node_key_filter!(
                                AccountRole,
                                None,
                                None,
                                owner.clone(),
                                UnitS::Create as u8 | UnitS::Delete as u8
                            ),
                            _ => unreachable!(),
                        })
                        .collect()
                }
                Trigger(ef) => {
                    let id = ef.id_matcher.map(Rc::new);
                    ef.event_set
                        .decompose()
                        .into_iter()
                        .map(|es| match es {
                            TriggerEventSet::Created => {
                                node_key_filter!(Trigger, id.clone(), TriggerS::Create)
                            }
                            TriggerEventSet::Deleted => {
                                node_key_filter!(Trigger, id.clone(), TriggerS::Delete)
                            }
                            TriggerEventSet::Extended => {
                                node_key_filter!(Trigger, id.clone(), TriggerS::Increase)
                            }
                            TriggerEventSet::Shortened => {
                                node_key_filter!(Trigger, id.clone(), TriggerS::Decrease)
                            }
                            TriggerEventSet::MetadataInserted => {
                                node_key_filter!(TriggerMetadata, id.clone(), None, MetadataS::Set)
                            }
                            TriggerEventSet::MetadataRemoved => node_key_filter!(
                                TriggerMetadata,
                                id.clone(),
                                None,
                                MetadataS::Unset
                            ),
                            _ => unreachable!(),
                        })
                        .collect()
                }
                Role(ef) => {
                    let id = ef.id_matcher.map(|id| Rc::new(tr::RoleId::Named(id.name)));
                    ef.event_set
                        .decompose()
                        .into_iter()
                        .map(|es| match es {
                            RoleEventSet::Created => {
                                node_key_filter!(Role, id.clone(), UnitS::Create)
                            }
                            RoleEventSet::Deleted => {
                                node_key_filter!(Role, id.clone(), UnitS::Delete)
                            }
                            RoleEventSet::PermissionAdded => {
                                node_key_filter!(RolePermission, id.clone(), None, UnitS::Create)
                            }
                            RoleEventSet::PermissionRemoved => {
                                node_key_filter!(RolePermission, id.clone(), None, UnitS::Delete)
                            }
                            _ => unreachable!(),
                        })
                        .collect()
                }
                Configuration(ef) => ef
                    .event_set
                    .decompose()
                    .into_iter()
                    .map(|es| match es {
                        ConfigurationEventSet::Changed => {
                            node_key_filter!(Parameter, None, ParameterS::Set)
                        }
                        _ => unreachable!(),
                    })
                    .collect(),
                Executor(ef) => ef
                    .event_set
                    .decompose()
                    .into_iter()
                    .map(|es| match es {
                        ExecutorEventSet::Upgraded => {
                            node_key_filter!(Authorizer, AuthorizerS::Set)
                        }
                        _ => unreachable!(),
                    })
                    .collect(),
            };

            map.into_iter().collect()
        }
    }
}
