use std::collections::HashSet;

use super::*;

pub type Receptor = Tree<WriteStatusFilter>;

#[derive(Debug, PartialEq, Eq)]
pub struct WriteStatusFilter;

impl Mode for WriteStatusFilter {
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

    impl From<dm::DataEventFilter> for Receptor {
        fn from(_value: dm::DataEventFilter) -> Self {
            todo!()
        }
    }
}
