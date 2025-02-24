use std::collections::HashSet;

use super::*;

pub type Receptor = Tree<WriteStatusFilter>;

pub type ReceptorRef<'a> = TreeRef<'a, WriteStatusFilter>;

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
    type Command = FilterU8;
    type Trigger = FilterU8;
    type Executable = FilterU8;
    type Metadata = FilterU8;
}

impl PartialOrd for Receptor {
    /// Returns early with a simplified conclusion.
    /// Note that `self` and `other` are asymmetric.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        for (key, signal) in self.iter() {
            let signal: FilterU8 = signal.into();
            let receptor_keys = key.receptor_keys();
            let Some(receptor_union) = other
                .iter()
                .filter_map(|(k, v)| receptor_keys.contains(k).then_some(v).map(FilterU8::from))
                .reduce(|acc, x| acc + x)
            else {
                return Some(Ordering::Greater);
            };
            match signal.partial_cmp(&receptor_union) {
                None | Some(Ordering::Greater) => return Some(Ordering::Greater),
                Some(Ordering::Equal | Ordering::Less) => continue,
            }
        }
        Some(Ordering::Less)
    }
}

impl NodeKey {
    fn receptor_keys(&self) -> HashSet<&NodeKey> {
        todo!()
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
