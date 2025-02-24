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
    fn partial_cmp(&self, _other: &Self) -> Option<Ordering> {
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
