use super::*;

pub type Permission = Tree<ReadWriteStatusFilter>;

pub type PermissionRef<'a> = TreeRef<'a, ReadWriteStatusFilter>;

pub type ReadWriteStatusFilter = receptor::WriteStatusFilter;

impl BitOr for Permission {
    type Output = Self;

    fn bitor(self, mut rhs: Self) -> Self::Output {
        for (k, v0) in self.into_iter() {
            let v = match rhs.remove(&k) {
                None => v0,
                Some(v1) => v0 | v1,
            };
            rhs.insert(k, v);
        }
        rhs
    }
}

mod transitional {
    use event::*;
    use iroha_executor_data_model::permission as xp;

    use super::*;

    macro_rules! impl_into_permission {
        ($can:path, $node:ident, |$source:ident| $key:expr, $values:expr) => {
            impl From<$can> for Permission {
                fn from($source: $can) -> Self {
                    HashMap::from([(
                        NodeKey::$node($key),
                        NodeValue::$node(
                            $values
                                .iter()
                                .map(Filtered::as_filter)
                                .reduce(|acc, x| acc | x)
                                .unwrap(),
                        ),
                    )])
                    .into()
                }
            }
        };
    }

    macro_rules! some {
        ($key_element:expr) => {
            Some(Rc::new($key_element))
        };
    }

    impl_into_permission!(
        xp::peer::CanManagePeers,
        Peer,
        |_v| None,
        [UnitS::Create, UnitS::Delete]
    );

    impl_into_permission!(
        xp::domain::CanRegisterDomain,
        Domain,
        |_v| None,
        [DomainS::Create]
    );

    impl_into_permission!(
        xp::domain::CanUnregisterDomain,
        Domain,
        |v| some!(v.domain),
        [DomainS::Delete]
    );

    impl_into_permission!(
        xp::domain::CanModifyDomainMetadata,
        DomainMetadata,
        |v| (some!(v.domain), None),
        [MetadataS::Set, MetadataS::Unset]
    );

    impl_into_permission!(
        xp::account::CanRegisterAccount,
        Account,
        |v| (None, some!(v.domain)),
        [UnitS::Create]
    );

    // SATO impl for the rest of permissions
}
