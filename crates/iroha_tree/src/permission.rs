use super::*;

pub type Permission = Tree<ReadWriteStatusFilter>;

pub type PermissionRef<'a> = TreeRef<'a, ReadWriteStatusFilter>;

pub type ReadWriteStatusFilter = receptor::WriteStatusFilter;

impl Add for Permission {
    type Output = Self;

    fn add(self, mut rhs: Self) -> Self::Output {
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
        |v| Some(v.domain),
        [DomainS::Delete]
    );

    impl_into_permission!(
        xp::domain::CanModifyDomainMetadata,
        DomainMetadata,
        |v| (Some(v.domain), None),
        [MetadataS::Set, MetadataS::Unset]
    );

    impl_into_permission!(
        xp::account::CanRegisterAccount,
        Account,
        |v| (None, Some(v.domain)),
        [UnitS::Create]
    );

    // impl_into_permission!(xp::account::CanUnregisterAccount, Account, |v| (), [S::]);

    // impl_into_permission!(xp::account::CanModifyAccountMetadata, Account, |v| (), [S::]);

    // impl_into_permission!(xp::asset_definition::CanRegisterAssetDefinition, AssetDefinition, |v| (), [S::]);

    // impl_into_permission!(xp::asset_definition::CanUnregisterAssetDefinition, AssetDefinition, |v| (), [S::]);

    // impl_into_permission!(xp::asset_definition::CanModifyAssetDefinitionMetadata, AssetDefinition, |v| (), [S::]);

    // impl_into_permission!(xp::asset::CanRegisterAssetWithDefinition, Asset, |v| (), [S::]);

    // impl_into_permission!(xp::asset::CanUnregisterAssetWithDefinition, Asset, |v| (), [S::]);

    // impl_into_permission!(xp::asset::CanMintAssetWithDefinition, Asset, |v| (), [S::]);

    // impl_into_permission!(xp::asset::CanBurnAssetWithDefinition, Asset, |v| (), [S::]);

    // impl_into_permission!(xp::asset::CanTransferAssetWithDefinition, Asset, |v| (), [S::]);

    // impl_into_permission!(xp::asset::CanRegisterAsset, Asset, |v| (), [S::]);

    // impl_into_permission!(xp::asset::CanUnregisterAsset, Asset, |v| (), [S::]);

    // impl_into_permission!(xp::asset::CanMintAsset, Asset, |v| (), [S::]);

    // impl_into_permission!(xp::asset::CanBurnAsset, Asset, |v| (), [S::]);

    // impl_into_permission!(xp::asset::CanTransferAsset, Asset, |v| (), [S::]);

    // impl_into_permission!(xp::asset::CanModifyAssetMetadata, Asset, |v| (), [S::]);

    // impl_into_permission!(xp::parameter::CanSetParameters, Parameter, |v| (), [S::]);

    // impl_into_permission!(xp::role::CanManageRoles, Role, |v| (), [S::]);

    // impl_into_permission!(xp::trigger::CanRegisterTrigger, Trigger, |v| (), [S::]);

    // impl_into_permission!(xp::trigger::CanExecuteTrigger, Trigger, |v| (), [S::]);

    // impl_into_permission!(xp::trigger::CanUnregisterTrigger, Trigger, |v| (), [S::]);

    // impl_into_permission!(xp::trigger::CanModifyTrigger, Trigger, |v| (), [S::]);

    // impl_into_permission!(xp::trigger::CanModifyTriggerMetadata, Trigger, |v| (), [S::]);

    // impl_into_permission!(xp::executor::CanUpgradeExecutor, Executor, |v| (), [S::]);
}
