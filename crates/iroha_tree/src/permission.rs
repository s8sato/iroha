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
        ($mod:ident::$can:ident, $path:ident, |$value:ident| $key:expr, $values:expr) => {
            impl From<xp::$mod::$can> for Permission {
                fn from($value: xp::$mod::$can) -> Self {
                    HashMap::from([(
                        NodeKey::$path($key),
                        NodeValue::$path(
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
        peer::CanManagePeers,
        Peer,
        |_v| None,
        [UnitS::Create, UnitS::Delete]
    );

    impl_into_permission!(
        domain::CanRegisterDomain,
        Domain,
        |_v| None,
        [DomainS::Create]
    );

    impl_into_permission!(
        domain::CanUnregisterDomain,
        Domain,
        |v| Some(v.domain),
        [DomainS::Delete]
    );

    impl_into_permission!(
        domain::CanModifyDomainMetadata,
        DomainMetadata,
        |v| (Some(v.domain), None),
        [MetadataS::Set, MetadataS::Unset]
    );

    impl_into_permission!(
        account::CanRegisterAccount,
        Account,
        |v| (None, Some(v.domain)),
        [UnitS::Create]
    );

    // impl_into_permission!(account::CanUnregisterAccount, Account, |v| (), [S::]);

    // impl_into_permission!(account::CanModifyAccountMetadata, Account, |v| (), [S::]);

    // impl_into_permission!(asset_definition::CanRegisterAssetDefinition, AssetDefinition, |v| (), [S::]);

    // impl_into_permission!(asset_definition::CanUnregisterAssetDefinition, AssetDefinition, |v| (), [S::]);

    // impl_into_permission!(asset_definition::CanModifyAssetDefinitionMetadata, AssetDefinition, |v| (), [S::]);

    // impl_into_permission!(asset::CanRegisterAssetWithDefinition, Asset, |v| (), [S::]);

    // impl_into_permission!(asset::CanUnregisterAssetWithDefinition, Asset, |v| (), [S::]);

    // impl_into_permission!(asset::CanMintAssetWithDefinition, Asset, |v| (), [S::]);

    // impl_into_permission!(asset::CanBurnAssetWithDefinition, Asset, |v| (), [S::]);

    // impl_into_permission!(asset::CanTransferAssetWithDefinition, Asset, |v| (), [S::]);

    // impl_into_permission!(asset::CanRegisterAsset, Asset, |v| (), [S::]);

    // impl_into_permission!(asset::CanUnregisterAsset, Asset, |v| (), [S::]);

    // impl_into_permission!(asset::CanMintAsset, Asset, |v| (), [S::]);

    // impl_into_permission!(asset::CanBurnAsset, Asset, |v| (), [S::]);

    // impl_into_permission!(asset::CanTransferAsset, Asset, |v| (), [S::]);

    // impl_into_permission!(asset::CanModifyAssetMetadata, Asset, |v| (), [S::]);

    // impl_into_permission!(parameter::CanSetParameters, Parameter, |v| (), [S::]);

    // impl_into_permission!(role::CanManageRoles, Role, |v| (), [S::]);

    // impl_into_permission!(trigger::CanRegisterTrigger, Trigger, |v| (), [S::]);

    // impl_into_permission!(trigger::CanExecuteTrigger, Trigger, |v| (), [S::]);

    // impl_into_permission!(trigger::CanUnregisterTrigger, Trigger, |v| (), [S::]);

    // impl_into_permission!(trigger::CanModifyTrigger, Trigger, |v| (), [S::]);

    // impl_into_permission!(trigger::CanModifyTriggerMetadata, Trigger, |v| (), [S::]);

    // impl_into_permission!(executor::CanUpgradeExecutor, Executor, |v| (), [S::]);
}
