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
                Some(v1) => v0 + v1,
            };
            rhs.insert(k, v);
        }
        rhs
    }
}

mod transitional {
    use iroha_executor_data_model::permission as xp;

    use super::*;

    impl From<xp::peer::CanManagePeers> for Permission {
        fn from(_value: xp::peer::CanManagePeers) -> Self {
            todo!()
        }
    }

    impl From<xp::domain::CanRegisterDomain> for Permission {
        fn from(_value: xp::domain::CanRegisterDomain) -> Self {
            todo!()
        }
    }

    impl From<xp::domain::CanUnregisterDomain> for Permission {
        fn from(_value: xp::domain::CanUnregisterDomain) -> Self {
            todo!()
        }
    }

    impl From<xp::domain::CanModifyDomainMetadata> for Permission {
        fn from(_value: xp::domain::CanModifyDomainMetadata) -> Self {
            todo!()
        }
    }

    impl From<xp::account::CanRegisterAccount> for Permission {
        fn from(_value: xp::account::CanRegisterAccount) -> Self {
            todo!()
        }
    }

    impl From<xp::account::CanUnregisterAccount> for Permission {
        fn from(_value: xp::account::CanUnregisterAccount) -> Self {
            todo!()
        }
    }

    impl From<xp::account::CanModifyAccountMetadata> for Permission {
        fn from(_value: xp::account::CanModifyAccountMetadata) -> Self {
            todo!()
        }
    }

    impl From<xp::asset_definition::CanRegisterAssetDefinition> for Permission {
        fn from(_value: xp::asset_definition::CanRegisterAssetDefinition) -> Self {
            todo!()
        }
    }

    impl From<xp::asset_definition::CanUnregisterAssetDefinition> for Permission {
        fn from(_value: xp::asset_definition::CanUnregisterAssetDefinition) -> Self {
            todo!()
        }
    }

    impl From<xp::asset_definition::CanModifyAssetDefinitionMetadata> for Permission {
        fn from(_value: xp::asset_definition::CanModifyAssetDefinitionMetadata) -> Self {
            todo!()
        }
    }

    impl From<xp::asset::CanRegisterAssetWithDefinition> for Permission {
        fn from(_value: xp::asset::CanRegisterAssetWithDefinition) -> Self {
            todo!()
        }
    }

    impl From<xp::asset::CanUnregisterAssetWithDefinition> for Permission {
        fn from(_value: xp::asset::CanUnregisterAssetWithDefinition) -> Self {
            todo!()
        }
    }

    impl From<xp::asset::CanMintAssetWithDefinition> for Permission {
        fn from(_value: xp::asset::CanMintAssetWithDefinition) -> Self {
            todo!()
        }
    }

    impl From<xp::asset::CanBurnAssetWithDefinition> for Permission {
        fn from(_value: xp::asset::CanBurnAssetWithDefinition) -> Self {
            todo!()
        }
    }

    impl From<xp::asset::CanTransferAssetWithDefinition> for Permission {
        fn from(_value: xp::asset::CanTransferAssetWithDefinition) -> Self {
            todo!()
        }
    }

    impl From<xp::asset::CanRegisterAsset> for Permission {
        fn from(_value: xp::asset::CanRegisterAsset) -> Self {
            todo!()
        }
    }

    impl From<xp::asset::CanUnregisterAsset> for Permission {
        fn from(_value: xp::asset::CanUnregisterAsset) -> Self {
            todo!()
        }
    }

    impl From<xp::asset::CanMintAsset> for Permission {
        fn from(_value: xp::asset::CanMintAsset) -> Self {
            todo!()
        }
    }

    impl From<xp::asset::CanBurnAsset> for Permission {
        fn from(_value: xp::asset::CanBurnAsset) -> Self {
            todo!()
        }
    }

    impl From<xp::asset::CanTransferAsset> for Permission {
        fn from(_value: xp::asset::CanTransferAsset) -> Self {
            todo!()
        }
    }

    impl From<xp::asset::CanModifyAssetMetadata> for Permission {
        fn from(_value: xp::asset::CanModifyAssetMetadata) -> Self {
            todo!()
        }
    }

    impl From<xp::parameter::CanSetParameters> for Permission {
        fn from(_value: xp::parameter::CanSetParameters) -> Self {
            todo!()
        }
    }

    impl From<xp::role::CanManageRoles> for Permission {
        fn from(_value: xp::role::CanManageRoles) -> Self {
            todo!()
        }
    }

    impl From<xp::trigger::CanRegisterTrigger> for Permission {
        fn from(_value: xp::trigger::CanRegisterTrigger) -> Self {
            todo!()
        }
    }

    impl From<xp::trigger::CanExecuteTrigger> for Permission {
        fn from(_value: xp::trigger::CanExecuteTrigger) -> Self {
            todo!()
        }
    }

    impl From<xp::trigger::CanUnregisterTrigger> for Permission {
        fn from(_value: xp::trigger::CanUnregisterTrigger) -> Self {
            todo!()
        }
    }

    impl From<xp::trigger::CanModifyTrigger> for Permission {
        fn from(_value: xp::trigger::CanModifyTrigger) -> Self {
            todo!()
        }
    }

    impl From<xp::trigger::CanModifyTriggerMetadata> for Permission {
        fn from(_value: xp::trigger::CanModifyTriggerMetadata) -> Self {
            todo!()
        }
    }

    impl From<xp::executor::CanUpgradeExecutor> for Permission {
        fn from(_value: xp::executor::CanUpgradeExecutor) -> Self {
            todo!()
        }
    }
}
