use super::*;

pub type Permission = Tree<ReadWriteStatusFilter>;

pub type ReadWriteStatusFilter = receptor::WriteStatusFilter;

impl Filtered for changeset::ChangeSet {
    type Filter = Permission;

    fn passes(&self, filter: &Self::Filter) -> Result<(), Self::Filter> {
        self.as_status().passes(filter)
    }
}

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
        ($can:path, $node:ident, |$source:ident| $key:expr, $statuses:expr) => {
            impl From<$can> for Permission {
                fn from($source: $can) -> Self {
                    [(
                        NodeKey::$node($key),
                        NodeValue::$node(
                            $statuses
                                .iter()
                                .map(FilterU8::from)
                                .reduce(|acc, x| acc | x)
                                .unwrap(),
                        ),
                    )]
                    .into_iter()
                    .collect()
                }
            }
        };
    }

    macro_rules! some {
        ($key_element:expr) => {
            Some(Rc::new($key_element))
        };
    }

    // The following just demonstrates the possibility of replacing the current permissions:

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

    impl_into_permission!(
        xp::account::CanUnregisterAccount,
        Account,
        |v| (some!(v.account.signatory), some!(v.account.domain)),
        [UnitS::Delete]
    );

    impl_into_permission!(
        xp::account::CanModifyAccountMetadata,
        AccountMetadata,
        |v| (some!(v.account.signatory), some!(v.account.domain), None),
        [MetadataS::Set, MetadataS::Unset]
    );

    impl_into_permission!(
        xp::asset_definition::CanRegisterAssetDefinition,
        Asset,
        |v| (None, some!(v.domain)),
        [AssetS::Create]
    );

    impl_into_permission!(
        xp::asset_definition::CanUnregisterAssetDefinition,
        Asset,
        |v| (
            some!(v.asset_definition.name),
            some!(v.asset_definition.domain)
        ),
        [AssetS::Delete]
    );

    impl_into_permission!(
        xp::asset_definition::CanModifyAssetDefinitionMetadata,
        AssetMetadata,
        |v| (
            some!(v.asset_definition.name),
            some!(v.asset_definition.domain),
            None
        ),
        [MetadataS::Set, MetadataS::Unset]
    );

    impl_into_permission!(
        xp::asset::CanMintAssetWithDefinition,
        AccountAsset,
        |v| (
            None,
            None,
            some!(v.asset_definition.name),
            some!(v.asset_definition.domain)
        ),
        [AccountAssetS::Mint]
    );

    impl_into_permission!(
        xp::asset::CanBurnAssetWithDefinition,
        AccountAsset,
        |v| (
            None,
            None,
            some!(v.asset_definition.name),
            some!(v.asset_definition.domain)
        ),
        [AccountAssetS::Burn]
    );

    impl_into_permission!(
        xp::asset::CanTransferAssetWithDefinition,
        AccountAsset,
        |v| (
            None,
            None,
            some!(v.asset_definition.name),
            some!(v.asset_definition.domain)
        ),
        [AccountAssetS::Send]
    );

    impl_into_permission!(
        xp::asset::CanMintAsset,
        AccountAsset,
        |v| (
            some!(v.asset.account.signatory),
            some!(v.asset.account.domain),
            some!(v.asset.definition.name),
            some!(v.asset.definition.domain)
        ),
        [AccountAssetS::Mint]
    );

    impl_into_permission!(
        xp::asset::CanBurnAsset,
        AccountAsset,
        |v| (
            some!(v.asset.account.signatory),
            some!(v.asset.account.domain),
            some!(v.asset.definition.name),
            some!(v.asset.definition.domain)
        ),
        [AccountAssetS::Burn]
    );

    impl_into_permission!(
        xp::asset::CanTransferAsset,
        AccountAsset,
        |v| (
            some!(v.asset.account.signatory),
            some!(v.asset.account.domain),
            some!(v.asset.definition.name),
            some!(v.asset.definition.domain)
        ),
        [AccountAssetS::Send]
    );

    impl_into_permission!(
        xp::nft::CanRegisterNft,
        Nft,
        |v| (None, some!(v.domain)),
        [NftS::Create]
    );

    impl_into_permission!(
        xp::nft::CanUnregisterNft,
        Nft,
        |v| (some!(v.nft.name), some!(v.nft.domain)),
        [NftS::Delete]
    );

    impl_into_permission!(
        xp::nft::CanTransferNft,
        AccountRole,
        |v| (None, None, some!(crate::tr::RoleId::NftOwner(v.nft))),
        [UnitS::Create, UnitS::Delete]
    );

    impl_into_permission!(
        xp::nft::CanModifyNftMetadata,
        NftData,
        |v| (some!(v.nft.name), some!(v.nft.domain), None),
        [MetadataS::Set, MetadataS::Unset]
    );

    impl_into_permission!(
        xp::parameter::CanSetParameters,
        Parameter,
        |_v| None,
        [ParameterS::Set]
    );

    impl_into_permission!(
        xp::role::CanManageRoles,
        Role,
        |_v| None,
        [UnitS::Create, UnitS::Delete]
    );

    // TODO Separate into registration and ownership transfer.
    // xp::trigger::CanRegisterTrigger

    // TODO No validation should be performed when calling wasm executables, as they are resolved into event predictions and then validated.
    // xp::trigger::CanExecuteTrigger

    impl_into_permission!(
        xp::trigger::CanUnregisterTrigger,
        Trigger,
        |v| some!(v.trigger),
        [TriggerS::Delete]
    );

    impl_into_permission!(
        xp::trigger::CanModifyTrigger,
        Trigger,
        |v| some!(v.trigger),
        [TriggerS::Increase, TriggerS::Decrease]
    );

    impl_into_permission!(
        xp::trigger::CanModifyTriggerMetadata,
        TriggerMetadata,
        |v| (some!(v.trigger), None),
        [MetadataS::Set, MetadataS::Unset]
    );

    impl_into_permission!(
        xp::executor::CanUpgradeExecutor,
        Authorizer,
        |_v| (),
        [AuthorizerS::Set]
    );
}
