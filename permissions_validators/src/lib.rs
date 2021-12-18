//! Out of box implementations for common permission checks.

#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;

use iroha_core::{
    prelude::*,
    smartcontracts::{
        permissions::{
            prelude::*, HasToken, IsAllowed, IsInstructionAllowedBoxed, IsQueryAllowedBoxed,
            ValidatorApplyOr, ValidatorBuilder,
        },
        Evaluate,
    },
    wsv::WorldTrait,
};
use iroha_data_model::{isi::*, prelude::*};
use iroha_macro::error::ErrorTryFromEnum;

macro_rules! impl_from_item_for_instruction_validator_box {
    ( $ty:ty ) => {
        impl<W: WorldTrait> From<$ty> for IsInstructionAllowedBoxed<W> {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }
    };
}

macro_rules! impl_from_item_for_query_validator_box {
    ( $ty:ty ) => {
        impl<W: WorldTrait> From<$ty> for IsQueryAllowedBoxed<W> {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }
    };
}

macro_rules! impl_from_item_for_granted_token_validator_box {
    ( $ty:ty ) => {
        impl<W: WorldTrait> From<$ty> for HasTokenBoxed<W> {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }

        impl<W: WorldTrait> From<$ty> for IsInstructionAllowedBoxed<W> {
            fn from(validator: $ty) -> Self {
                let validator: HasTokenBoxed<W> = validator.into();
                Box::new(validator)
            }
        }
    };
}

macro_rules! impl_from_item_for_grant_instruction_validator_box {
    ( $ty:ty ) => {
        impl<W: WorldTrait> From<$ty> for IsGrantAllowedBoxed<W> {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }

        impl<W: WorldTrait> From<$ty> for IsInstructionAllowedBoxed<W> {
            fn from(validator: $ty) -> Self {
                let validator: IsGrantAllowedBoxed<W> = validator.into();
                Box::new(validator)
            }
        }
    };
}

macro_rules! try_into_or_exit {
    ( $ident:ident ) => {
        if let Ok(into) = $ident.try_into() {
            into
        } else {
            return Ok(());
        }
    };
}

/// Permission checks asociated with use cases that can be summarized as private blockchains (e.g. CBDC).
pub mod private_blockchain {

    use super::*;

    /// A preconfigured set of permissions for simple use cases.
    pub fn default_instructions_permissions<W: WorldTrait>() -> IsInstructionAllowedBoxed<W> {
        ValidatorBuilder::new()
            .with_recursive_validator(
                register::ProhibitRegisterDomains.or(register::GrantedAllowedRegisterDomains),
            )
            .all_should_succeed()
    }

    /// A preconfigured set of permissions for simple use cases.
    pub fn default_query_permissions<W: WorldTrait>() -> IsQueryAllowedBoxed<W> {
        ValidatorBuilder::new().all_should_succeed()
    }

    /// Prohibits using `Grant` instruction at runtime.
    /// This means `Grant` instruction will only be used in genesis to specify rights.
    #[derive(Debug, Copy, Clone)]
    pub struct ProhibitGrant;

    impl_from_item_for_grant_instruction_validator_box!(ProhibitGrant);

    impl<W: WorldTrait> IsGrantAllowed<W> for ProhibitGrant {
        fn check_grant(
            &self,
            _authority: &AccountId,
            _instruction: &GrantBox,
            _wsv: &WorldStateView<W>,
        ) -> Result<(), DenialReason> {
            Err("Granting at runtime is prohibited.".to_owned())
        }
    }

    pub mod register {
        //! Module with permissions for registering.

        use std::collections::BTreeMap;

        use super::*;

        /// Can register domains permission token name.
        pub const CAN_REGISTER_DOMAINS_TOKEN: &str = "can_register_domains";

        /// Prohibits registering domains.
        #[derive(Debug, Copy, Clone)]
        pub struct ProhibitRegisterDomains;

        impl_from_item_for_instruction_validator_box!(ProhibitRegisterDomains);

        impl<W: WorldTrait> IsAllowed<W, Instruction> for ProhibitRegisterDomains {
            fn check(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                _wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let _register_box = if let Instruction::Register(register) = instruction {
                    register
                } else {
                    return Ok(());
                };
                Err("Domain registration is prohibited.".to_owned())
            }
        }

        /// Validator that allows to register domains for accounts with the corresponding permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantedAllowedRegisterDomains;

        impl_from_item_for_granted_token_validator_box!(GrantedAllowedRegisterDomains);

        impl<W: WorldTrait> HasToken<W> for GrantedAllowedRegisterDomains {
            fn token(
                &self,
                _authority: &AccountId,
                _instruction: &Instruction,
                _wsv: &WorldStateView<W>,
            ) -> Result<PermissionToken, String> {
                Ok(PermissionToken::new(
                    CAN_REGISTER_DOMAINS_TOKEN,
                    BTreeMap::new(),
                ))
            }
        }
    }

    /// Query Permissions.
    pub mod query {
        use super::*;

        /// Allow queries that only access the data of the domain of the signer.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAccountsDomain;

        impl<W: WorldTrait> IsAllowed<W, QueryBox> for OnlyAccountsDomain {
            #[allow(clippy::too_many_lines, clippy::match_same_arms)]
            fn check(
                &self,
                authority: &AccountId,
                query: &QueryBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                use QueryBox::*;
                let context = Context::new();
                match query {
                    FindAssetsByAssetDefinitionId(_) | FindAssetsByName(_) | FindAllAssets(_) => {
                        Err("Only access to the assets of the same domain is permitted.".to_owned())
                    }
                    FindAllAccounts(_) | FindAccountsByName(_) => Err(
                        "Only access to the accounts of the same domain is permitted.".to_owned(),
                    ),
                    FindAllAssetsDefinitions(_) => Err(
                        "Only access to the asset definitions of the same domain is permitted."
                            .to_owned(),
                    ),
                    FindAllDomains(_) => {
                        Err("Only access to the domain of the account is permitted.".to_owned())
                    }
                    #[cfg(feature = "roles")]
                    FindAllRoles(_) => Ok(()),
                    FindAllPeers(_) => Ok(()),
                    FindAccountById(query) => {
                        let account_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if account_id.domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access account {} as it is in a different domain.",
                                account_id
                            ))
                        }
                    }
                    FindAccountKeyValueByIdAndKey(query) => {
                        let account_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if account_id.domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access account {} as it is in a different domain.",
                                account_id
                            ))
                        }
                    }
                    FindAccountsByDomainId(query) => {
                        let domain_id = query
                            .domain_id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access accounts from a different domain with name {}.",
                                domain_id
                            ))
                        }
                    }
                    FindAssetById(query) => {
                        let asset_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if asset_id.account_id.domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access asset {} as it is in a different domain.",
                                asset_id
                            ))
                        }
                    }
                    FindAssetsByAccountId(query) => {
                        let account_id = query
                            .account_id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if account_id.domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access account {} as it is in a different domain.",
                                account_id
                            ))
                        }
                    }
                    FindAssetsByDomainId(query) => {
                        let domain_id = query
                            .domain_id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access assets from a different domain with name {}.",
                                domain_id
                            ))
                        }
                    }
                    FindAssetsByDomainIdAndAssetDefinitionId(query) => {
                        let domain_id = query
                            .domain_id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access assets from a different domain with name {}.",
                                domain_id
                            ))
                        }
                    }
                    FindAssetDefinitionKeyValueByIdAndKey(query) => {
                        let asset_definition_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if asset_definition_id.domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access asset definition from a different domain. Asset definition domain: {}. Signers account domain {}.",
                                asset_definition_id.domain_id,
                                authority.domain_id
                            ))
                        }
                    }
                    FindAssetQuantityById(query) => {
                        let asset_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if asset_id.account_id.domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access asset {} as it is in a different domain.",
                                asset_id
                            ))
                        }
                    }
                    FindAssetKeyValueByIdAndKey(query) => {
                        let asset_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if asset_id.account_id.domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access asset {} as it is in a different domain.",
                                asset_id
                            ))
                        }
                    }
                    FindDomainById(query::FindDomainById { id })
                    | FindDomainKeyValueByIdAndKey(query::FindDomainKeyValueByIdAndKey {
                        id,
                        ..
                    }) => {
                        let domain_id =
                            id.evaluate(wsv, &context).map_err(|err| err.to_string())?;
                        if domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!("Cannot access a different domain: {}.", domain_id))
                        }
                    }
                    FindTransactionsByAccountId(query) => {
                        let account_id = query
                            .account_id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if account_id.domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access account {} as it is in a different domain.",
                                account_id
                            ))
                        }
                    }
                    FindTransactionByHash(_query) => Ok(()),
                    #[cfg(feature = "roles")]
                    FindRolesByAccountId(query) => {
                        let account_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if account_id.domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access account {} as it is in a different domain.",
                                account_id
                            ))
                        }
                    }
                    FindPermissionTokensByAccountId(query) => {
                        let account_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if account_id.domain_id == authority.domain_id {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access account {} as it is in a different domain.",
                                account_id
                            ))
                        }
                    }
                }
            }
        }

        impl_from_item_for_query_validator_box!(OnlyAccountsDomain);

        /// Allow queries that only access the signers account data.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAccountsData;

        impl<W: WorldTrait> IsAllowed<W, QueryBox> for OnlyAccountsData {
            #[allow(clippy::too_many_lines, clippy::match_same_arms)]
            fn check(
                &self,
                authority: &AccountId,
                query: &QueryBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                use QueryBox::*;

                let context = Context::new();
                match query {
                    FindAccountsByName(_)
                    | FindAccountsByDomainId(_)
                    | FindAllAccounts(_)
                    | FindAllAssetsDefinitions(_)
                    | FindAssetsByAssetDefinitionId(_)
                    | FindAssetsByDomainId(_)
                    | FindAssetsByName(_)
                    | FindAllDomains(_)
                    | FindDomainById(_)
                    | FindDomainKeyValueByIdAndKey(_)
                    | FindAssetsByDomainIdAndAssetDefinitionId(_)
                    | FindAssetDefinitionKeyValueByIdAndKey(_)
                    | FindAllAssets(_) => {
                        Err("Only access to the assets of the same domain is permitted.".to_owned())
                    }
                    #[cfg(feature = "roles")]
                    FindAllRoles(_) => Ok(()),
                    FindAllPeers(_) => Ok(()),
                    FindAccountById(query) => {
                        let account_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if &account_id == authority {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access account {} as only access to your own account is permitted..",
                                account_id
                            ))
                        }
                    }
                    FindAccountKeyValueByIdAndKey(query) => {
                        let account_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if &account_id == authority {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access account {} as only access to your own account is permitted..",
                                account_id
                            ))
                        }
                    }
                    FindAssetById(query) => {
                        let asset_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if &asset_id.account_id == authority {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access asset {} as it is in a different account.",
                                asset_id
                            ))
                        }
                    }
                    FindAssetsByAccountId(query) => {
                        let account_id = query
                            .account_id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if &account_id == authority {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access a different account: {}.",
                                account_id
                            ))
                        }
                    }

                    FindAssetQuantityById(query) => {
                        let asset_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if &asset_id.account_id == authority {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access asset {} as it is in a different account.",
                                asset_id
                            ))
                        }
                    }
                    FindAssetKeyValueByIdAndKey(query) => {
                        let asset_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if &asset_id.account_id == authority {
                            Ok(())
                        } else {
                            Err(format!(
                                "Cannot access asset {} as it is in a different account.",
                                asset_id
                            ))
                        }
                    }

                    FindTransactionsByAccountId(query) => {
                        let account_id = query
                            .account_id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if &account_id == authority {
                            Ok(())
                        } else {
                            Err(format!("Cannot access another account: {}.", account_id))
                        }
                    }
                    FindTransactionByHash(_query) => Ok(()),
                    #[cfg(feature = "roles")]
                    FindRolesByAccountId(query) => {
                        let account_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if &account_id == authority {
                            Ok(())
                        } else {
                            Err(format!("Cannot access another account: {}.", account_id))
                        }
                    }
                    FindPermissionTokensByAccountId(query) => {
                        let account_id = query
                            .id
                            .evaluate(wsv, &context)
                            .map_err(|err| err.to_string())?;
                        if &account_id == authority {
                            Ok(())
                        } else {
                            Err(format!("Cannot access another account: {}.", account_id))
                        }
                    }
                }
            }
        }

        impl_from_item_for_query_validator_box!(OnlyAccountsData);
    }
}

/// Permission checks asociated with use cases that can be summarized as public blockchains.
pub mod public_blockchain {
    use super::*;

    /// Origin asset id param used in permission tokens.
    pub const ASSET_ID_TOKEN_PARAM_NAME: &str = "asset_id";
    /// Origin account id param used in permission tokens.
    pub const ACCOUNT_ID_TOKEN_PARAM_NAME: &str = "account_id";
    /// Origin asset definition param used in permission tokens.
    pub const ASSET_DEFINITION_ID_TOKEN_PARAM_NAME: &str = "asset_definition_id";

    /// A preconfigured set of permissions for simple use cases.
    pub fn default_permissions<W: WorldTrait>() -> IsInstructionAllowedBoxed<W> {
        // Grant instruction checks are or unioned, so that if one permission validator approves this Grant it will succeed.
        let grant_instruction_validator = ValidatorBuilder::new()
            .with_validator(transfer::GrantMyAssetAccess)
            .with_validator(unregister::GrantRegisteredByMeAccess)
            .with_validator(mint::GrantRegisteredByMeAccess)
            .with_validator(burn::GrantMyAssetAccess)
            .with_validator(burn::GrantRegisteredByMeAccess)
            .with_validator(key_value::GrantMyAssetAccessRemove)
            .with_validator(key_value::GrantMyAssetAccessSet)
            .with_validator(key_value::GrantMyMetadataAccessSet)
            .with_validator(key_value::GrantMyMetadataAccessRemove)
            .with_validator(key_value::GrantMyAssetDefinitionSet)
            .with_validator(key_value::GrantMyAssetDefinitionRemove)
            .any_should_succeed("Grant instruction validator.");
        ValidatorBuilder::new()
            .with_recursive_validator(grant_instruction_validator)
            .with_recursive_validator(transfer::OnlyOwnedAssets.or(transfer::GrantedByAssetOwner))
            .with_recursive_validator(
                unregister::OnlyAssetsCreatedByThisAccount.or(unregister::GrantedByAssetCreator),
            )
            .with_recursive_validator(
                mint::OnlyAssetsCreatedByThisAccount.or(mint::GrantedByAssetCreator),
            )
            .with_recursive_validator(burn::OnlyOwnedAssets.or(burn::GrantedByAssetOwner))
            .with_recursive_validator(
                burn::OnlyAssetsCreatedByThisAccount.or(burn::GrantedByAssetCreator),
            )
            .with_recursive_validator(
                key_value::AccountSetOnlyForSignerAccount.or(key_value::SetGrantedByAccountOwner),
            )
            .with_recursive_validator(
                key_value::AccountRemoveOnlyForSignerAccount
                    .or(key_value::RemoveGrantedByAccountOwner),
            )
            .with_recursive_validator(
                key_value::AssetSetOnlyForSignerAccount.or(key_value::SetGrantedByAssetOwner),
            )
            .with_recursive_validator(
                key_value::AssetRemoveOnlyForSignerAccount.or(key_value::RemoveGrantedByAssetOwner),
            )
            .with_recursive_validator(
                key_value::AssetDefinitionSetOnlyForSignerAccount
                    .or(key_value::SetGrantedByAssetDefinitionOwner),
            )
            .with_recursive_validator(
                key_value::AssetDefinitionRemoveOnlyForSignerAccount
                    .or(key_value::RemoveGrantedByAssetDefinitionOwner),
            )
            .all_should_succeed()
    }

    /// Checks that `authority` is account owner for account supplied in `permission_token`.
    ///
    /// # Errors
    /// - The `permission_token` is of improper format.
    /// - Account owner is not `authority`
    pub fn check_account_owner_for_token(
        permission_token: &PermissionToken,
        authority: &AccountId,
    ) -> Result<(), String> {
        let account_id = if let Value::Id(IdBox::AccountId(account_id)) = permission_token
            .params
            .get(&Name::new(ACCOUNT_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?)
            .ok_or(format!(
                "Failed to find permission param {}.",
                ACCOUNT_ID_TOKEN_PARAM_NAME
            ))? {
            account_id
        } else {
            return Err(format!(
                "Permission param {} is not an AccountId.",
                ACCOUNT_ID_TOKEN_PARAM_NAME
            ));
        };
        if account_id != authority {
            return Err("Account specified in permission token is not owned by signer.".to_owned());
        }
        Ok(())
    }

    /// Checks that `authority` is asset owner for asset supplied in `permission_token`.
    ///
    /// # Errors
    /// - The `permission_token` is of improper format.
    /// - Asset owner is not `authority`
    pub fn check_asset_owner_for_token(
        permission_token: &PermissionToken,
        authority: &AccountId,
    ) -> Result<(), String> {
        let asset_id = if let Value::Id(IdBox::AssetId(asset_id)) = permission_token
            .params
            .get(&Name::new(ASSET_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?)
            .ok_or(format!(
                "Failed to find permission param {}.",
                ASSET_ID_TOKEN_PARAM_NAME
            ))? {
            asset_id
        } else {
            return Err(format!(
                "Permission param {} is not an AssetId.",
                ASSET_ID_TOKEN_PARAM_NAME
            ));
        };
        if &asset_id.account_id != authority {
            return Err("Asset specified in permission token is not owned by signer.".to_owned());
        }
        Ok(())
    }

    /// Checks that asset creator is `authority` in the supplied `permission_token`.
    ///
    /// # Errors
    /// - The `permission_token` is of improper format.
    /// - Asset creator is not `authority`
    pub fn check_asset_creator_for_token<W: WorldTrait>(
        permission_token: &PermissionToken,
        authority: &AccountId,
        wsv: &WorldStateView<W>,
    ) -> Result<(), String> {
        let definition_id = if let Value::Id(IdBox::AssetDefinitionId(definition_id)) =
            permission_token
                .params
                .get(&Name::new(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?)
                .ok_or(format!(
                    "Failed to find permission param {}.",
                    ASSET_DEFINITION_ID_TOKEN_PARAM_NAME
                ))? {
            definition_id
        } else {
            return Err(format!(
                "Permission param {} is not an AssetDefinitionId.",
                ASSET_DEFINITION_ID_TOKEN_PARAM_NAME
            ));
        };
        let registered_by_signer_account = wsv
            .asset_definition_entry(definition_id)
            .map(|asset_definition_entry| &asset_definition_entry.registered_by == authority)
            .unwrap_or(false);
        if !registered_by_signer_account {
            return Err(
                "Can not grant access for assets, registered by another account.".to_owned(),
            );
        }
        Ok(())
    }

    pub mod transfer {
        //! Module with permission for transfering

        use super::*;

        /// Can transfer user's assets permission token name.
        pub const CAN_TRANSFER_USER_ASSETS_TOKEN: &str = "can_transfer_user_assets";

        /// Checks that account transfers only the assets that he owns.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyOwnedAssets;

        impl_from_item_for_instruction_validator_box!(OnlyOwnedAssets);

        impl<W: WorldTrait> IsAllowed<W, Instruction> for OnlyOwnedAssets {
            fn check(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let transfer_box = if let Instruction::Transfer(transfer) = instruction {
                    transfer
                } else {
                    return Ok(());
                };
                let source_id = transfer_box
                    .source_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let source_id: AssetId = try_into_or_exit!(source_id);

                if &source_id.account_id != authority {
                    return Err("Can't transfer assets of the other account.".to_owned());
                }
                Ok(())
            }
        }

        /// Allows transfering user's assets from a different account if the corresponding user granted this permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantedByAssetOwner;

        impl_from_item_for_granted_token_validator_box!(GrantedByAssetOwner);

        impl<W: WorldTrait> HasToken<W> for GrantedByAssetOwner {
            fn token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<PermissionToken, String> {
                let transfer_box = if let Instruction::Transfer(transfer_box) = instruction {
                    transfer_box
                } else {
                    return Err("Instruction is not transfer.".to_owned());
                };
                let source_id = transfer_box
                    .source_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let source_id: AssetId = if let Ok(id) = source_id.try_into() {
                    id
                } else {
                    return Err("Source id is not an AssetId.".to_owned());
                };
                let mut params = BTreeMap::new();
                params.insert(
                    Name::new(ASSET_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?,
                    source_id.into(),
                );
                Ok(PermissionToken::new(CAN_TRANSFER_USER_ASSETS_TOKEN, params))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyAssetAccess;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccess);

        impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyAssetAccess {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let permission_token: PermissionToken = instruction
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
                if permission_token.name.to_string() != CAN_TRANSFER_USER_ASSETS_TOKEN {
                    return Err("Grant instruction is not for transfer permission.".to_owned());
                }
                check_asset_owner_for_token(&permission_token, authority)
            }
        }
    }

    pub mod unregister {
        //! Module with permission for unregistering

        use super::*;

        /// Can unregister asset with the corresponding asset definition.
        pub const CAN_UNREGISTER_ASSET_WITH_DEFINITION: &str =
            "can_unregister_asset_with_definition";

        /// Checks that account can unregister only the assets which were registered by this account in the first place.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAssetsCreatedByThisAccount;

        impl_from_item_for_instruction_validator_box!(OnlyAssetsCreatedByThisAccount);

        impl<W: WorldTrait> IsAllowed<W, Instruction> for OnlyAssetsCreatedByThisAccount {
            fn check(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let unregister_box = if let Instruction::Unregister(unregister) = instruction {
                    unregister
                } else {
                    return Ok(());
                };
                let object_id = unregister_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_definition_id: AssetDefinitionId = try_into_or_exit!(object_id);
                let registered_by_signer_account = wsv
                    .asset_definition_entry(&asset_definition_id)
                    .map(|asset_definition_entry| {
                        &asset_definition_entry.registered_by == authority
                    })
                    .unwrap_or(false);
                if !registered_by_signer_account {
                    return Err("Can't unregister assets registered by other accounts.".to_owned());
                }
                Ok(())
            }
        }

        /// Allows unregistering user's assets from a different account if the corresponding user granted the permission token
        /// for a specific asset.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantedByAssetCreator;

        impl_from_item_for_granted_token_validator_box!(GrantedByAssetCreator);

        impl<W: WorldTrait> HasToken<W> for GrantedByAssetCreator {
            fn token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<PermissionToken, String> {
                let unregister_box = if let Instruction::Unregister(unregister) = instruction {
                    unregister
                } else {
                    return Err("Instruction is not unregister.".to_owned());
                };
                let object_id = unregister_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let object_id: AssetDefinitionId = if let Ok(obj_id) = object_id.try_into() {
                    obj_id
                } else {
                    return Err("Source id is not an AssetDefinitionId.".to_owned());
                };
                let mut params = BTreeMap::new();
                params.insert(
                    Name::new(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?,
                    object_id.into(),
                );
                Ok(PermissionToken::new(
                    CAN_UNREGISTER_ASSET_WITH_DEFINITION,
                    params,
                ))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantRegisteredByMeAccess;

        impl_from_item_for_grant_instruction_validator_box!(GrantRegisteredByMeAccess);

        impl<W: WorldTrait> IsGrantAllowed<W> for GrantRegisteredByMeAccess {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let permission_token: PermissionToken = instruction
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
                if permission_token.name.to_string() != CAN_UNREGISTER_ASSET_WITH_DEFINITION {
                    return Err("Grant instruction is not for unregister permission.".to_owned());
                }
                check_asset_creator_for_token(&permission_token, authority, wsv)
            }
        }
    }

    pub mod mint {
        //! Module with permission for minting

        use super::*;

        /// Can mint asset with the corresponding asset definition.
        pub const CAN_MINT_USER_ASSET_DEFINITIONS_TOKEN: &str = "can_mint_user_asset_definitions";

        /// Checks that account can mint only the assets which were registered by this account.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAssetsCreatedByThisAccount;

        impl_from_item_for_instruction_validator_box!(OnlyAssetsCreatedByThisAccount);

        impl<W: WorldTrait> IsAllowed<W, Instruction> for OnlyAssetsCreatedByThisAccount {
            fn check(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let mint_box = if let Instruction::Mint(mint) = instruction {
                    mint
                } else {
                    return Ok(());
                };
                let destination_id = mint_box
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = try_into_or_exit!(destination_id);
                let registered_by_signer_account = wsv
                    .asset_definition_entry(&asset_id.definition_id)
                    .map(|asset_definition_entry| {
                        &asset_definition_entry.registered_by == authority
                    })
                    .unwrap_or(false);
                if !registered_by_signer_account {
                    return Err("Can't mint assets registered by other accounts.".to_owned());
                }
                Ok(())
            }
        }

        /// Allows minting assets from a different account if the corresponding user granted the permission token
        /// for a specific asset.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantedByAssetCreator;

        impl_from_item_for_granted_token_validator_box!(GrantedByAssetCreator);

        impl<W: WorldTrait> HasToken<W> for GrantedByAssetCreator {
            fn token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<PermissionToken, String> {
                let mint_box = if let Instruction::Mint(mint) = instruction {
                    mint
                } else {
                    return Err("Instruction is not mint.".to_owned());
                };
                let destination_id = mint_box
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = if let Ok(dest_id) = destination_id.try_into() {
                    dest_id
                } else {
                    return Err("Destination is not an Asset.".to_owned());
                };
                let mut params = BTreeMap::new();
                params.insert(
                    Name::new(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?,
                    asset_id.definition_id.into(),
                );
                Ok(PermissionToken::new(
                    CAN_MINT_USER_ASSET_DEFINITIONS_TOKEN,
                    params,
                ))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantRegisteredByMeAccess;

        impl_from_item_for_grant_instruction_validator_box!(GrantRegisteredByMeAccess);

        impl<W: WorldTrait> IsGrantAllowed<W> for GrantRegisteredByMeAccess {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let permission_token: PermissionToken = instruction
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
                if permission_token.name.to_string() != CAN_MINT_USER_ASSET_DEFINITIONS_TOKEN {
                    return Err("Grant instruction is not for mint permission.".to_owned());
                }
                check_asset_creator_for_token(&permission_token, authority, wsv)
            }
        }
    }

    pub mod burn {
        //! Module with permission for burning

        use super::*;

        /// Can burn asset with the corresponding asset definition.
        pub const CAN_BURN_ASSET_WITH_DEFINITION: &str = "can_burn_asset_with_definition";
        /// Can burn user's assets permission token name.
        pub const CAN_BURN_USER_ASSETS_TOKEN: &str = "can_burn_user_assets";

        /// Checks that account can burn only the assets which were registered by this account.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyAssetsCreatedByThisAccount;

        impl_from_item_for_instruction_validator_box!(OnlyAssetsCreatedByThisAccount);

        impl<W: WorldTrait> IsAllowed<W, Instruction> for OnlyAssetsCreatedByThisAccount {
            fn check(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let burn_box = if let Instruction::Burn(burn) = instruction {
                    burn
                } else {
                    return Ok(());
                };
                let destination_id = burn_box
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = try_into_or_exit!(destination_id);
                let registered_by_signer_account = wsv
                    .asset_definition_entry(&asset_id.definition_id)
                    .map(|asset_definition_entry| {
                        &asset_definition_entry.registered_by == authority
                    })
                    .unwrap_or(false);
                if !registered_by_signer_account {
                    return Err("Can't burn assets registered by other accounts.".to_owned());
                }
                Ok(())
            }
        }

        /// Allows burning assets from a different account than the creator's of this asset if the corresponding user granted the permission token
        /// for a specific asset.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantedByAssetCreator;

        impl_from_item_for_granted_token_validator_box!(GrantedByAssetCreator);

        impl<W: WorldTrait> HasToken<W> for GrantedByAssetCreator {
            fn token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<PermissionToken, String> {
                let burn_box = if let Instruction::Burn(burn) = instruction {
                    burn
                } else {
                    return Err("Instruction is not burn.".to_owned());
                };
                let destination_id = burn_box
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = if let Ok(dest_id) = destination_id.try_into() {
                    dest_id
                } else {
                    return Err("Destination is not an Asset.".to_owned());
                };
                let mut params = BTreeMap::new();
                params.insert(
                    Name::new(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?,
                    asset_id.definition_id.into(),
                );
                Ok(PermissionToken::new(CAN_BURN_ASSET_WITH_DEFINITION, params))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantRegisteredByMeAccess;

        impl_from_item_for_grant_instruction_validator_box!(GrantRegisteredByMeAccess);

        impl<W: WorldTrait> IsGrantAllowed<W> for GrantRegisteredByMeAccess {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let permission_token: PermissionToken = instruction
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
                if permission_token.name.to_string() != CAN_BURN_ASSET_WITH_DEFINITION {
                    return Err("Grant instruction is not for burn permission.".to_owned());
                }
                check_asset_creator_for_token(&permission_token, authority, wsv)
            }
        }

        /// Checks that account can burn only the assets that he currently owns.
        #[derive(Debug, Copy, Clone)]
        pub struct OnlyOwnedAssets;

        impl_from_item_for_instruction_validator_box!(OnlyOwnedAssets);

        impl<W: WorldTrait> IsAllowed<W, Instruction> for OnlyOwnedAssets {
            fn check(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let burn_box = if let Instruction::Burn(burn) = instruction {
                    burn
                } else {
                    return Ok(());
                };
                let destination_id = burn_box
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let asset_id: AssetId = try_into_or_exit!(destination_id);
                if &asset_id.account_id != authority {
                    return Err("Can't burn assets from another account.".to_owned());
                }
                Ok(())
            }
        }

        /// Allows burning user's assets from a different account if the corresponding user granted this permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantedByAssetOwner;

        impl_from_item_for_granted_token_validator_box!(GrantedByAssetOwner);

        impl<W: WorldTrait> HasToken<W> for GrantedByAssetOwner {
            fn token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<PermissionToken, String> {
                let burn_box = if let Instruction::Burn(burn_box) = instruction {
                    burn_box
                } else {
                    return Err("Instruction is not burn.".to_owned());
                };
                let destination_id = burn_box
                    .destination_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let destination_id: AssetId = if let Ok(dest_id) = destination_id.try_into() {
                    dest_id
                } else {
                    return Err("Source id is not an AssetId.".to_owned());
                };
                let mut params = BTreeMap::new();
                params.insert(
                    Name::new(ASSET_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?,
                    destination_id.into(),
                );
                Ok(PermissionToken::new(CAN_BURN_USER_ASSETS_TOKEN, params))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyAssetAccess;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccess);

        impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyAssetAccess {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let permission_token: PermissionToken = instruction
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
                if permission_token.name.to_string() != CAN_BURN_USER_ASSETS_TOKEN {
                    return Err("Grant instruction is not for burn permission.".to_owned());
                }
                check_asset_owner_for_token(&permission_token, authority)?;
                Ok(())
            }
        }
    }

    pub mod key_value {
        //! Module with permission for burning

        use super::*;

        /// Can set key value in user's assets permission token name.
        pub const CAN_SET_KEY_VALUE_USER_ASSETS_TOKEN: &str = "can_set_key_value_in_user_assets";
        /// Can remove key value in user's assets permission token name.
        pub const CAN_REMOVE_KEY_VALUE_IN_USER_ASSETS: &str = "can_remove_key_value_in_user_assets";
        /// Can burn user's assets permission token name.
        pub const CAN_SET_KEY_VALUE_IN_USER_METADATA: &str = "can_set_key_value_in_user_metadata";
        /// Can burn user's assets permission token name.
        pub const CAN_REMOVE_KEY_VALUE_IN_USER_METADATA: &str =
            "can_remove_key_value_in_user_metadata";
        /// Can set key value in the corresponding asset definition.
        pub const CAN_SET_KEY_VALUE_IN_ASSET_DEFINITION: &str =
            "can_set_key_value_in_asset_definition";
        /// Can remove key value in the corresponding asset definition.
        pub const CAN_REMOVE_KEY_VALUE_IN_ASSET_DEFINITION: &str =
            "can_remove_key_value_in_asset_definition";
        /// Target account id for setting and removing key value permission tokens.
        pub const ACCOUNT_ID_TOKEN_PARAM_NAME: &str = "account_id";

        /// Checks that account can set keys for assets only for the signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AssetSetOnlyForSignerAccount;

        impl_from_item_for_instruction_validator_box!(AssetSetOnlyForSignerAccount);

        impl<W: WorldTrait> IsAllowed<W, Instruction> for AssetSetOnlyForSignerAccount {
            fn check(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
                    set_kv
                } else {
                    return Ok(());
                };
                let object_id = set_kv_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                match object_id {
                    IdBox::AssetId(asset_id) if &asset_id.account_id != authority => {
                        Err("Can't set value to asset store from another account.".to_owned())
                    }
                    _ => Ok(()),
                }
            }
        }

        /// Allows setting user's assets key value map from a different account
        /// if the corresponding user granted this permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct SetGrantedByAssetOwner;

        impl_from_item_for_granted_token_validator_box!(SetGrantedByAssetOwner);

        impl<W: WorldTrait> HasToken<W> for SetGrantedByAssetOwner {
            fn token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<PermissionToken, String> {
                let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
                    set_kv
                } else {
                    return Err("Instruction is not set.".to_owned());
                };
                let object_id = set_kv_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let object_id: AssetId = if let Ok(obj_id) = object_id.try_into() {
                    obj_id
                } else {
                    return Err("Source id is not an AssetId.".to_owned());
                };
                let mut params = BTreeMap::new();
                params.insert(
                    Name::new(ASSET_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?,
                    object_id.into(),
                );
                Ok(PermissionToken::new(
                    CAN_SET_KEY_VALUE_USER_ASSETS_TOKEN,
                    params,
                ))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyAssetAccessSet;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccessSet);

        impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyAssetAccessSet {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let permission_token: PermissionToken = instruction
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
                if permission_token.name.to_string() != CAN_SET_KEY_VALUE_USER_ASSETS_TOKEN {
                    return Err("Grant instruction is not for set permission.".to_owned());
                }
                check_asset_owner_for_token(&permission_token, authority)?;
                Ok(())
            }
        }

        /// Checks that account can set keys only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AccountSetOnlyForSignerAccount;

        impl_from_item_for_instruction_validator_box!(AccountSetOnlyForSignerAccount);

        impl<W: WorldTrait> IsAllowed<W, Instruction> for AccountSetOnlyForSignerAccount {
            fn check(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
                    set_kv
                } else {
                    return Ok(());
                };
                let object_id = set_kv_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                match &object_id {
                    IdBox::AccountId(account_id) if account_id != authority => {
                        Err("Can't set value to account store from another account.".to_owned())
                    }
                    _ => Ok(()),
                }
            }
        }

        /// Allows setting user's metadata key value pairs from a different account if the corresponding user granted this permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct SetGrantedByAccountOwner;

        impl_from_item_for_granted_token_validator_box!(SetGrantedByAccountOwner);

        impl<W: WorldTrait> HasToken<W> for SetGrantedByAccountOwner {
            fn token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<PermissionToken, String> {
                let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
                    set_kv
                } else {
                    return Err("Instruction is not set.".to_owned());
                };
                let object_id = set_kv_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let object_id: AccountId = if let Ok(obj_id) = object_id.try_into() {
                    obj_id
                } else {
                    return Err("Source id is not an AccountId.".to_owned());
                };
                let mut params = BTreeMap::new();
                params.insert(
                    Name::new(ACCOUNT_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?,
                    object_id.into(),
                );
                Ok(PermissionToken::new(
                    CAN_SET_KEY_VALUE_IN_USER_METADATA,
                    params,
                ))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyMetadataAccessSet;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyMetadataAccessSet);

        impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyMetadataAccessSet {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let permission_token: PermissionToken = instruction
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
                if permission_token.name.to_string() != CAN_SET_KEY_VALUE_IN_USER_METADATA {
                    return Err("Grant instruction is not for set permission.".to_owned());
                }
                check_account_owner_for_token(&permission_token, authority)?;
                Ok(())
            }
        }

        /// Checks that account can remove keys for assets only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AssetRemoveOnlyForSignerAccount;

        impl_from_item_for_instruction_validator_box!(AssetRemoveOnlyForSignerAccount);

        impl<W: WorldTrait> IsAllowed<W, Instruction> for AssetRemoveOnlyForSignerAccount {
            fn check(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
                    rem_kv
                } else {
                    return Ok(());
                };
                let object_id = rem_kv_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                match object_id {
                    IdBox::AssetId(asset_id) if &asset_id.account_id != authority => {
                        Err("Can't remove value from asset store from another account.".to_owned())
                    }
                    _ => Ok(()),
                }
            }
        }

        /// Allows removing user's assets key value pairs from a different account if the corresponding user granted this permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct RemoveGrantedByAssetOwner;

        impl_from_item_for_granted_token_validator_box!(RemoveGrantedByAssetOwner);

        impl<W: WorldTrait> HasToken<W> for RemoveGrantedByAssetOwner {
            fn token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<PermissionToken, String> {
                let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
                    rem_kv
                } else {
                    return Err("Instruction is not set.".to_owned());
                };
                let object_id = rem_kv_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let object_id: AssetId = if let Ok(obj_id) = object_id.try_into() {
                    obj_id
                } else {
                    return Err("Source id is not an AssetId.".to_owned());
                };
                let mut params = BTreeMap::new();
                params.insert(
                    Name::new(ASSET_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?,
                    object_id.into(),
                );
                Ok(PermissionToken::new(
                    CAN_REMOVE_KEY_VALUE_IN_USER_ASSETS,
                    params,
                ))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyAssetAccessRemove;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccessRemove);

        impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyAssetAccessRemove {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let permission_token: PermissionToken = instruction
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
                if permission_token.name.to_string() != CAN_REMOVE_KEY_VALUE_IN_USER_ASSETS {
                    return Err("Grant instruction is not for set permission.".to_owned());
                }
                check_asset_owner_for_token(&permission_token, authority)?;
                Ok(())
            }
        }

        /// Checks that account can remove keys only the for signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AccountRemoveOnlyForSignerAccount;

        impl_from_item_for_instruction_validator_box!(AccountRemoveOnlyForSignerAccount);

        impl<W: WorldTrait> IsAllowed<W, Instruction> for AccountRemoveOnlyForSignerAccount {
            fn check(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
                    rem_kv
                } else {
                    return Ok(());
                };
                let object_id = rem_kv_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                match object_id {
                    IdBox::AccountId(account_id) if &account_id != authority => Err(
                        "Can't remove value from account store from another account.".to_owned(),
                    ),
                    _ => Ok(()),
                }
            }
        }

        /// Allows removing user's metadata key value pairs from a different account if the corresponding user granted this permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct RemoveGrantedByAccountOwner;

        impl_from_item_for_granted_token_validator_box!(RemoveGrantedByAccountOwner);

        impl<W: WorldTrait> HasToken<W> for RemoveGrantedByAccountOwner {
            fn token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<PermissionToken, String> {
                let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
                    rem_kv
                } else {
                    return Err("Instruction is not remove.".to_owned());
                };
                let object_id = rem_kv_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let object_id: AccountId = if let Ok(obj_id) = object_id.try_into() {
                    obj_id
                } else {
                    return Err("Source id is not an AccountId.".to_owned());
                };
                let mut params = BTreeMap::new();
                params.insert(
                    Name::new(ACCOUNT_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?,
                    object_id.into(),
                );
                Ok(PermissionToken::new(
                    CAN_REMOVE_KEY_VALUE_IN_USER_METADATA,
                    params,
                ))
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the metadata
        /// of the signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyMetadataAccessRemove;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyMetadataAccessRemove);

        impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyMetadataAccessRemove {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let permission_token: PermissionToken = instruction
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
                if permission_token.name.to_string() != CAN_REMOVE_KEY_VALUE_IN_USER_METADATA {
                    return Err("Grant instruction is not for remove permission.".to_owned());
                }
                check_account_owner_for_token(&permission_token, authority)?;
                Ok(())
            }
        }

        /// Validator that checks Grant instruction so that the access is granted to the assets defintion
        /// registered by signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyAssetDefinitionSet;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetDefinitionSet);

        impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyAssetDefinitionSet {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let permission_token: PermissionToken = instruction
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
                if permission_token.name.to_string() != CAN_SET_KEY_VALUE_IN_ASSET_DEFINITION {
                    return Err(
                        "Grant instruction is not for set key value in asset definition permission."
                            .to_owned(),
                    );
                }
                check_asset_creator_for_token(&permission_token, authority, wsv)
            }
        }

        // Validator that checks Grant instruction so that the access is granted to the assets defintion
        /// registered by signer account.
        #[derive(Debug, Clone, Copy)]
        pub struct GrantMyAssetDefinitionRemove;

        impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetDefinitionRemove);

        impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyAssetDefinitionRemove {
            fn check_grant(
                &self,
                authority: &AccountId,
                instruction: &GrantBox,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let permission_token: PermissionToken = instruction
                    .object
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
                if permission_token.name.to_string() != CAN_REMOVE_KEY_VALUE_IN_ASSET_DEFINITION {
                    return Err(
                        "Grant instruction is not for remove key value in asset definition permission."
                            .to_owned(),
                    );
                }
                check_asset_creator_for_token(&permission_token, authority, wsv)
            }
        }

        /// Checks that account can set keys for asset definitions only registered by the signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AssetDefinitionSetOnlyForSignerAccount;

        impl_from_item_for_instruction_validator_box!(AssetDefinitionSetOnlyForSignerAccount);

        impl<W: WorldTrait> IsAllowed<W, Instruction> for AssetDefinitionSetOnlyForSignerAccount {
            fn check(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
                    set_kv
                } else {
                    return Ok(());
                };
                let obj_id = set_kv_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                let object_id: AssetDefinitionId = try_into_or_exit!(obj_id);
                let registered_by_signer_account = wsv
                    .asset_definition_entry(&object_id)
                    .map(|asset_definition_entry| {
                        &asset_definition_entry.registered_by == authority
                    })
                    .unwrap_or(false);
                if !registered_by_signer_account {
                    return Err(
                        "Can't set key value to asset definition registered by other accounts."
                            .to_owned(),
                    );
                }
                Ok(())
            }
        }

        /// Checks that account can set keys for asset definitions only registered by the signer account.
        #[derive(Debug, Copy, Clone)]
        pub struct AssetDefinitionRemoveOnlyForSignerAccount;

        impl_from_item_for_instruction_validator_box!(AssetDefinitionRemoveOnlyForSignerAccount);

        impl<W: WorldTrait> IsAllowed<W, Instruction> for AssetDefinitionRemoveOnlyForSignerAccount {
            fn check(
                &self,
                authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<(), DenialReason> {
                let rem_kv_box = if let Instruction::RemoveKeyValue(rem_kv) = instruction {
                    rem_kv
                } else {
                    return Ok(());
                };
                let obj_id = rem_kv_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;

                let object_id: AssetDefinitionId = try_into_or_exit!(obj_id);
                let registered_by_signer_account = wsv
                    .asset_definition_entry(&object_id)
                    .map(|asset_definition_entry| {
                        &asset_definition_entry.registered_by == authority
                    })
                    .unwrap_or(false);
                if !registered_by_signer_account {
                    return Err(
                        "Can't remove key value to asset definition registered by other accounts."
                            .to_owned(),
                    );
                }
                Ok(())
            }
        }

        /// Allows setting asset definition's metadata key value pairs from a different account if the corresponding user granted this permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct SetGrantedByAssetDefinitionOwner;

        impl_from_item_for_granted_token_validator_box!(SetGrantedByAssetDefinitionOwner);

        impl<W: WorldTrait> HasToken<W> for SetGrantedByAssetDefinitionOwner {
            fn token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<PermissionToken, String> {
                let set_kv_box = if let Instruction::SetKeyValue(set_kv) = instruction {
                    set_kv
                } else {
                    return Err("Instruction is not set.".to_owned());
                };
                let object_id = set_kv_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let object_id: AssetDefinitionId = if let Ok(obj_id) = object_id.try_into() {
                    obj_id
                } else {
                    return Err("Source id is not an AssetDefinitionId.".to_owned());
                };
                let mut params = BTreeMap::new();
                params.insert(
                    Name::new(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?,
                    object_id.into(),
                );
                Ok(PermissionToken::new(
                    CAN_SET_KEY_VALUE_IN_ASSET_DEFINITION,
                    params,
                ))
            }
        }

        /// Allows setting asset definition's metadata key value pairs from a different account if the corresponding user granted this permission token.
        #[derive(Debug, Clone, Copy)]
        pub struct RemoveGrantedByAssetDefinitionOwner;

        impl_from_item_for_granted_token_validator_box!(RemoveGrantedByAssetDefinitionOwner);

        impl<W: WorldTrait> HasToken<W> for RemoveGrantedByAssetDefinitionOwner {
            fn token(
                &self,
                _authority: &AccountId,
                instruction: &Instruction,
                wsv: &WorldStateView<W>,
            ) -> Result<PermissionToken, String> {
                let set_kv_box = if let Instruction::RemoveKeyValue(set_kv) = instruction {
                    set_kv
                } else {
                    return Err("Instruction is not remove key value.".to_owned());
                };
                let object_id = set_kv_box
                    .object_id
                    .evaluate(wsv, &Context::new())
                    .map_err(|e| e.to_string())?;
                let object_id: AssetDefinitionId = if let Ok(obj_id) = object_id.try_into() {
                    obj_id
                } else {
                    return Err("Source id is not an AssetDefinitionId.".to_owned());
                };
                let mut params = BTreeMap::new();
                params.insert(
                    Name::new(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME).map_err(|e| e.to_string())?,
                    object_id.into(),
                );
                Ok(PermissionToken::new(
                    CAN_REMOVE_KEY_VALUE_IN_ASSET_DEFINITION,
                    params,
                ))
            }
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::restriction)]

        use std::collections::{BTreeMap, BTreeSet};

        use iroha_core::wsv::World;

        use super::*;

        fn new_xor_definition(xor_id: &AssetDefinitionId) -> AssetDefinition {
            AssetDefinition::new_quantity(xor_id.clone())
        }

        #[test]
        fn transfer_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test").unwrap();
            let bob_xor_id = <Asset as Identifiable>::Id::from_names("xor", "test", "bob", "test").unwrap();
            let wsv = WorldStateView::<World>::new(World::new());
            let transfer = Instruction::Transfer(TransferBox {
                source_id: IdBox::AssetId(alice_xor_id).into(),
                object: Value::U32(10).into(),
                destination_id: IdBox::AssetId(bob_xor_id).into(),
            });
            assert!(transfer::OnlyOwnedAssets
                .check(&alice_id, &transfer, &wsv)
                .is_ok());
            assert!(transfer::OnlyOwnedAssets
                .check(&bob_id, &transfer, &wsv)
                .is_err());
        }

        #[test]
        fn transfer_granted_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test").unwrap();
            let bob_xor_id = <Asset as Identifiable>::Id::from_names("xor", "test", "bob", "test").unwrap();
            let mut domain = Domain::new(DomainId::new("test").unwrap());
            let mut bob_account = Account::new(bob_id.clone());
            let _ = bob_account.permission_tokens.insert(PermissionToken::new(
                transfer::CAN_TRANSFER_USER_ASSETS_TOKEN,
                [(
                    Name::new(ASSET_ID_TOKEN_PARAM_NAME).unwrap(),
                    alice_xor_id.clone().into(),
                )],
            ));
            domain.accounts.insert(bob_id.clone(), bob_account);
            let domains = vec![(DomainId::new("test").unwrap(), domain)];
            let wsv = WorldStateView::<World>::new(World::with(domains, BTreeSet::new()));
            let transfer = Instruction::Transfer(TransferBox {
                source_id: IdBox::AssetId(alice_xor_id).into(),
                object: Value::U32(10).into(),
                destination_id: IdBox::AssetId(bob_xor_id).into(),
            });
            let validator: IsInstructionAllowedBoxed<World> = transfer::OnlyOwnedAssets
                .or(transfer::GrantedByAssetOwner)
                .into();
            assert!(validator.check(&alice_id, &transfer, &wsv).is_ok());
            assert!(validator.check(&bob_id, &transfer, &wsv).is_ok());
        }

        #[test]
        fn grant_transfer_of_my_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test").unwrap();
            let permission_token_to_alice = PermissionToken::new(
                transfer::CAN_TRANSFER_USER_ASSETS_TOKEN,
                [(
                    Name::new(ASSET_ID_TOKEN_PARAM_NAME).unwrap(), alice_xor_id.into())],
            );
            let wsv = WorldStateView::<World>::new(World::new());
            let grant = Instruction::Grant(GrantBox {
                object: permission_token_to_alice.into(),
                destination_id: IdBox::AccountId(bob_id.clone()).into(),
            });
            let validator: IsInstructionAllowedBoxed<World> = transfer::GrantMyAssetAccess.into();
            assert!(validator.check(&alice_id, &grant, &wsv).is_ok());
            assert!(validator.check(&bob_id, &grant, &wsv).is_err());
        }

        #[test]
        fn unregister_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test").unwrap();
            let xor_definition = new_xor_definition(&xor_id);
            let wsv = WorldStateView::<World>::new(World::with(
                [(
                    "test".to_owned(),
                    Domain {
                        accounts: BTreeMap::new(),
                        id: Name::new("test").unwrap().into(),
                        asset_definitions: [(
                            xor_id.clone(),
                            AssetDefinitionEntry {
                                definition: xor_definition,
                                registered_by: alice_id.clone(),
                            },
                        )]
                        .into(),
                        metadata: Metadata::new(),
                    },
                )],
                [],
            ));
            let unregister =
                Instruction::Unregister(UnregisterBox::new(IdBox::AssetDefinitionId(xor_id)));
            assert!(unregister::OnlyAssetsCreatedByThisAccount
                .check(&alice_id, &unregister, &wsv)
                .is_ok());
            assert!(unregister::OnlyAssetsCreatedByThisAccount
                .check(&bob_id, &unregister, &wsv)
                .is_err());
        }

        #[test]
        fn unregister_granted_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test").unwrap();
            let xor_definition = new_xor_definition(&xor_id);
            let mut domain = Domain::new(DomainId::new("test").unwrap());
            let mut bob_account = Account::new(bob_id.clone());
            let _ = bob_account.permission_tokens.insert(PermissionToken::new(
                unregister::CAN_UNREGISTER_ASSET_WITH_DEFINITION,
                [(
                    Name::new(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME).unwrap(),
                    xor_id.clone().into(),
                )],
            ));
            domain.accounts.insert(bob_id.clone(), bob_account);
            domain.asset_definitions.insert(
                xor_id.clone(),
                AssetDefinitionEntry::new(xor_definition, alice_id.clone()),
            );
            let domains = vec![(DomainId::new("test").unwrap(), domain)];
            let wsv = WorldStateView::<World>::new(World::with(domains, []));
            let instruction = Instruction::Unregister(UnregisterBox::new(xor_id));
            let validator: IsInstructionAllowedBoxed<World> =
                unregister::OnlyAssetsCreatedByThisAccount
                    .or(unregister::GrantedByAssetCreator)
                    .into();
            assert!(validator.check(&alice_id, &instruction, &wsv).is_ok());
            assert!(validator.check(&bob_id, &instruction, &wsv).is_ok());
        }

        #[test]
        fn grant_unregister_of_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test").unwrap();
            let xor_definition = new_xor_definition(&xor_id);
            let permission_token_to_alice = PermissionToken::new(
                unregister::CAN_UNREGISTER_ASSET_WITH_DEFINITION,
                [(
                    Name::new(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME).unwrap(),
                    xor_id.clone().into(),
                )],
            );
            let mut domain = Domain::new(DomainId::new("test").unwrap());
            domain.asset_definitions.insert(
                xor_id,
                AssetDefinitionEntry::new(xor_definition, alice_id.clone()),
            );
            let domains = vec![(DomainId::new("test").unwrap(), domain)];

            let wsv = WorldStateView::<World>::new(World::with(domains, []));
            let grant = Instruction::Grant(GrantBox {
                object: permission_token_to_alice.into(),
                destination_id: IdBox::AccountId(bob_id.clone()).into(),
            });
            let validator: IsInstructionAllowedBoxed<World> =
                unregister::GrantRegisteredByMeAccess.into();
            assert!(validator.check(&alice_id, &grant, &wsv).is_ok());
            assert!(validator.check(&bob_id, &grant, &wsv).is_err());
        }

        #[test]
        fn mint_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test").unwrap();
            let xor_definition = new_xor_definition(&xor_id);
            let wsv = WorldStateView::<World>::new(World::with(
                [(
                    "test".to_string(),
                    Domain {
                        accounts: BTreeMap::new(),
                        id: DomainId::new("test").unwrap(),
                        asset_definitions: [(
                            xor_id,
                            AssetDefinitionEntry {
                                definition: xor_definition,
                                registered_by: alice_id.clone(),
                            },
                        )]
                        .into(),
                        metadata: Metadata::new(),
                    },
                )],
                [],
            ));
            let mint = Instruction::Mint(MintBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            assert!(mint::OnlyAssetsCreatedByThisAccount
                .check(&alice_id, &mint, &wsv)
                .is_ok());
            assert!(mint::OnlyAssetsCreatedByThisAccount
                .check(&bob_id, &mint, &wsv)
                .is_err());
        }

        #[test]
        fn mint_granted_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test").unwrap();
            let xor_definition = new_xor_definition(&xor_id);
            let mut domain = Domain::new(DomainId::new("test").unwrap());
            let mut bob_account = Account::new(bob_id.clone());
            let _ = bob_account.permission_tokens.insert(PermissionToken::new(
                mint::CAN_MINT_USER_ASSET_DEFINITIONS_TOKEN,
                [(
                    Name::new(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME).unwrap(),
                    xor_id.clone().into(),
                )],
            ));
            domain.accounts.insert(bob_id.clone(), bob_account);
            domain.asset_definitions.insert(
                xor_id,
                AssetDefinitionEntry::new(xor_definition, alice_id.clone()),
            );
            let domains = vec![(DomainId::new("test").unwrap(), domain)];
            let wsv = WorldStateView::<World>::new(World::with(domains, []));
            let instruction = Instruction::Mint(MintBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            let validator: IsInstructionAllowedBoxed<World> = mint::OnlyAssetsCreatedByThisAccount
                .or(mint::GrantedByAssetCreator)
                .into();
            assert!(validator.check(&alice_id, &instruction, &wsv).is_ok());
            assert!(validator.check(&bob_id, &instruction, &wsv).is_ok());
        }

        #[test]
        fn grant_mint_of_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test").unwrap();
            let xor_definition = new_xor_definition(&xor_id);
            let permission_token_to_alice = PermissionToken::new(
                mint::CAN_MINT_USER_ASSET_DEFINITIONS_TOKEN,
                [(
                    Name::new(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME).unwrap(),
                    xor_id.clone().into(),
                )],
            );
            let mut domain = Domain::new(DomainId::new("test").unwrap());
            domain.asset_definitions.insert(
                xor_id,
                AssetDefinitionEntry::new(xor_definition, alice_id.clone()),
            );
            let domains = vec![(DomainId::new("test").unwrap(), domain)];
            let wsv = WorldStateView::<World>::new(World::with(domains, vec![]));
            let grant = Instruction::Grant(GrantBox {
                object: permission_token_to_alice.into(),
                destination_id: IdBox::AccountId(bob_id.clone()).into(),
            });
            let validator: IsInstructionAllowedBoxed<World> =
                mint::GrantRegisteredByMeAccess.into();
            assert!(validator.check(&alice_id, &grant, &wsv).is_ok());
            assert!(validator.check(&bob_id, &grant, &wsv).is_err());
        }

        #[test]
        fn burn_only_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test").unwrap();
            let xor_definition = new_xor_definition(&xor_id);
            let wsv = WorldStateView::<World>::new(World::with(
                [(
                    "test".to_string(),
                    Domain {
                        accounts: [].into(),
                        id: DomainId::new("test").unwrap(),
                        asset_definitions: [(
                            xor_id,
                            AssetDefinitionEntry {
                                definition: xor_definition,
                                registered_by: alice_id.clone(),
                            },
                        )]
                        .into(),
                        metadata: Metadata::new(),
                    },
                )],
                [],
            ));
            let burn = Instruction::Burn(BurnBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            assert!(burn::OnlyAssetsCreatedByThisAccount
                .check(&alice_id, &burn, &wsv)
                .is_ok());
            assert!(burn::OnlyAssetsCreatedByThisAccount
                .check(&bob_id, &burn, &wsv)
                .is_err());
        }

        #[test]
        fn burn_granted_asset_definition() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test").unwrap();
            let xor_definition = new_xor_definition(&xor_id);
            let mut domain = Domain::new(DomainId::new("test").unwrap());
            let mut bob_account = Account::new(bob_id.clone());
            let _ = bob_account.permission_tokens.insert(PermissionToken::new(
                burn::CAN_BURN_ASSET_WITH_DEFINITION,
                [(
                    Name::new(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME).unwrap(),
                    xor_id.clone().into(),
                )],
            ));
            domain.accounts.insert(bob_id.clone(), bob_account);
            domain.asset_definitions.insert(
                xor_id,
                AssetDefinitionEntry::new(xor_definition, alice_id.clone()),
            );
            let domains = vec![(DomainId::new("test").unwrap(), domain)];
            let wsv = WorldStateView::<World>::new(World::with(domains, vec![]));
            let instruction = Instruction::Burn(BurnBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            let validator: IsInstructionAllowedBoxed<World> = burn::OnlyAssetsCreatedByThisAccount
                .or(burn::GrantedByAssetCreator)
                .into();
            assert!(validator.check(&alice_id, &instruction, &wsv).is_ok());
            assert!(validator.check(&bob_id, &instruction, &wsv).is_ok());
        }

        #[test]
        fn grant_burn_of_assets_created_by_this_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test").unwrap();
            let xor_definition = new_xor_definition(&xor_id);
            let permission_token_to_alice = PermissionToken::new(
                burn::CAN_BURN_ASSET_WITH_DEFINITION,
                [(
                    Name::new(ASSET_DEFINITION_ID_TOKEN_PARAM_NAME).unwrap(),
                    xor_id.clone().into(),
                )],
            );
            let mut domain = Domain::new(DomainId::new("test").unwrap());
            domain.asset_definitions.insert(
                xor_id,
                AssetDefinitionEntry::new(xor_definition, alice_id.clone()),
            );
            let domains = vec![(DomainId::new("test").unwrap(), domain)];
            let wsv = WorldStateView::<World>::new(World::with(domains, vec![]));
            let grant = Instruction::Grant(GrantBox {
                object: permission_token_to_alice.into(),
                destination_id: IdBox::AccountId(bob_id.clone()).into(),
            });
            let validator: IsInstructionAllowedBoxed<World> =
                burn::GrantRegisteredByMeAccess.into();
            assert!(validator.check(&alice_id, &grant, &wsv).is_ok());
            assert!(validator.check(&bob_id, &grant, &wsv).is_err());
        }

        #[test]
        fn burn_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test").unwrap();
            let wsv = WorldStateView::<World>::new(World::new());
            let burn = Instruction::Burn(BurnBox {
                object: Value::U32(100).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            assert!(burn::OnlyOwnedAssets.check(&alice_id, &burn, &wsv).is_ok());
            assert!(burn::OnlyOwnedAssets.check(&bob_id, &burn, &wsv).is_err());
        }

        #[test]
        fn burn_granted_assets() -> Result<(), String> {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test").unwrap();
            let mut domain = Domain::new("test")?;
            let mut bob_account = Account::new(bob_id.clone());
            let _ = bob_account.permission_tokens.insert(PermissionToken::new(
                burn::CAN_BURN_USER_ASSETS_TOKEN,
                [(
                    Name::new(ASSET_ID_TOKEN_PARAM_NAME).unwrap(),
                    alice_xor_id.clone().into(),
                )],
            ));
            domain.accounts.insert(bob_id.clone(), bob_account);
            let domains = vec![(DomainId::new("test").unwrap(), domain)];
            let wsv = WorldStateView::<World>::new(World::with(domains, vec![]));
            let transfer = Instruction::Burn(BurnBox {
                object: Value::U32(10).into(),
                destination_id: IdBox::AssetId(alice_xor_id).into(),
            });
            let validator: IsInstructionAllowedBoxed<World> =
                burn::OnlyOwnedAssets.or(burn::GrantedByAssetOwner).into();
            validator.check(&alice_id, &transfer, &wsv)?;
            assert!(validator.check(&bob_id, &transfer, &wsv).is_ok());
            Ok(())
        }

        #[test]
        fn grant_burn_of_my_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test").unwrap();
            let permission_token_to_alice = PermissionToken::new(
                burn::CAN_BURN_USER_ASSETS_TOKEN,
                [(
                    Name::new(ASSET_ID_TOKEN_PARAM_NAME).unwrap(), alice_xor_id.into())],
            );
            let wsv = WorldStateView::<World>::new(World::new());
            let grant = Instruction::Grant(GrantBox {
                object: permission_token_to_alice.into(),
                destination_id: IdBox::AccountId(bob_id.clone()).into(),
            });
            let validator: IsInstructionAllowedBoxed<World> = burn::GrantMyAssetAccess.into();
            assert!(validator.check(&alice_id, &grant, &wsv).is_ok());
            assert!(validator.check(&bob_id, &grant, &wsv).is_err());
        }

        #[test]
        fn set_to_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test").unwrap();
            let wsv = WorldStateView::<World>::new(World::new());
            let set = Instruction::SetKeyValue(SetKeyValueBox::new(
                IdBox::AssetId(alice_xor_id),
                Name::new("key").unwrap(),
                Name::new("value").unwrap(),
            ));
            assert!(key_value::AssetSetOnlyForSignerAccount
                .check(&alice_id, &set, &wsv)
                .is_ok());
            assert!(key_value::AssetSetOnlyForSignerAccount
                .check(&bob_id, &set, &wsv)
                .is_err());
        }

        #[test]
        fn remove_to_only_owned_assets() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test").unwrap();
            let wsv = WorldStateView::<World>::new(World::new());
            let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
                IdBox::AssetId(alice_xor_id),
                Name::new("key").unwrap(),
            ));
            assert!(key_value::AssetRemoveOnlyForSignerAccount
                .check(&alice_id, &set, &wsv)
                .is_ok());
            assert!(key_value::AssetRemoveOnlyForSignerAccount
                .check(&bob_id, &set, &wsv)
                .is_err());
        }

        #[test]
        fn set_to_only_owned_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let wsv = WorldStateView::<World>::new(World::new());
            let set = Instruction::SetKeyValue(SetKeyValueBox::new(
                IdBox::AccountId(alice_id.clone()),
                Name::new("key").unwrap(),
                Name::new("value").unwrap(),
            ));
            assert!(key_value::AccountSetOnlyForSignerAccount
                .check(&alice_id, &set, &wsv)
                .is_ok());
            assert!(key_value::AccountSetOnlyForSignerAccount
                .check(&bob_id, &set, &wsv)
                .is_err());
        }

        #[test]
        fn remove_to_only_owned_account() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let wsv = WorldStateView::<World>::new(World::new());
            let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
                IdBox::AccountId(alice_id.clone()),
                Name::new("key").unwrap(),
            ));
            assert!(key_value::AccountRemoveOnlyForSignerAccount
                .check(&alice_id, &set, &wsv)
                .is_ok());
            assert!(key_value::AccountRemoveOnlyForSignerAccount
                .check(&bob_id, &set, &wsv)
                .is_err());
        }

        #[test]
        fn set_to_only_owned_asset_definition() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test").unwrap();
            let xor_definition = new_xor_definition(&xor_id);
            let wsv = WorldStateView::<World>::new(World::with(
                [(
                    "test".to_string(),
                    Domain {
                        accounts: BTreeMap::new(),
                        id: DomainId::new("test").unwrap(),
                        asset_definitions: [(
                            xor_id.clone(),
                            AssetDefinitionEntry {
                                definition: xor_definition,
                                registered_by: alice_id.clone(),
                            },
                        )]
                        .into(),
                        metadata: Metadata::new(),
                    },
                )],
                [],
            ));
            let set = Instruction::SetKeyValue(SetKeyValueBox::new(
                IdBox::AssetDefinitionId(xor_id),
                Name::new("key").unwrap(),
                Name::new("value").unwrap(),
            ));
            assert!(key_value::AssetDefinitionSetOnlyForSignerAccount
                .check(&alice_id, &set, &wsv)
                .is_ok());
            assert!(key_value::AssetDefinitionSetOnlyForSignerAccount
                .check(&bob_id, &set, &wsv)
                .is_err());
        }

        #[test]
        fn remove_to_only_owned_asset_definition() {
            let alice_id = <Account as Identifiable>::Id::new("alice", "test").unwrap();
            let bob_id = <Account as Identifiable>::Id::new("bob", "test").unwrap();
            let xor_id = <AssetDefinition as Identifiable>::Id::new("xor", "test").unwrap();
            let xor_definition = new_xor_definition(&xor_id);
            let wsv = WorldStateView::<World>::new(World::with(
                [(
                    "test".to_string(),
                    Domain {
                        accounts: BTreeMap::new(),
                        id: DomainId::new("test").unwrap(),
                        asset_definitions: [(
                            xor_id.clone(),
                            AssetDefinitionEntry {
                                definition: xor_definition,
                                registered_by: alice_id.clone(),
                            },
                        )]
                        .into(),
                        metadata: Metadata::new(),
                    },
                )],
                [],
            ));
            let set = Instruction::RemoveKeyValue(RemoveKeyValueBox::new(
                IdBox::AssetDefinitionId(xor_id),
                Name::new("key").unwrap(),
            ));
            assert!(key_value::AssetDefinitionRemoveOnlyForSignerAccount
                .check(&alice_id, &set, &wsv)
                .is_ok());
            assert!(key_value::AssetDefinitionRemoveOnlyForSignerAccount
                .check(&bob_id, &set, &wsv)
                .is_err());
        }
    }
}
