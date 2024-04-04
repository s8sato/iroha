//! Definition of Iroha default executor and accompanying validation functions
#![allow(missing_docs, clippy::missing_errors_doc)]

pub mod tokens;

use alloc::format;

pub use account::{
    visit_register_account, visit_remove_account_key_value, visit_set_account_key_value,
    visit_unregister_account,
};
pub use asset::{
    visit_burn_asset_numeric, visit_mint_asset_numeric, visit_register_asset,
    visit_remove_asset_key_value, visit_set_asset_key_value, visit_transfer_asset_numeric,
    visit_transfer_asset_store, visit_unregister_asset,
};
pub use asset_definition::{
    visit_register_asset_definition, visit_remove_asset_definition_key_value,
    visit_set_asset_definition_key_value, visit_transfer_asset_definition,
    visit_unregister_asset_definition,
};
pub use domain::{
    visit_register_domain, visit_remove_domain_key_value, visit_set_domain_key_value,
    visit_transfer_domain, visit_unregister_domain,
};
pub use executor::visit_upgrade;
pub use fail::visit_fail;
use iroha_smart_contract::data_model::isi::InstructionBox;
pub use log::visit_log;
pub use parameter::{visit_new_parameter, visit_set_parameter};
pub use peer::{visit_register_peer, visit_unregister_peer};
pub use permission_token::{visit_grant_account_permission, visit_revoke_account_permission};
pub use role::{
    visit_grant_account_role, visit_grant_role_permission, visit_register_role,
    visit_revoke_account_role, visit_revoke_role_permission, visit_unregister_role,
};
pub use trigger::{
    visit_burn_trigger_repetitions, visit_execute_trigger, visit_mint_trigger_repetitions,
    visit_register_trigger, visit_unregister_trigger,
};

use crate::{permission, permission::Token as _, prelude::*};

pub fn default_permission_token_schema() -> PermissionTokenSchema {
    let mut schema = iroha_executor::PermissionTokenSchema::default();

    macro_rules! add_to_schema {
        ($token_ty:ty) => {
            schema.insert::<$token_ty>();
        };
    }

    tokens::map_token_type!(add_to_schema);

    schema
}

// NOTE: If any new `visit_..` functions are introduced in this module, one should
// not forget to update the default executor boilerplate too, specifically the
// `iroha_executor::derive::default::impl_derive_visit` function
// signature list.

/// Default validation for [`SignedTransaction`].
///
/// # Warning
///
/// Each instruction is executed in sequence following successful validation.
/// [`Executable::Wasm`] is not executed because it is validated on the host side.
pub fn visit_transaction<V: Validate + ?Sized>(
    executor: &mut V,
    authority: &AccountId,
    transaction: &SignedTransaction,
) {
    match transaction.instructions() {
        Executable::Wasm(wasm) => executor.visit_wasm(authority, wasm),
        Executable::Instructions(instructions) => {
            for isi in instructions {
                if executor.verdict().is_ok() {
                    executor.visit_instruction(authority, isi);
                }
            }
        }
    }
}

/// Default validation for [`InstructionBox`].
///
/// # Warning
///
/// Instruction is executed following successful validation
pub fn visit_instruction<V: Validate + ?Sized>(
    executor: &mut V,
    authority: &AccountId,
    isi: &InstructionBox,
) {
    match isi {
        InstructionBox::NewParameter(isi) => {
            executor.visit_new_parameter(authority, isi);
        }
        InstructionBox::SetParameter(isi) => {
            executor.visit_set_parameter(authority, isi);
        }
        InstructionBox::Log(isi) => {
            executor.visit_log(authority, isi);
        }
        InstructionBox::ExecuteTrigger(isi) => {
            executor.visit_execute_trigger(authority, isi);
        }
        InstructionBox::Burn(isi) => {
            executor.visit_burn(authority, isi);
        }
        InstructionBox::Fail(isi) => {
            executor.visit_fail(authority, isi);
        }
        InstructionBox::Grant(isi) => {
            executor.visit_grant(authority, isi);
        }
        InstructionBox::Mint(isi) => {
            executor.visit_mint(authority, isi);
        }
        InstructionBox::Register(isi) => {
            executor.visit_register(authority, isi);
        }
        InstructionBox::RemoveKeyValue(isi) => {
            executor.visit_remove_key_value(authority, isi);
        }
        InstructionBox::Revoke(isi) => {
            executor.visit_revoke(authority, isi);
        }
        InstructionBox::SetKeyValue(isi) => {
            executor.visit_set_key_value(authority, isi);
        }
        InstructionBox::Transfer(isi) => {
            executor.visit_transfer(authority, isi);
        }
        InstructionBox::Unregister(isi) => {
            executor.visit_unregister(authority, isi);
        }
        InstructionBox::Upgrade(isi) => {
            executor.visit_upgrade(authority, isi);
        }
    }
}

pub mod peer {
    use super::*;

    pub fn visit_register_peer<V: Validate + ?Sized>(
        executor: &mut V,
        _authority: &AccountId,
        isi: &Register<Peer>,
    ) {
        execute!(executor, isi)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_unregister_peer<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Unregister<Peer>,
    ) {
        if is_genesis(executor) {
            execute!(executor, isi);
        }
        if tokens::peer::CanUnregisterAnyPeer.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(executor, "Can't unregister peer");
    }
}

pub mod domain {
    use iroha_smart_contract::data_model::{domain::DomainId, permission::PermissionToken};
    use permission::{
        account::is_account_owner, accounts_permission_tokens, domain::is_domain_owner,
    };
    use tokens::AnyPermissionToken;

    use super::*;

    pub fn visit_register_domain<V: Validate + ?Sized>(
        executor: &mut V,
        _authority: &AccountId,
        isi: &Register<Domain>,
    ) {
        execute!(executor, isi)
    }

    pub fn visit_unregister_domain<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Unregister<Domain>,
    ) {
        let domain_id = isi.object_id();

        if is_genesis(executor)
            || match is_domain_owner(domain_id, authority) {
                Err(err) => deny!(executor, err),
                Ok(is_domain_owner) => is_domain_owner,
            }
            || {
                let can_unregister_domain_token = tokens::domain::CanUnregisterDomain {
                    domain_id: domain_id.clone(),
                };
                can_unregister_domain_token.is_owned_by(authority)
            }
        {
            for (owner_id, permission) in accounts_permission_tokens() {
                if is_token_domain_associated(&permission, domain_id) {
                    let isi = Revoke::permission(permission, owner_id.clone());
                    if let Err(_err) = isi.execute() {
                        deny!(executor, "Can't revoke associated permission token");
                    }
                }
            }
            execute!(executor, isi);
        }
        deny!(executor, "Can't unregister domain");
    }

    pub fn visit_transfer_domain<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Transfer<Account, DomainId, Account>,
    ) {
        let source_id = isi.source_id();
        let domain_id = isi.object();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_account_owner(source_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        match is_domain_owner(domain_id, source_id) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }

        deny!(executor, "Can't transfer domain of another account");
    }

    pub fn visit_set_domain_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &SetKeyValue<Domain>,
    ) {
        let domain_id = isi.object_id();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_domain_owner(domain_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_set_key_value_in_domain_token = tokens::domain::CanSetKeyValueInDomain {
            domain_id: domain_id.clone(),
        };
        if can_set_key_value_in_domain_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(executor, "Can't set key value in domain metadata");
    }

    pub fn visit_remove_domain_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &RemoveKeyValue<Domain>,
    ) {
        let domain_id = isi.object_id();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_domain_owner(domain_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_remove_key_value_in_domain_token = tokens::domain::CanRemoveKeyValueInDomain {
            domain_id: domain_id.clone(),
        };
        if can_remove_key_value_in_domain_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(executor, "Can't remove key value in domain metadata");
    }

    #[allow(clippy::too_many_lines)]
    fn is_token_domain_associated(permission: &PermissionToken, domain_id: &DomainId) -> bool {
        let Ok(permission) = AnyPermissionToken::try_from(permission) else {
            return false;
        };
        match permission {
            AnyPermissionToken::CanUnregisterDomain(permission) => {
                &permission.domain_id == domain_id
            }
            AnyPermissionToken::CanSetKeyValueInDomain(permission) => {
                &permission.domain_id == domain_id
            }
            AnyPermissionToken::CanRemoveKeyValueInDomain(permission) => {
                &permission.domain_id == domain_id
            }
            AnyPermissionToken::CanRegisterAccountInDomain(permission) => {
                &permission.domain_id == domain_id
            }
            AnyPermissionToken::CanRegisterAssetDefinitionInDomain(permission) => {
                &permission.domain_id == domain_id
            }
            AnyPermissionToken::CanUnregisterAssetDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanSetKeyValueInAssetDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanRemoveKeyValueInAssetDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanRegisterAssetWithDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanUnregisterAssetWithDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanBurnAssetWithDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanMintAssetWithDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanTransferAssetWithDefinition(permission) => {
                permission.asset_definition_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanBurnUserAsset(permission) => {
                permission.asset_id.definition_id().domain_id() == domain_id
                    || permission.asset_id.account_id().domain_id() == domain_id
            }
            AnyPermissionToken::CanTransferUserAsset(permission) => {
                permission.asset_id.definition_id().domain_id() == domain_id
                    || permission.asset_id.account_id().domain_id() == domain_id
            }
            AnyPermissionToken::CanUnregisterUserAsset(permission) => {
                permission.asset_id.definition_id().domain_id() == domain_id
                    || permission.asset_id.account_id().domain_id() == domain_id
            }
            AnyPermissionToken::CanSetKeyValueInUserAsset(permission) => {
                permission.asset_id.definition_id().domain_id() == domain_id
                    || permission.asset_id.account_id().domain_id() == domain_id
            }
            AnyPermissionToken::CanRemoveKeyValueInUserAsset(permission) => {
                permission.asset_id.definition_id().domain_id() == domain_id
                    || permission.asset_id.account_id().domain_id() == domain_id
            }
            AnyPermissionToken::CanMintUserAsset(permission) => {
                permission.asset_id.definition_id().domain_id() == domain_id
                    || permission.asset_id.account_id().domain_id() == domain_id
            }
            AnyPermissionToken::CanUnregisterAccount(permission) => {
                permission.account_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanMintUserPublicKeys(permission) => {
                permission.account_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanBurnUserPublicKeys(permission) => {
                permission.account_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanMintUserSignatureCheckConditions(permission) => {
                permission.account_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanSetKeyValueInUserAccount(permission) => {
                permission.account_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanRemoveKeyValueInUserAccount(permission) => {
                permission.account_id.domain_id() == domain_id
            }
            AnyPermissionToken::CanUnregisterUserTrigger(permission) => {
                permission.trigger_id.domain_id().as_ref() == Some(domain_id)
            }
            AnyPermissionToken::CanExecuteUserTrigger(permission) => {
                permission.trigger_id.domain_id().as_ref() == Some(domain_id)
            }
            AnyPermissionToken::CanBurnUserTrigger(permission) => {
                permission.trigger_id.domain_id().as_ref() == Some(domain_id)
            }
            AnyPermissionToken::CanMintUserTrigger(permission) => {
                permission.trigger_id.domain_id().as_ref() == Some(domain_id)
            }
            AnyPermissionToken::CanUnregisterAnyPeer(_)
            | AnyPermissionToken::CanGrantPermissionToCreateParameters(_)
            | AnyPermissionToken::CanRevokePermissionToCreateParameters(_)
            | AnyPermissionToken::CanCreateParameters(_)
            | AnyPermissionToken::CanGrantPermissionToSetParameters(_)
            | AnyPermissionToken::CanRevokePermissionToSetParameters(_)
            | AnyPermissionToken::CanSetParameters(_)
            | AnyPermissionToken::CanUnregisterAnyRole(_)
            | AnyPermissionToken::CanUpgradeExecutor(_) => false,
        }
    }
}

pub mod account {
    use iroha_smart_contract::data_model::permission::PermissionToken;
    use permission::{account::is_account_owner, accounts_permission_tokens};
    use tokens::AnyPermissionToken;

    use super::*;

    pub fn visit_register_account<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Register<Account>,
    ) {
        let domain_id = isi.object().id().domain_id();

        match permission::domain::is_domain_owner(domain_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }

        let can_register_account_in_domain = tokens::domain::CanRegisterAccountInDomain {
            domain_id: domain_id.clone(),
        };
        if can_register_account_in_domain.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't register account in a domain owned by another account"
        );
    }

    pub fn visit_unregister_account<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Unregister<Account>,
    ) {
        let account_id = isi.object_id();

        if is_genesis(executor)
            || match is_account_owner(account_id, authority) {
                Err(err) => deny!(executor, err),
                Ok(is_account_owner) => is_account_owner,
            }
            || {
                let can_unregister_user_account = tokens::account::CanUnregisterAccount {
                    account_id: account_id.clone(),
                };
                can_unregister_user_account.is_owned_by(authority)
            }
        {
            for (owner_id, permission) in accounts_permission_tokens() {
                if is_token_account_associated(&permission, account_id) {
                    let isi = Revoke::permission(permission, owner_id.clone());
                    if let Err(_err) = isi.execute() {
                        deny!(executor, "Can't revoke associated permission token");
                    }
                }
            }
            execute!(executor, isi);
        }
        deny!(executor, "Can't unregister another account");
    }

    pub fn visit_set_account_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &SetKeyValue<Account>,
    ) {
        let account_id = isi.object_id();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_account_owner(account_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_set_key_value_in_user_account_token =
            tokens::account::CanSetKeyValueInUserAccount {
                account_id: account_id.clone(),
            };
        if can_set_key_value_in_user_account_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't set value to the metadata of another account"
        );
    }

    pub fn visit_remove_account_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &RemoveKeyValue<Account>,
    ) {
        let account_id = isi.object_id();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_account_owner(account_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_remove_key_value_in_user_account_token =
            tokens::account::CanRemoveKeyValueInUserAccount {
                account_id: account_id.clone(),
            };
        if can_remove_key_value_in_user_account_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't remove value from the metadata of another account"
        );
    }

    fn is_token_account_associated(permission: &PermissionToken, account_id: &AccountId) -> bool {
        let Ok(permission) = AnyPermissionToken::try_from(permission) else {
            return false;
        };
        match permission {
            AnyPermissionToken::CanUnregisterAccount(permission) => {
                &permission.account_id == account_id
            }
            AnyPermissionToken::CanMintUserPublicKeys(permission) => {
                &permission.account_id == account_id
            }
            AnyPermissionToken::CanBurnUserPublicKeys(permission) => {
                &permission.account_id == account_id
            }
            AnyPermissionToken::CanMintUserSignatureCheckConditions(permission) => {
                &permission.account_id == account_id
            }
            AnyPermissionToken::CanSetKeyValueInUserAccount(permission) => {
                &permission.account_id == account_id
            }
            AnyPermissionToken::CanRemoveKeyValueInUserAccount(permission) => {
                &permission.account_id == account_id
            }
            AnyPermissionToken::CanBurnUserAsset(permission) => {
                permission.asset_id.account_id() == account_id
            }
            AnyPermissionToken::CanTransferUserAsset(permission) => {
                permission.asset_id.account_id() == account_id
            }
            AnyPermissionToken::CanUnregisterUserAsset(permission) => {
                permission.asset_id.account_id() == account_id
            }
            AnyPermissionToken::CanSetKeyValueInUserAsset(permission) => {
                permission.asset_id.account_id() == account_id
            }
            AnyPermissionToken::CanRemoveKeyValueInUserAsset(permission) => {
                permission.asset_id.account_id() == account_id
            }
            AnyPermissionToken::CanMintUserAsset(permission) => {
                permission.asset_id.account_id() == account_id
            }
            AnyPermissionToken::CanUnregisterUserTrigger(_)
            | AnyPermissionToken::CanExecuteUserTrigger(_)
            | AnyPermissionToken::CanBurnUserTrigger(_)
            | AnyPermissionToken::CanMintUserTrigger(_)
            | AnyPermissionToken::CanUnregisterAnyPeer(_)
            | AnyPermissionToken::CanUnregisterDomain(_)
            | AnyPermissionToken::CanSetKeyValueInDomain(_)
            | AnyPermissionToken::CanRemoveKeyValueInDomain(_)
            | AnyPermissionToken::CanRegisterAccountInDomain(_)
            | AnyPermissionToken::CanRegisterAssetDefinitionInDomain(_)
            | AnyPermissionToken::CanUnregisterAssetDefinition(_)
            | AnyPermissionToken::CanSetKeyValueInAssetDefinition(_)
            | AnyPermissionToken::CanRemoveKeyValueInAssetDefinition(_)
            | AnyPermissionToken::CanRegisterAssetWithDefinition(_)
            | AnyPermissionToken::CanUnregisterAssetWithDefinition(_)
            | AnyPermissionToken::CanBurnAssetWithDefinition(_)
            | AnyPermissionToken::CanMintAssetWithDefinition(_)
            | AnyPermissionToken::CanTransferAssetWithDefinition(_)
            | AnyPermissionToken::CanGrantPermissionToCreateParameters(_)
            | AnyPermissionToken::CanRevokePermissionToCreateParameters(_)
            | AnyPermissionToken::CanCreateParameters(_)
            | AnyPermissionToken::CanGrantPermissionToSetParameters(_)
            | AnyPermissionToken::CanRevokePermissionToSetParameters(_)
            | AnyPermissionToken::CanSetParameters(_)
            | AnyPermissionToken::CanUnregisterAnyRole(_)
            | AnyPermissionToken::CanUpgradeExecutor(_) => false,
        }
    }
}

pub mod asset_definition {
    use iroha_smart_contract::data_model::{asset::AssetDefinitionId, permission::PermissionToken};
    use permission::{
        account::is_account_owner, accounts_permission_tokens,
        asset_definition::is_asset_definition_owner,
    };
    use tokens::AnyPermissionToken;

    use super::*;

    pub fn visit_register_asset_definition<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Register<AssetDefinition>,
    ) {
        let domain_id = isi.object().id().domain_id();

        match permission::domain::is_domain_owner(domain_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }

        let can_register_asset_definition_in_domain_token =
            tokens::domain::CanRegisterAssetDefinitionInDomain {
                domain_id: domain_id.clone(),
            };
        if can_register_asset_definition_in_domain_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't register asset definition in a domain owned by another account"
        );
    }

    pub fn visit_unregister_asset_definition<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Unregister<AssetDefinition>,
    ) {
        let asset_definition_id = isi.object_id();

        if is_genesis(executor)
            || match is_asset_definition_owner(asset_definition_id, authority) {
                Err(err) => deny!(executor, err),
                Ok(is_asset_definition_owner) => is_asset_definition_owner,
            }
            || {
                let can_unregister_asset_definition_token =
                    tokens::asset_definition::CanUnregisterAssetDefinition {
                        asset_definition_id: asset_definition_id.clone(),
                    };
                can_unregister_asset_definition_token.is_owned_by(authority)
            }
        {
            for (owner_id, permission) in accounts_permission_tokens() {
                if is_token_asset_definition_associated(&permission, asset_definition_id) {
                    let isi = Revoke::permission(permission, owner_id.clone());
                    if let Err(_err) = isi.execute() {
                        deny!(executor, "Can't revoke associated permission token");
                    }
                }
            }
            execute!(executor, isi);
        }
        deny!(
            executor,
            "Can't unregister asset definition in a domain owned by another account"
        );
    }

    pub fn visit_transfer_asset_definition<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Transfer<Account, AssetDefinitionId, Account>,
    ) {
        let source_id = isi.source_id();
        let destination_id = isi.object();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_account_owner(source_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        match is_asset_definition_owner(destination_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }

        deny!(
            executor,
            "Can't transfer asset definition of another account"
        );
    }

    pub fn visit_set_asset_definition_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &SetKeyValue<AssetDefinition>,
    ) {
        let asset_definition_id = isi.object_id();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_asset_definition_owner(asset_definition_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_set_key_value_in_asset_definition_token =
            tokens::asset_definition::CanSetKeyValueInAssetDefinition {
                asset_definition_id: asset_definition_id.clone(),
            };
        if can_set_key_value_in_asset_definition_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't set value to the asset definition metadata created by another account"
        );
    }

    pub fn visit_remove_asset_definition_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &RemoveKeyValue<AssetDefinition>,
    ) {
        let asset_definition_id = isi.object_id();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_asset_definition_owner(asset_definition_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_remove_key_value_in_asset_definition_token =
            tokens::asset_definition::CanRemoveKeyValueInAssetDefinition {
                asset_definition_id: asset_definition_id.clone(),
            };
        if can_remove_key_value_in_asset_definition_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't remove value from the asset definition metadata created by another account"
        );
    }

    fn is_token_asset_definition_associated(
        permission: &PermissionToken,
        asset_definition_id: &AssetDefinitionId,
    ) -> bool {
        let Ok(permission) = AnyPermissionToken::try_from(permission) else {
            return false;
        };
        match permission {
            AnyPermissionToken::CanUnregisterAssetDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanSetKeyValueInAssetDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanRemoveKeyValueInAssetDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanRegisterAssetWithDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanUnregisterAssetWithDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanBurnAssetWithDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanMintAssetWithDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanTransferAssetWithDefinition(permission) => {
                &permission.asset_definition_id == asset_definition_id
            }
            AnyPermissionToken::CanBurnUserAsset(permission) => {
                permission.asset_id.definition_id() == asset_definition_id
            }
            AnyPermissionToken::CanTransferUserAsset(permission) => {
                permission.asset_id.definition_id() == asset_definition_id
            }
            AnyPermissionToken::CanUnregisterUserAsset(permission) => {
                permission.asset_id.definition_id() == asset_definition_id
            }
            AnyPermissionToken::CanSetKeyValueInUserAsset(permission) => {
                permission.asset_id.definition_id() == asset_definition_id
            }
            AnyPermissionToken::CanRemoveKeyValueInUserAsset(permission) => {
                permission.asset_id.definition_id() == asset_definition_id
            }
            AnyPermissionToken::CanMintUserAsset(permission) => {
                permission.asset_id.definition_id() == asset_definition_id
            }
            AnyPermissionToken::CanUnregisterAccount(_)
            | AnyPermissionToken::CanMintUserPublicKeys(_)
            | AnyPermissionToken::CanBurnUserPublicKeys(_)
            | AnyPermissionToken::CanMintUserSignatureCheckConditions(_)
            | AnyPermissionToken::CanSetKeyValueInUserAccount(_)
            | AnyPermissionToken::CanRemoveKeyValueInUserAccount(_)
            | AnyPermissionToken::CanUnregisterUserTrigger(_)
            | AnyPermissionToken::CanExecuteUserTrigger(_)
            | AnyPermissionToken::CanBurnUserTrigger(_)
            | AnyPermissionToken::CanMintUserTrigger(_)
            | AnyPermissionToken::CanUnregisterAnyPeer(_)
            | AnyPermissionToken::CanUnregisterDomain(_)
            | AnyPermissionToken::CanSetKeyValueInDomain(_)
            | AnyPermissionToken::CanRemoveKeyValueInDomain(_)
            | AnyPermissionToken::CanRegisterAccountInDomain(_)
            | AnyPermissionToken::CanRegisterAssetDefinitionInDomain(_)
            | AnyPermissionToken::CanGrantPermissionToCreateParameters(_)
            | AnyPermissionToken::CanRevokePermissionToCreateParameters(_)
            | AnyPermissionToken::CanCreateParameters(_)
            | AnyPermissionToken::CanGrantPermissionToSetParameters(_)
            | AnyPermissionToken::CanRevokePermissionToSetParameters(_)
            | AnyPermissionToken::CanSetParameters(_)
            | AnyPermissionToken::CanUnregisterAnyRole(_)
            | AnyPermissionToken::CanUpgradeExecutor(_) => false,
        }
    }
}

pub mod asset {
    use iroha_smart_contract::data_model::{
        asset::AssetValue, isi::Instruction, metadata::Metadata,
    };
    use iroha_smart_contract_utils::Encode;
    use permission::{asset::is_asset_owner, asset_definition::is_asset_definition_owner};

    use super::*;

    pub fn visit_register_asset<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Register<Asset>,
    ) {
        let asset = isi.object();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_asset_definition_owner(asset.id().definition_id(), authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_register_assets_with_definition_token =
            tokens::asset::CanRegisterAssetWithDefinition {
                asset_definition_id: asset.id().definition_id().clone(),
            };
        if can_register_assets_with_definition_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't register assets with definitions registered by other accounts"
        );
    }

    pub fn visit_unregister_asset<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Unregister<Asset>,
    ) {
        let asset_id = isi.object_id();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_asset_owner(asset_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        match is_asset_definition_owner(asset_id.definition_id(), authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_unregister_assets_with_definition_token =
            tokens::asset::CanUnregisterAssetWithDefinition {
                asset_definition_id: asset_id.definition_id().clone(),
            };
        if can_unregister_assets_with_definition_token.is_owned_by(authority) {
            execute!(executor, isi);
        }
        let can_unregister_user_asset_token = tokens::asset::CanUnregisterUserAsset {
            asset_id: asset_id.clone(),
        };
        if can_unregister_user_asset_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(executor, "Can't unregister asset from another account");
    }

    fn validate_mint_asset<V, Q>(executor: &mut V, authority: &AccountId, isi: &Mint<Q, Asset>)
    where
        V: Validate + ?Sized,
        Q: Into<AssetValue>,
        Mint<Q, Asset>: Instruction + Encode,
    {
        let asset_id = isi.destination_id();
        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_asset_definition_owner(asset_id.definition_id(), authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_mint_assets_with_definition_token = tokens::asset::CanMintAssetWithDefinition {
            asset_definition_id: asset_id.definition_id().clone(),
        };
        if can_mint_assets_with_definition_token.is_owned_by(authority) {
            execute!(executor, isi);
        }
        let can_mint_user_asset_token = tokens::asset::CanMintUserAsset {
            asset_id: asset_id.clone(),
        };
        if can_mint_user_asset_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't mint assets with definitions registered by other accounts"
        );
    }

    pub fn visit_mint_asset_numeric<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Mint<Numeric, Asset>,
    ) {
        validate_mint_asset(executor, authority, isi);
    }

    fn validate_burn_asset<V, Q>(executor: &mut V, authority: &AccountId, isi: &Burn<Q, Asset>)
    where
        V: Validate + ?Sized,
        Q: Into<AssetValue>,
        Burn<Q, Asset>: Instruction + Encode,
    {
        let asset_id = isi.destination_id();
        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_asset_owner(asset_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        match is_asset_definition_owner(asset_id.definition_id(), authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_burn_assets_with_definition_token = tokens::asset::CanBurnAssetWithDefinition {
            asset_definition_id: asset_id.definition_id().clone(),
        };
        if can_burn_assets_with_definition_token.is_owned_by(authority) {
            execute!(executor, isi);
        }
        let can_burn_user_asset_token = tokens::asset::CanBurnUserAsset {
            asset_id: asset_id.clone(),
        };
        if can_burn_user_asset_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(executor, "Can't burn assets from another account");
    }

    pub fn visit_burn_asset_numeric<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Burn<Numeric, Asset>,
    ) {
        validate_burn_asset(executor, authority, isi);
    }

    fn validate_transfer_asset<V, Q>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Transfer<Asset, Q, Account>,
    ) where
        V: Validate + ?Sized,
        Q: Into<AssetValue>,
        Transfer<Asset, Q, Account>: Instruction + Encode,
    {
        let asset_id = isi.source_id();
        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_asset_owner(asset_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        match is_asset_definition_owner(asset_id.definition_id(), authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_transfer_assets_with_definition_token =
            tokens::asset::CanTransferAssetWithDefinition {
                asset_definition_id: asset_id.definition_id().clone(),
            };
        if can_transfer_assets_with_definition_token.is_owned_by(authority) {
            execute!(executor, isi);
        }
        let can_transfer_user_asset_token = tokens::asset::CanTransferUserAsset {
            asset_id: asset_id.clone(),
        };
        if can_transfer_user_asset_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(executor, "Can't transfer assets of another account");
    }

    pub fn visit_transfer_asset_numeric<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Transfer<Asset, Numeric, Account>,
    ) {
        validate_transfer_asset(executor, authority, isi);
    }

    pub fn visit_transfer_asset_store<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Transfer<Asset, Metadata, Account>,
    ) {
        validate_transfer_asset(executor, authority, isi);
    }

    pub fn visit_set_asset_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &SetKeyValue<Asset>,
    ) {
        let asset_id = isi.object_id();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_asset_owner(asset_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }

        let can_set_key_value_in_user_asset_token = tokens::asset::CanSetKeyValueInUserAsset {
            asset_id: asset_id.clone(),
        };
        if can_set_key_value_in_user_asset_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't set value to the asset metadata of another account"
        );
    }

    pub fn visit_remove_asset_key_value<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &RemoveKeyValue<Asset>,
    ) {
        let asset_id = isi.object_id();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_asset_owner(asset_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_remove_key_value_in_user_asset_token =
            tokens::asset::CanRemoveKeyValueInUserAsset {
                asset_id: asset_id.clone(),
            };
        if can_remove_key_value_in_user_asset_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't remove value from the asset metadata of another account"
        );
    }
}

pub mod parameter {
    use super::*;

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_new_parameter<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &NewParameter,
    ) {
        if is_genesis(executor) {
            execute!(executor, isi);
        }
        if tokens::parameter::CanCreateParameters.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't create new configuration parameters outside genesis without permission"
        );
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_set_parameter<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &SetParameter,
    ) {
        if is_genesis(executor) {
            execute!(executor, isi);
        }
        if tokens::parameter::CanSetParameters.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't set configuration parameters without permission"
        );
    }
}

pub mod role {
    use iroha_smart_contract::data_model::role::Role;
    use role::tokens::AnyPermissionToken;

    use super::*;

    macro_rules! impl_validate_grant_revoke_account_role {
        ($executor:ident, $isi:ident, $authority:ident, $method:ident) => {
            let role_id = $isi.object();

            let find_role_query_res = match FindRoleByRoleId::new(role_id.clone()).execute() {
                Ok(res) => res.into_raw_parts().0,
                Err(error) => {
                    deny!($executor, error);
                }
            };
            let role = Role::try_from(find_role_query_res).unwrap();

            let mut unknown_tokens = Vec::new();
            if !is_genesis($executor) {
                for token in role.permissions() {
                    if let Ok(token) = AnyPermissionToken::try_from(token) {
                        if let Err(error) = permission::ValidateGrantRevoke::$method(
                            &token,
                            $authority,
                            $executor.block_height(),
                        ) {
                            deny!($executor, error);
                        }
                        continue;
                    }

                    unknown_tokens.push(token);
                }
            }

            assert!(
                unknown_tokens.is_empty(),
                "Role contains unknown permission tokens: {unknown_tokens:?}"
            );
            execute!($executor, $isi)
        };
    }

    macro_rules! impl_validate_grant_revoke_role_permission {
        ($executor:ident, $isi:ident, $authority:ident, $method:ident, $isi_type:ty) => {
            let role_id = $isi.destination_id().clone();
            let token = $isi.object();

            if let Ok(any_token) = AnyPermissionToken::try_from(token) {
                let token = PermissionToken::from(any_token.clone());
                let isi = <$isi_type>::role_permission(token, role_id);
                if is_genesis($executor) {
                    execute!($executor, isi);
                }
                if let Err(error) = permission::ValidateGrantRevoke::$method(
                    &any_token,
                    $authority,
                    $executor.block_height(),
                ) {
                    deny!($executor, error);
                }

                execute!($executor, isi);
            }

            deny!(
                $executor,
                ValidationFail::NotPermitted(format!("{token:?}: Unknown permission token"))
            );
        };
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_register_role<V: Validate + ?Sized>(
        executor: &mut V,
        _authority: &AccountId,
        isi: &Register<Role>,
    ) {
        let role = isi.object().inner();

        // Unify permission tokens inside role and deduplicate them
        let mut new_role = Role::new(role.id().clone());
        let mut unknown_tokens = Vec::new();
        for token in role.permissions() {
            iroha_smart_contract::debug!(&format!("Checking `{token:?}`"));

            if let Ok(any_token) = AnyPermissionToken::try_from(token) {
                let token = PermissionToken::from(any_token);
                new_role = new_role.add_permission(token);
                continue;
            }

            unknown_tokens.push(token);
        }

        if !unknown_tokens.is_empty() {
            deny!(
                executor,
                ValidationFail::NotPermitted(format!(
                    "{unknown_tokens:?}: Unrecognised permission tokens"
                ))
            );
        }

        let isi = Register::role(new_role);
        execute!(executor, isi);
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_unregister_role<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Unregister<Role>,
    ) {
        if is_genesis(executor) {
            execute!(executor, isi);
        }
        if tokens::role::CanUnregisterAnyRole.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(executor, "Can't unregister role");
    }

    pub fn visit_grant_account_role<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Grant<RoleId, Account>,
    ) {
        impl_validate_grant_revoke_account_role!(executor, isi, authority, validate_grant);
    }

    pub fn visit_revoke_account_role<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Revoke<RoleId, Account>,
    ) {
        impl_validate_grant_revoke_account_role!(executor, isi, authority, validate_revoke);
    }

    pub fn visit_grant_role_permission<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Grant<PermissionToken, Role>,
    ) {
        impl_validate_grant_revoke_role_permission!(executor, isi, authority, validate_grant, Grant<PermissionToken, Role>);
    }

    pub fn visit_revoke_role_permission<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Revoke<PermissionToken, Role>,
    ) {
        impl_validate_grant_revoke_role_permission!(executor, isi, authority, validate_revoke, Revoke<PermissionToken, Role>);
    }
}

pub mod trigger {
    use iroha_smart_contract::data_model::{permission::PermissionToken, trigger::TriggerId};
    use permission::{accounts_permission_tokens, trigger::is_trigger_owner};
    use tokens::AnyPermissionToken;

    use super::*;

    pub fn visit_register_trigger<V: Validate + ?Sized>(
        executor: &mut V,
        _authority: &AccountId,
        isi: &Register<Trigger>,
    ) {
        execute!(executor, isi)
    }

    pub fn visit_unregister_trigger<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Unregister<Trigger>,
    ) {
        let trigger_id = isi.object_id();

        if is_genesis(executor)
            || match is_trigger_owner(trigger_id, authority) {
                Err(err) => deny!(executor, err),
                Ok(is_trigger_owner) => is_trigger_owner,
            }
            || {
                let can_unregister_user_trigger_token = tokens::trigger::CanUnregisterUserTrigger {
                    trigger_id: trigger_id.clone(),
                };
                can_unregister_user_trigger_token.is_owned_by(authority)
            }
        {
            for (owner_id, permission) in accounts_permission_tokens() {
                if is_token_trigger_associated(&permission, trigger_id) {
                    let isi = Revoke::permission(permission, owner_id.clone());
                    if let Err(_err) = isi.execute() {
                        deny!(executor, "Can't revoke associated permission token");
                    }
                }
            }
            execute!(executor, isi);
        }
        deny!(
            executor,
            "Can't unregister trigger owned by another account"
        );
    }

    pub fn visit_mint_trigger_repetitions<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Mint<u32, Trigger>,
    ) {
        let trigger_id = isi.destination_id();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_trigger_owner(trigger_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_mint_user_trigger_token = tokens::trigger::CanMintUserTrigger {
            trigger_id: trigger_id.clone(),
        };
        if can_mint_user_trigger_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't mint execution count for trigger owned by another account"
        );
    }

    pub fn visit_burn_trigger_repetitions<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Burn<u32, Trigger>,
    ) {
        let trigger_id = isi.destination_id();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_trigger_owner(trigger_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_mint_user_trigger_token = tokens::trigger::CanBurnUserTrigger {
            trigger_id: trigger_id.clone(),
        };
        if can_mint_user_trigger_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(
            executor,
            "Can't burn execution count for trigger owned by another account"
        );
    }

    pub fn visit_execute_trigger<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &ExecuteTrigger,
    ) {
        let trigger_id = isi.trigger_id();

        if is_genesis(executor) {
            execute!(executor, isi);
        }
        match is_trigger_owner(trigger_id, authority) {
            Err(err) => deny!(executor, err),
            Ok(true) => execute!(executor, isi),
            Ok(false) => {}
        }
        let can_execute_trigger_token = tokens::trigger::CanExecuteUserTrigger {
            trigger_id: trigger_id.clone(),
        };
        if can_execute_trigger_token.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(executor, "Can't execute trigger owned by another account");
    }

    fn is_token_trigger_associated(permission: &PermissionToken, trigger_id: &TriggerId) -> bool {
        let Ok(permission) = AnyPermissionToken::try_from(permission) else {
            return false;
        };
        match permission {
            AnyPermissionToken::CanUnregisterUserTrigger(permission) => {
                &permission.trigger_id == trigger_id
            }
            AnyPermissionToken::CanExecuteUserTrigger(permission) => {
                &permission.trigger_id == trigger_id
            }
            AnyPermissionToken::CanBurnUserTrigger(permission) => {
                &permission.trigger_id == trigger_id
            }
            AnyPermissionToken::CanMintUserTrigger(permission) => {
                &permission.trigger_id == trigger_id
            }
            AnyPermissionToken::CanUnregisterAnyPeer(_)
            | AnyPermissionToken::CanUnregisterDomain(_)
            | AnyPermissionToken::CanSetKeyValueInDomain(_)
            | AnyPermissionToken::CanRemoveKeyValueInDomain(_)
            | AnyPermissionToken::CanRegisterAccountInDomain(_)
            | AnyPermissionToken::CanRegisterAssetDefinitionInDomain(_)
            | AnyPermissionToken::CanUnregisterAccount(_)
            | AnyPermissionToken::CanMintUserPublicKeys(_)
            | AnyPermissionToken::CanBurnUserPublicKeys(_)
            | AnyPermissionToken::CanMintUserSignatureCheckConditions(_)
            | AnyPermissionToken::CanSetKeyValueInUserAccount(_)
            | AnyPermissionToken::CanRemoveKeyValueInUserAccount(_)
            | AnyPermissionToken::CanUnregisterAssetDefinition(_)
            | AnyPermissionToken::CanSetKeyValueInAssetDefinition(_)
            | AnyPermissionToken::CanRemoveKeyValueInAssetDefinition(_)
            | AnyPermissionToken::CanRegisterAssetWithDefinition(_)
            | AnyPermissionToken::CanUnregisterAssetWithDefinition(_)
            | AnyPermissionToken::CanUnregisterUserAsset(_)
            | AnyPermissionToken::CanBurnAssetWithDefinition(_)
            | AnyPermissionToken::CanBurnUserAsset(_)
            | AnyPermissionToken::CanMintAssetWithDefinition(_)
            | AnyPermissionToken::CanTransferAssetWithDefinition(_)
            | AnyPermissionToken::CanTransferUserAsset(_)
            | AnyPermissionToken::CanSetKeyValueInUserAsset(_)
            | AnyPermissionToken::CanRemoveKeyValueInUserAsset(_)
            | AnyPermissionToken::CanMintUserAsset(_)
            | AnyPermissionToken::CanGrantPermissionToCreateParameters(_)
            | AnyPermissionToken::CanRevokePermissionToCreateParameters(_)
            | AnyPermissionToken::CanCreateParameters(_)
            | AnyPermissionToken::CanGrantPermissionToSetParameters(_)
            | AnyPermissionToken::CanRevokePermissionToSetParameters(_)
            | AnyPermissionToken::CanSetParameters(_)
            | AnyPermissionToken::CanUnregisterAnyRole(_)
            | AnyPermissionToken::CanUpgradeExecutor(_) => false,
        }
    }
}

pub mod permission_token {
    use tokens::AnyPermissionToken;

    use super::*;

    macro_rules! impl_validate {
        ($executor:ident, $authority:ident, $isi:ident, $method:ident, $isi_type:ty) => {
            let account_id = $isi.destination_id().clone();
            let token = $isi.object();

            if let Ok(any_token) = AnyPermissionToken::try_from(token) {
                let token = PermissionToken::from(any_token.clone());
                let isi = <$isi_type>::permission(token, account_id);
                if is_genesis($executor) {
                    execute!($executor, isi);
                }
                if let Err(error) = permission::ValidateGrantRevoke::$method(
                    &any_token,
                    $authority,
                    $executor.block_height(),
                ) {
                    deny!($executor, error);
                }

                execute!($executor, isi);
            }

            deny!(
                $executor,
                ValidationFail::NotPermitted(format!("{token:?}: Unknown permission token"))
            );
        };
    }

    pub fn visit_grant_account_permission<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Grant<PermissionToken, Account>,
    ) {
        impl_validate!(
            executor,
            authority,
            isi,
            validate_grant,
            Grant<PermissionToken, Account>
        );
    }

    pub fn visit_revoke_account_permission<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Revoke<PermissionToken, Account>,
    ) {
        impl_validate!(
            executor,
            authority,
            isi,
            validate_revoke,
            Revoke<PermissionToken, Account>
        );
    }
}

pub mod executor {
    use super::*;

    #[allow(clippy::needless_pass_by_value)]
    pub fn visit_upgrade<V: Validate + ?Sized>(
        executor: &mut V,
        authority: &AccountId,
        isi: &Upgrade,
    ) {
        if is_genesis(executor) {
            execute!(executor, isi);
        }
        if tokens::executor::CanUpgradeExecutor.is_owned_by(authority) {
            execute!(executor, isi);
        }

        deny!(executor, "Can't upgrade executor");
    }
}

pub mod log {
    use super::*;

    pub fn visit_log<V: Validate + ?Sized>(executor: &mut V, _authority: &AccountId, isi: &Log) {
        execute!(executor, isi)
    }
}

pub mod fail {
    use super::*;

    pub fn visit_fail<V: Validate + ?Sized>(executor: &mut V, _authority: &AccountId, isi: &Fail) {
        execute!(executor, isi)
    }
}

fn is_genesis<V: Validate + ?Sized>(executor: &V) -> bool {
    executor.block_height() == 0
}
