use std::{collections::BTreeMap, str::FromStr};

use executor_custom_data_model::multisig::{MultisigAccountArgs, MultisigTransactionArgs};
use eyre::Result;
use iroha::{
    client,
    crypto::KeyPair,
    data_model::{
        parameter::SmartContractParameter,
        prelude::*,
        query::{builder::SingleQueryError, trigger::FindTriggers},
        transaction::TransactionBuilder,
    },
};
use iroha_data_model::asset::{AssetDefinition, AssetDefinitionId};
use iroha_executor_data_model::permission::asset_definition::CanRegisterAssetDefinition;
use iroha_test_network::*;
use iroha_test_samples::{gen_account_in, BOB_ID, BOB_KEYPAIR, CARPENTER_ID, CARPENTER_KEYPAIR};
use nonzero_ext::nonzero;

#[test]
#[expect(clippy::too_many_lines)]
fn mutlisig() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_400).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    test_client.submit_all_blocking([
        SetParameter::new(Parameter::SmartContract(SmartContractParameter::Fuel(
            nonzero!(100_000_000_u64),
        ))),
        SetParameter::new(Parameter::Executor(SmartContractParameter::Fuel(nonzero!(
            100_000_000_u64
        )))),
    ])?;

    // Predefined in default genesis
    let multisig_accounts_registry_id = TriggerId::from_str("multisig_accounts_wonderland")?;

    // Create multisig account id and destroy it's private key
    // FIXME #5022 Should not allow arbitrary IDs. Otherwise, after #4426 pre-registration account will be hijacked as a multisig account
    let multisig_account_id = gen_account_in("wonderland").0;

    let multisig_transactions_registry_id: TriggerId = format!(
        "multisig_transactions_{}_{}",
        multisig_account_id.signatory(),
        multisig_account_id.domain()
    )
    .parse()?;

    let signatories = core::iter::repeat_with(|| gen_account_in("wonderland"))
        .take(5)
        .collect::<BTreeMap<AccountId, KeyPair>>();

    let args = MultisigAccountArgs {
        account: Account::new(multisig_account_id.clone()),
        signatories: signatories.keys().cloned().collect(),
    };

    test_client.submit_all_blocking(
        signatories
            .keys()
            .cloned()
            .map(Account::new)
            .map(Register::account),
    )?;

    let client = |account: AccountId, key_pair: KeyPair| client::Client {
        account,
        key_pair,
        ..test_client.clone()
    };
    let register_multisig_account =
        ExecuteTrigger::new(multisig_accounts_registry_id).with_args(&args);

    // Account cannot register multisig account in another domain
    let carpenter_client = client(CARPENTER_ID.clone(), CARPENTER_KEYPAIR.clone());
    let _err = carpenter_client
        .submit_blocking(register_multisig_account.clone())
        .expect_err("multisig account should not be registered by account of another domain");

    // Account can register multisig account in domain without special permission
    let bob_client = client(BOB_ID.clone(), BOB_KEYPAIR.clone());
    bob_client
        .submit_blocking(register_multisig_account)
        .expect("multisig account should be registered by account of the same domain");

    // Check that multisig account exist
    test_client
        .submit_blocking(Grant::account_permission(
            CanRegisterAssetDefinition {
                domain: "wonderland".parse().unwrap(),
            },
            multisig_account_id.clone(),
        ))
        .expect("multisig account should be created by calling the multisig accounts registry");

    // Check that multisig transactions registry exist
    let trigger = test_client
        .query(FindTriggers::new())
        .filter_with(|trigger| trigger.id.eq(multisig_transactions_registry_id.clone()))
        .execute_single()
        .expect("multisig transactions registry should be created along with the corresponding multisig account");

    assert_eq!(trigger.id(), &multisig_transactions_registry_id);

    let asset_definition_id = "asset_definition_controlled_by_multisig#wonderland"
        .parse::<AssetDefinitionId>()
        .unwrap();
    let instructions =
        vec![
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()))
                .into(),
        ];
    let instructions_hash = HashOf::new(&instructions);

    let mut signatories_iter = signatories.into_iter();

    if let Some((signatory, key_pair)) = signatories_iter.next() {
        let args = MultisigTransactionArgs::Propose(instructions);
        let propose =
            ExecuteTrigger::new(multisig_transactions_registry_id.clone()).with_args(&args);
        test_client.submit_transaction_blocking(
            &TransactionBuilder::new(test_client.chain.clone(), signatory)
                .with_instructions([propose])
                .sign(key_pair.private_key()),
        )?;
    }

    // Check that asset definition isn't created yet
    let err = test_client
        .query(client::asset::all_definitions())
        .filter_with(|asset_definition| asset_definition.id.eq(asset_definition_id.clone()))
        .execute_single()
        .expect_err("asset definition shouldn't be created without enough approvals");
    assert!(matches!(err, SingleQueryError::ExpectedOneGotNone));

    for (signatory, key_pair) in signatories_iter {
        let args = MultisigTransactionArgs::Approve(instructions_hash);
        let approve =
            ExecuteTrigger::new(multisig_transactions_registry_id.clone()).with_args(&args);
        test_client.submit_transaction_blocking(
            &TransactionBuilder::new(test_client.chain.clone(), signatory)
                .with_instructions([approve])
                .sign(key_pair.private_key()),
        )?;
    }

    // Check that new asset definition was created and multisig account is owner
    let asset_definition = test_client
        .query(client::asset::all_definitions())
        .filter_with(|asset_definition| asset_definition.id.eq(asset_definition_id.clone()))
        .execute_single()
        .expect("asset definition should be created with enough approvals");

    assert_eq!(asset_definition.owned_by(), &multisig_account_id);

    Ok(())
}
