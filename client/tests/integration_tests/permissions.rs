#![allow(clippy::restriction)]

use std::thread;

use iroha_client::client::{self, Client};
use iroha_core::{config::Configuration, prelude::AllowAll};
use iroha_data_model::prelude::*;
use iroha_permissions_validators::{private_blockchain, public_blockchain};
use test_network::{Peer as TestPeer, *};
use tokio::runtime::Runtime;

const BURN_REJECTION_REASON: &str = "Failed to pass first check with Can\'t burn assets from another account. \
    and second check with Account does not have the needed permission token: \
    PermissionToken { name: \"can_burn_user_assets\", params: {\"asset_id\": Id(AssetId(Id { definition_id: \
    DefinitionId { name: \"xor\", domain_name: \"wonderland\" }, account_id: Id { name: \"bob\", domain_name: \"wonderland\" } }))} }..";

const MINT_REJECTION_REASON: &str = "Failed to pass first check with Can\'t transfer assets of the other account. \
    and second check with Account does not have the needed permission token: \
    PermissionToken { name: \"can_transfer_user_assets\", params: {\"asset_id\": Id(AssetId(Id { definition_id: \
    DefinitionId { name: \"xor\", domain_name: \"wonderland\" }, account_id: Id { name: \"bob\", domain_name: \"wonderland\" } }))} }..";

fn get_assets(iroha_client: &mut Client, id: &AccountId) -> Vec<Asset> {
    iroha_client
        .request(client::asset::by_account_id(id.clone()))
        .expect("Failed to execute request.")
}

#[test]
fn permissions_disallow_asset_transfer() {
    let rt = Runtime::test();
    let (_peer, mut iroha_client) = rt.block_on(<TestPeer>::start_test_with_permissions(
        public_blockchain::default_permissions(),
        AllowAll.into(),
    ));
    wait_for_genesis_committed(vec![iroha_client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    // Given
    let alice_id = AccountId::new("alice", "wonderland").unwrap();
    let bob_id = AccountId::new("bob", "wonderland").unwrap();
    let asset_definition_id = AssetDefinitionId::new("xor", "wonderland").unwrap();
    let create_asset = RegisterBox::new(IdentifiableBox::from(AssetDefinition::new_quantity(
        asset_definition_id.clone(),
    )));
    let register_bob = RegisterBox::new(IdentifiableBox::from(NewAccount::new(bob_id.clone())));

    let alice_start_assets = get_assets(&mut iroha_client, &alice_id);
    iroha_client
        .submit_all(vec![create_asset.into(), register_bob.into()])
        .expect("Failed to prepare state.");
    thread::sleep(pipeline_time * 2);

    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), bob_id.clone())),
    );
    iroha_client
        .submit(mint_asset)
        .expect("Failed to create asset.");
    thread::sleep(pipeline_time * 2);

    //When
    let transfer_asset = TransferBox::new(
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), bob_id)),
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id, alice_id.clone())),
    );
    let err = iroha_client
        .submit_blocking(transfer_asset)
        .expect_err("Transaction was not rejected.");
    let rejection_reason = err
        .downcast_ref::<PipelineRejectionReason>()
        .unwrap_or_else(|| panic!("Error {} is not PipelineRejectionReasons.", err));
    //Then
    assert_eq!(
        rejection_reason,
        &PipelineRejectionReason::Transaction(TransactionRejectionReason::NotPermitted(
            NotPermittedFail {
                reason: MINT_REJECTION_REASON.to_owned(),
            }
        ))
    );
    let alice_assets = get_assets(&mut iroha_client, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}

#[test]
fn permissions_disallow_asset_burn() {
    let rt = Runtime::test();
    let (_not_drop, mut iroha_client) = rt.block_on(<TestPeer>::start_test_with_permissions(
        public_blockchain::default_permissions(),
        AllowAll.into(),
    ));
    let pipeline_time = Configuration::pipeline_time();

    // Given
    thread::sleep(pipeline_time * 5);

    let domain_name = "wonderland";
    let alice_id = AccountId::new("alice", domain_name).unwrap();
    let bob_id = AccountId::new("bob", domain_name).unwrap();
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name).unwrap();
    let create_asset = RegisterBox::new(IdentifiableBox::from(AssetDefinition::new_quantity(
        asset_definition_id.clone(),
    )));
    let register_bob = RegisterBox::new(IdentifiableBox::from(NewAccount::new(bob_id.clone())));

    let alice_start_assets = get_assets(&mut iroha_client, &alice_id);

    iroha_client
        .submit_all(vec![create_asset.into(), register_bob.into()])
        .expect("Failed to prepare state.");

    thread::sleep(pipeline_time * 2);

    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), bob_id.clone())),
    );
    iroha_client
        .submit_all(vec![mint_asset.into()])
        .expect("Failed to create asset.");
    thread::sleep(pipeline_time * 2);
    //When
    let burn_asset = BurnBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id, bob_id)),
    );

    let err = iroha_client
        .submit_blocking(burn_asset)
        .expect_err("Transaction was not rejected.");
    let rejection_reason = err
        .downcast_ref::<PipelineRejectionReason>()
        .unwrap_or_else(|| panic!("Error {} is not PipelineRejectionReasons.", err));
    //Then
    assert_eq!(
        rejection_reason,
        &PipelineRejectionReason::Transaction(TransactionRejectionReason::NotPermitted(
            NotPermittedFail {
                reason: BURN_REJECTION_REASON.to_owned(),
            }
        ))
    );

    let alice_assets = get_assets(&mut iroha_client, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}

#[test]
fn account_can_query_only_its_own_domain() {
    let rt = Runtime::test();
    let (_not_drop, mut iroha_client) = rt.block_on(<TestPeer>::start_test_with_permissions(
        AllowAll.into(),
        private_blockchain::query::OnlyAccountsDomain.into(),
    ));
    let pipeline_time = Configuration::pipeline_time();

    // Given
    thread::sleep(pipeline_time * 2);

    let domain_name = "wonderland";
    let new_domain_name = "wonderland2";
    let register_domain = RegisterBox::new(IdentifiableBox::from(Domain::new(Name::new(new_domain_name).unwrap().into())));

    iroha_client
        .submit(register_domain)
        .expect("Failed to prepare state.");

    thread::sleep(pipeline_time * 2);

    // Alice can query the domain in which her account exists.
    assert!(iroha_client
        .request(client::domain::by_id(DomainId::new(domain_name).unwrap()))
        .is_ok());

    // Alice can not query other domains.
    assert!(iroha_client
        .request(client::domain::by_id(DomainId::new(new_domain_name).unwrap()))
        .is_err());
}
