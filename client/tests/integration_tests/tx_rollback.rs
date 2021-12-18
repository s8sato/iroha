#![allow(clippy::restriction)]

use std::thread;

use iroha_client::client;
use iroha_core::config::Configuration;
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

#[test]
fn client_sends_transaction_with_invalid_instruction_should_not_see_any_changes() {
    let (_rt, _peer, mut iroha_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(vec![iroha_client.clone()], 0);

    let pipeline_time = Configuration::pipeline_time();

    //When
    let account_id = AccountId::new("alice", "wonderland").unwrap();
    let asset_definition_id = AssetDefinitionId::new("xor", "wonderland").unwrap();
    let wrong_asset_definition_id = AssetDefinitionId::new("ksor", "wonderland").unwrap();
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new_quantity(asset_definition_id).into(),
    ));
    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(
            wrong_asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    iroha_client
        .submit_all(vec![create_asset.into(), mint_asset.into()])
        .expect("Failed to prepare state.");
    thread::sleep(pipeline_time * 2);

    //Then
    let request = client::asset::by_account_id(account_id);
    let query_result = iroha_client
        .request(request)
        .expect("Failed to execute request.");
    assert!(query_result
        .iter()
        .all(|asset| asset.id.definition_id != wrong_asset_definition_id));
    let definition_query_result = iroha_client
        .request(client::asset::all_definitions())
        .expect("Failed to execute request.");
    assert!(definition_query_result
        .iter()
        .all(|asset| asset.id != wrong_asset_definition_id));
}
