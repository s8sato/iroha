#![allow(clippy::restriction, clippy::pedantic)]

use std::thread;

use iroha_client::client;
use iroha_core::{config::Configuration, prelude::*};
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

#[test]
fn client_can_transfer_asset_to_another_account() {
    let (_rt, _peer, mut iroha_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(vec![iroha_client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    let create_domain = RegisterBox::new(IdentifiableBox::from(Domain::new(DomainId::new("domain").unwrap())));
    let account1_id = AccountId::new("account1", "domain").unwrap();
    let account2_id = AccountId::new("account2", "domain").unwrap();
    let create_account1 = RegisterBox::new(IdentifiableBox::NewAccount(
        NewAccount::with_signatory(
            account1_id.clone(),
            KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        )
        .into(),
    ));
    let create_account2 = RegisterBox::new(IdentifiableBox::NewAccount(
        NewAccount::with_signatory(
            account2_id.clone(),
            KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        )
        .into(),
    ));
    let asset_definition_id = AssetDefinitionId::new("xor", "domain").unwrap();
    let quantity: u32 = 200;
    let create_asset = RegisterBox::new(IdentifiableBox::from(AssetDefinition::new_quantity(
        asset_definition_id.clone(),
    )));
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account1_id.clone(),
        )),
    );

    iroha_client
        .submit_all(vec![
            create_domain.into(),
            create_account1.into(),
            create_account2.into(),
            create_asset.into(),
            mint_asset.into(),
        ])
        .expect("Failed to prepare state.");

    thread::sleep(pipeline_time * 2);

    //When
    let quantity = 20;
    let transfer_asset = TransferBox::new(
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), account1_id)),
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account2_id.clone(),
        )),
    );
    iroha_client.submit_till(
        transfer_asset,
        client::asset::by_account_id(account2_id.clone()),
        |result| {
            result.iter().any(|asset| {
                asset.id.definition_id == asset_definition_id
                    && asset.value == AssetValue::Quantity(quantity)
                    && asset.id.account_id == account2_id
            })
        },
    );
}
