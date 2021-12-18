#![allow(clippy::too_many_lines, clippy::restriction)]

use std::{str::FromStr, thread, time::Duration};

use iroha_client::{client::Client, samples::get_client_config};
use iroha_core::{
    genesis::{GenesisNetwork, GenesisNetworkTrait, RawGenesisBlock},
    prelude::*,
    samples::get_config,
};
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, TestRuntime};
use tokio::runtime::Runtime;

#[test]
fn find_rate_and_make_exchange_isi_should_be_valid() {
    let _instruction = Pair::new(
        TransferBox::new(
            IdBox::AssetId(AssetId::from_names("btc", "crypto", "seller", "company").unwrap()),
            Expression::Query(
                FindAssetQuantityById::new(AssetId::from_names(
                    "btc2eth_rate",
                    "exchange",
                    "dex",
                    "exchange",
                ).unwrap())
                .into(),
            ),
            IdBox::AssetId(AssetId::from_names("btc", "crypto", "buyer", "company").unwrap()),
        ),
        TransferBox::new(
            IdBox::AssetId(AssetId::from_names("btc", "crypto", "buyer", "company").unwrap()),
            Expression::Query(
                FindAssetQuantityById::new(AssetId::from_names(
                    "btc2eth_rate",
                    "exchange",
                    "dex",
                    "exchange",
                ).unwrap())
                .into(),
            ),
            IdBox::AssetId(AssetId::from_names("btc", "crypto", "seller", "company").unwrap()),
        ),
    );
}

#[test]
fn find_rate_and_check_it_greater_than_value_isi_should_be_valid() {
    let _instruction = IfInstruction::new(
        Not::new(Greater::new(
            QueryBox::from(FindAssetQuantityById::new(AssetId::from_names(
                "btc2eth_rate",
                "exchange",
                "dex",
                "exchange",
            ).unwrap())),
            10_u32,
        )),
        FailBox::new("rate is less or equal to value"),
    );
}

struct FindRateAndCheckItGreaterThanValue {
    from_currency: String,
    to_currency: String,
    value: u32,
}

impl FindRateAndCheckItGreaterThanValue {
    pub fn new(from_currency: &str, to_currency: &str, value: u32) -> Self {
        Self {
            from_currency: from_currency.to_string(),
            to_currency: to_currency.to_string(),
            value,
        }
    }

    pub fn into_isi(self) -> IfInstruction {
        IfInstruction::new(
            Not::new(Greater::new(
                QueryBox::from(FindAssetQuantityById::new(AssetId::from_names(
                    &format!("{}2{}_rate", self.from_currency, self.to_currency),
                    "exchange",
                    "dex",
                    "exchange",
                ).unwrap())),
                self.value,
            )),
            FailBox::new("rate is less or equal to value"),
        )
    }
}

#[test]
fn find_rate_and_check_it_greater_than_value_predefined_isi_should_be_valid() {
    let _instruction = FindRateAndCheckItGreaterThanValue::new("btc", "eth", 10).into_isi();
}

#[test]
fn find_rate_and_make_exchange_isi_should_succeed() {
    let kp = KeyPair {
        public_key: PublicKey::from_str(
            r#"ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"#,
        )
        .unwrap(),
        private_key: PrivateKey {
            digest_function: "ed25519".to_string(),
            payload: hex_literal::hex!("9AC47ABF 59B356E0 BD7DCBBB B4DEC080 E302156A 48CA907E 47CB6AEA 1D32719E 7233BFC8 9DCBD68C 19FDE6CE 61582252 98EC1131 B6A130D1 AEB454C1 AB5183C0")
            .into(),
        },
    };
    let mut peer = <TestPeer>::new().expect("Failed to create peer");
    let configuration = get_config(std::iter::once(peer.id.clone()).collect(), Some(kp.clone()));
    let pipeline_time = Duration::from_millis(configuration.sumeragi.pipeline_time_ms());

    // Given
    let genesis = GenesisNetwork::from_configuration(
        true,
        RawGenesisBlock::new("alice", "wonderland", &kp.public_key),
        &configuration.genesis,
        configuration.sumeragi.max_instruction_number,
    )
    .unwrap();
    let rt = Runtime::test();
    let mut client_configuration = get_client_config(&configuration.sumeragi.key_pair);

    rt.block_on(peer.start_with_config(genesis, configuration));
    thread::sleep(pipeline_time);

    client_configuration.torii_api_url = "http://".to_owned() + &peer.api_address;
    let mut iroha_client = Client::new(&client_configuration);
    iroha_client
        .submit_all(vec![
            RegisterBox::new(IdentifiableBox::from(Domain::new(DomainId::new("exchange").unwrap()))).into(),
            RegisterBox::new(IdentifiableBox::from(Domain::new(DomainId::new("company").unwrap()))).into(),
            RegisterBox::new(IdentifiableBox::from(Domain::new(DomainId::new("crypto").unwrap()))).into(),
            RegisterBox::new(IdentifiableBox::NewAccount(
                NewAccount::new(AccountId::new("seller", "company").unwrap()).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::NewAccount(
                NewAccount::new(AccountId::new("buyer", "company").unwrap()).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::NewAccount(
                NewAccount::new(AccountId::new("dex", "exchange").unwrap()).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::AssetDefinition(
                AssetDefinition::new_quantity(AssetDefinitionId::new("btc", "crypto").unwrap()).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::AssetDefinition(
                AssetDefinition::new_quantity(AssetDefinitionId::new("eth", "crypto").unwrap()).into(),
            ))
            .into(),
            RegisterBox::new(IdentifiableBox::AssetDefinition(
                AssetDefinition::new_quantity(AssetDefinitionId::new("btc2eth_rate", "exchange").unwrap())
                    .into(),
            ))
            .into(),
            MintBox::new(
                Value::U32(200),
                IdBox::AssetId(AssetId::new(
                    AssetDefinitionId::new("eth", "crypto").unwrap(),
                    AccountId::new("buyer", "company").unwrap(),
                )),
            )
            .into(),
            MintBox::new(
                Value::U32(20),
                IdBox::AssetId(AssetId::new(
                    AssetDefinitionId::new("btc", "crypto").unwrap(),
                    AccountId::new("seller", "company").unwrap(),
                )),
            )
            .into(),
            MintBox::new(
                Value::U32(20),
                IdBox::AssetId(AssetId::new(
                    AssetDefinitionId::new("btc2eth_rate", "exchange").unwrap(),
                    AccountId::new("dex", "exchange").unwrap(),
                )),
            )
            .into(),
            Pair::new(
                TransferBox::new(
                    IdBox::AssetId(AssetId::from_names("btc", "crypto", "seller", "company").unwrap()),
                    Expression::Query(
                        FindAssetQuantityById::new(AssetId::from_names(
                            "btc2eth_rate",
                            "exchange",
                            "dex",
                            "exchange",
                        ).unwrap())
                        .into(),
                    ),
                    IdBox::AssetId(AssetId::from_names("btc", "crypto", "buyer", "company").unwrap()),
                ),
                TransferBox::new(
                    IdBox::AssetId(AssetId::from_names("eth", "crypto", "buyer", "company").unwrap()),
                    Expression::Query(
                        FindAssetQuantityById::new(AssetId::from_names(
                            "btc2eth_rate",
                            "exchange",
                            "dex",
                            "exchange",
                        ).unwrap())
                        .into(),
                    ),
                    IdBox::AssetId(AssetId::from_names("eth", "crypto", "seller", "company").unwrap()),
                ),
            )
            .into(),
        ])
        .expect("Failed to execute Iroha Special Instruction.");
    thread::sleep(pipeline_time * 3);
    let expected_seller_eth = 20;
    let expected_buyer_eth = 180;
    let expected_buyer_btc = 20;

    let eth_quantity = iroha_client
        .request(FindAssetQuantityById::new(AssetId::from_names(
            "eth", "crypto", "seller", "company",
        ).unwrap()))
        .expect("Failed to execute Iroha Query");
    assert_eq!(expected_seller_eth, eth_quantity);

    // For the btc amount we expect an error, as zero assets are purged from accounts
    iroha_client
        .request(FindAssetQuantityById::new(AssetId::from_names(
            "btc", "crypto", "seller", "company",
        ).unwrap()))
        .expect_err("Failed to execute Iroha Query");

    let buyer_eth_quantity = iroha_client
        .request(FindAssetQuantityById::new(AssetId::from_names(
            "eth", "crypto", "buyer", "company",
        ).unwrap()))
        .expect("Failed to execute Iroha Query");
    assert_eq!(expected_buyer_eth, buyer_eth_quantity);

    let buyer_btc_quantity = iroha_client
        .request(FindAssetQuantityById::new(AssetId::from_names(
            "btc", "crypto", "buyer", "company",
        ).unwrap()))
        .expect("Failed to execute Iroha Query");
    assert_eq!(expected_buyer_btc, buyer_btc_quantity);
}
