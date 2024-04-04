use std::{str::FromStr as _, sync::mpsc, thread, time::Duration};

use eyre::{eyre, Result, WrapErr};
use iroha_client::{
    client::{self, Client},
    data_model::{
        prelude::*,
        query::error::{FindError, QueryExecutionFail},
        transaction::{Executable, WasmSmartContract},
    },
};
use iroha_genesis::GenesisNetwork;
use iroha_logger::info;
use iroha_sample_params::alias::Alias;
use test_network::*;

const TRIGGER_NAME: &str = "mint_rose";

#[test]
fn call_execute_trigger() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_005).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = "alice@wonderland".parse_alias();
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let prev_value = get_asset_value(&mut test_client, asset_id.clone());

    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = build_register_trigger_isi(asset_id.clone(), vec![instruction.into()]);
    test_client.submit_blocking(register_trigger)?;

    let trigger_id = TriggerId::from_str(TRIGGER_NAME)?;
    let call_trigger = ExecuteTrigger::new(trigger_id);
    test_client.submit_blocking(call_trigger)?;

    let new_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());

    Ok(())
}

#[test]
fn execute_trigger_should_produce_event() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_010).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id: AccountId = "alice@wonderland".parse_alias();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = build_register_trigger_isi(asset_id, vec![instruction.into()]);
    test_client.submit_blocking(register_trigger)?;

    let trigger_id = TriggerId::from_str(TRIGGER_NAME)?;
    let call_trigger = ExecuteTrigger::new(trigger_id.clone());

    let thread_client = test_client.clone();
    let (sender, receiver) = mpsc::channel();
    let _handle = thread::spawn(move || -> Result<()> {
        let mut event_it = thread_client.listen_for_events(
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id)
                .under_authority(account_id),
        )?;
        if event_it.next().is_some() {
            sender.send(())?;
            return Ok(());
        }
        Err(eyre!("No events emitted"))
    });

    test_client.submit(call_trigger)?;

    receiver
        .recv_timeout(Duration::from_secs(60))
        .wrap_err("Failed to receive event message")
}

#[test]
fn infinite_recursion_should_produce_one_call_per_block() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_015).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = "alice@wonderland".parse_alias();
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let trigger_id = TriggerId::from_str(TRIGGER_NAME)?;
    let call_trigger = ExecuteTrigger::new(trigger_id);
    let prev_value = get_asset_value(&mut test_client, asset_id.clone());

    let instructions = vec![
        Mint::asset_numeric(1u32, asset_id.clone()).into(),
        call_trigger.clone().into(),
    ];
    let register_trigger = build_register_trigger_isi(asset_id.clone(), instructions);
    test_client.submit_blocking(register_trigger)?;

    test_client.submit_blocking(call_trigger)?;

    let new_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());

    Ok(())
}

#[test]
fn trigger_failure_should_not_cancel_other_triggers_execution() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_020).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id: AccountId = "alice@wonderland".parse_alias();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    // Registering trigger that should fail on execution
    let bad_trigger_id = TriggerId::from_str("bad_trigger")?;
    // Invalid instruction
    let bad_trigger_instructions = vec![Fail::new("Bad trigger".to_owned())];
    let register_bad_trigger = Register::trigger(Trigger::new(
        bad_trigger_id.clone(),
        Action::new(
            bad_trigger_instructions,
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(bad_trigger_id.clone())
                .under_authority(account_id.clone()),
        ),
    ));
    test_client.submit(register_bad_trigger)?;

    // Registering normal trigger
    let trigger_id = TriggerId::from_str(TRIGGER_NAME)?;
    let trigger_instructions = vec![Mint::asset_numeric(1u32, asset_id.clone())];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id,
        Action::new(
            trigger_instructions,
            Repeats::Indefinitely,
            account_id,
            // Time-triggers (which are Pre-commit triggers) will be executed last
            TimeEventFilter::new(ExecutionTime::PreCommit),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&mut test_client, asset_id.clone());

    // Executing bad trigger
    test_client.submit_blocking(ExecuteTrigger::new(bad_trigger_id))?;

    // Checking results
    let new_asset_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(
        new_asset_value,
        prev_asset_value.checked_add(Numeric::ONE).unwrap()
    );
    Ok(())
}

#[test]
fn trigger_should_not_be_executed_with_zero_repeats_count() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_025).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id: AccountId = "alice@wonderland".parse_alias();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id = TriggerId::from_str("self_modifying_trigger")?;

    let trigger_instructions = vec![Mint::asset_numeric(1u32, asset_id.clone())];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            Repeats::from(1_u32),
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&mut test_client, asset_id.clone());

    // Executing trigger first time
    let execute_trigger = ExecuteTrigger::new(trigger_id.clone());
    test_client.submit_blocking(execute_trigger.clone())?;

    // Executing trigger second time

    // NOTE: Keep this for debugging purposes
    // let error = test_client
    //     .submit_blocking(execute_trigger)
    //     .expect_err("Error expected");
    // iroha_logger::info!(?error);

    assert!(matches!(
        test_client
            .submit_blocking(execute_trigger)
            .expect_err("Error expected")
            .chain()
            .last()
            .expect("At least two error causes expected")
            .downcast_ref::<QueryExecutionFail>(),
        Some(QueryExecutionFail::Find(FindError::Trigger(id))) if *id == trigger_id
    ));

    // Checking results
    let new_asset_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(
        new_asset_value,
        prev_asset_value.checked_add(Numeric::ONE).unwrap()
    );

    Ok(())
}

#[test]
fn trigger_should_be_able_to_modify_its_own_repeats_count() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_030).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id: AccountId = "alice@wonderland".parse_alias();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id = TriggerId::from_str("self_modifying_trigger")?;

    let trigger_instructions = vec![
        InstructionBox::from(Mint::trigger_repetitions(1_u32, trigger_id.clone())),
        InstructionBox::from(Mint::asset_numeric(1u32, asset_id.clone())),
    ];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            Repeats::from(1_u32),
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&mut test_client, asset_id.clone());

    // Executing trigger first time
    let execute_trigger = ExecuteTrigger::new(trigger_id);
    test_client.submit_blocking(execute_trigger.clone())?;

    // Executing trigger second time
    test_client.submit_blocking(execute_trigger)?;

    // Checking results
    let new_asset_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(
        new_asset_value,
        prev_asset_value.checked_add(numeric!(2)).unwrap()
    );

    Ok(())
}

#[test]
fn unregister_trigger() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_035).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let account_id: AccountId = "alice@wonderland".parse_alias();

    // Registering trigger
    let trigger_id = TriggerId::from_str("empty_trigger")?;
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            Vec::<InstructionBox>::new(),
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    );
    let register_trigger = Register::trigger(trigger.clone());
    test_client.submit_blocking(register_trigger)?;

    // Finding trigger
    let find_trigger = FindTriggerById {
        id: trigger_id.clone(),
    };
    let found_trigger = test_client.request(find_trigger.clone())?;
    let found_action = found_trigger.action;
    let Executable::Instructions(found_instructions) = found_action.executable else {
        panic!("Expected instructions");
    };
    let found_trigger = Trigger::new(
        found_trigger.id,
        Action::new(
            Executable::Instructions(found_instructions),
            found_action.repeats,
            found_action.authority,
            found_action.filter,
        ),
    );
    assert_eq!(found_trigger, trigger);

    // Unregistering trigger
    let unregister_trigger = Unregister::trigger(trigger_id);
    test_client.submit_blocking(unregister_trigger)?;

    // Checking result
    assert!(test_client.request(find_trigger).is_err());

    Ok(())
}

/// Register wasm-trigger in genesis and execute it.
///
/// Not very representable from end-user point of view.
/// It's the problem of all ours *"integration"* tests that they are not really
/// integration.
/// Here it's easier to use the approach with `GenesisNetwork::test()` function
/// and extra isi insertion instead of a hardcoded genesis config.
/// This allows to not to update the hardcoded genesis every time
/// instructions/genesis API is changing.
///
/// Despite this simplification this test should really check
/// if we have the ability to pass a base64-encoded WASM trigger in the genesis.
#[test]
fn trigger_in_genesis_using_base64() -> Result<()> {
    // Building wasm trigger

    info!("Building trigger");
    let wasm =
        iroha_wasm_builder::Builder::new("tests/integration/smartcontracts/mint_rose_trigger")
            .show_output()
            .build()?
            .optimize()?
            .into_bytes()?;

    info!("WASM size is {} bytes", wasm.len());

    let engine = base64::engine::general_purpose::STANDARD;
    let wasm_base64 = serde_json::json!(base64::engine::Engine::encode(&engine, wasm)).to_string();
    let account_id: AccountId = "alice@wonderland".parse_alias();
    let trigger_id = TriggerId::from_str("genesis_trigger")?;

    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            serde_json::from_str::<WasmSmartContract>(&wasm_base64)
                .wrap_err("Can't deserialize wasm using base64")?,
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id.clone()),
        ),
    );

    // Registering trigger in genesis
    let genesis = GenesisNetwork::test_with_instructions([Register::trigger(trigger).into()]);

    let (_rt, _peer, mut test_client) = <PeerBuilder>::new()
        .with_genesis(genesis)
        .with_port(10_040)
        .start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let prev_value = get_asset_value(&mut test_client, asset_id.clone());

    // Executing trigger
    let call_trigger = ExecuteTrigger::new(trigger_id);
    test_client.submit_blocking(call_trigger)?;

    // Checking result
    let new_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());

    Ok(())
}

#[test]
fn trigger_should_be_able_to_modify_other_trigger() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_085).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id: AccountId = "alice@wonderland".parse_alias();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id_unregister = TriggerId::from_str("unregister_other_trigger")?;
    let trigger_id_to_be_unregistered = TriggerId::from_str("should_be_unregistered_trigger")?;

    let trigger_unregister_instructions =
        vec![Unregister::trigger(trigger_id_to_be_unregistered.clone())];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id_unregister.clone(),
        Action::new(
            trigger_unregister_instructions,
            Repeats::from(1_u32),
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id_unregister.clone())
                .under_authority(account_id.clone()),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    let trigger_should_be_unregistered_instructions =
        vec![Mint::asset_numeric(1u32, asset_id.clone())];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id_to_be_unregistered.clone(),
        Action::new(
            trigger_should_be_unregistered_instructions,
            Repeats::from(1_u32),
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id_to_be_unregistered.clone())
                .under_authority(account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&mut test_client, asset_id.clone());

    // Executing triggers
    let execute_trigger_unregister = ExecuteTrigger::new(trigger_id_unregister);
    let execute_trigger_should_be_unregistered = ExecuteTrigger::new(trigger_id_to_be_unregistered);
    test_client.submit_all_blocking([
        execute_trigger_unregister,
        execute_trigger_should_be_unregistered,
    ])?;

    // Checking results
    // First trigger should cancel second one, so value should stay the same
    let new_asset_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(new_asset_value, prev_asset_value);

    Ok(())
}

#[test]
fn trigger_burn_repetitions() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_070).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id: AccountId = "alice@wonderland".parse_alias();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id = TriggerId::from_str("trigger")?;

    let trigger_instructions = vec![Mint::asset_numeric(1u32, asset_id)];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            Repeats::from(1_u32),
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    test_client.submit_blocking(Burn::trigger_repetitions(1_u32, trigger_id.clone()))?;

    // Executing trigger
    let execute_trigger = ExecuteTrigger::new(trigger_id);
    let _err = test_client
        .submit_blocking(execute_trigger)
        .expect_err("Should fail without repetitions");

    Ok(())
}

#[test]
fn unregistering_one_of_two_triggers_with_identical_wasm_should_not_cause_original_wasm_loss(
) -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_105).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let account_id: AccountId = "alice@wonderland".parse_alias();
    let first_trigger_id = TriggerId::from_str("mint_rose_1")?;
    let second_trigger_id = TriggerId::from_str("mint_rose_2")?;

    let wasm =
        iroha_wasm_builder::Builder::new("tests/integration/smartcontracts/mint_rose_trigger")
            .show_output()
            .build()?
            .optimize()?
            .into_bytes()?;
    let wasm = WasmSmartContract::from_compiled(wasm);

    let build_trigger = |trigger_id: TriggerId| {
        Trigger::new(
            trigger_id.clone(),
            Action::new(
                wasm.clone(),
                Repeats::Indefinitely,
                account_id.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id)
                    .under_authority(account_id.clone()),
            ),
        )
    };

    let first_trigger = build_trigger(first_trigger_id.clone());
    let second_trigger = build_trigger(second_trigger_id.clone());

    test_client.submit_all_blocking([
        Register::trigger(first_trigger),
        Register::trigger(second_trigger.clone()),
    ])?;

    test_client.submit_blocking(Unregister::trigger(first_trigger_id))?;
    let got_second_trigger = test_client
        .request(FindTriggerById {
            id: second_trigger_id,
        })
        .expect("Failed to request second trigger");

    assert_eq!(got_second_trigger, second_trigger);

    Ok(())
}

fn get_asset_value(client: &mut Client, asset_id: AssetId) -> Numeric {
    let asset = client.request(client::asset::by_id(asset_id)).unwrap();

    let AssetValue::Numeric(val) = *asset.value() else {
        panic!("Unexpected asset value");
    };

    val
}

fn build_register_trigger_isi(
    asset_id: AssetId,
    trigger_instructions: Vec<InstructionBox>,
) -> Register<Trigger> {
    let trigger_id: TriggerId = TRIGGER_NAME.parse().expect("Valid");

    Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            Repeats::Indefinitely,
            asset_id.account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id)
                .under_authority(asset_id.account_id),
        ),
    ))
}
