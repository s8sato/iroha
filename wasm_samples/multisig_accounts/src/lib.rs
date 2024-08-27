//! Trigger given per domain to control multi-signature accounts and corresponding triggers

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::format;

use dlmalloc::GlobalDlmalloc;
use executor_custom_data_model::multisig::MultisigAccountArgs;
use iroha_executor_data_model::permission::trigger::CanExecuteTrigger;
use iroha_trigger::{debug::dbg_panic, prelude::*};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

// Binary containing common logic to each multisig account for handling multisig transactions
const WASM: &[u8] = core::include_bytes!(concat!(
    core::env!("OUT_DIR"),
    "/multisig_transactions.wasm"
));

#[iroha_trigger::main]
fn main(_id: TriggerId, owner: AccountId, event: EventBox) {
    let args: MultisigAccountArgs = match event {
        EventBox::ExecuteTrigger(event) => event
            .args()
            .dbg_expect("trigger expect args")
            .try_into_any()
            .dbg_expect("failed to parse args"),
        _ => dbg_panic("Only work as by call trigger"),
    };

    let account_id = args.account.id().clone();

    Register::account(args.account.clone())
        .execute()
        .dbg_expect("failed to register multisig account");

    let multisig_transactions_registry_id: TriggerId = format!(
        "multisig_transactions_{}_{}",
        account_id.signatory(),
        account_id.domain()
    )
    .parse()
    .dbg_expect("failed to parse trigger id");

    let executable = WasmSmartContract::from_compiled(WASM.to_vec());
    let multisig_transactions_registry = Trigger::new(
        multisig_transactions_registry_id.clone(),
        Action::new(
            executable,
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new().for_trigger(multisig_transactions_registry_id.clone()),
        ),
    );

    Register::trigger(multisig_transactions_registry)
        .execute()
        .dbg_expect("failed to register multisig transactions registry");

    let role_id: RoleId = format!(
        "multisig_signatory_{}_{}",
        account_id.signatory(),
        account_id.domain()
    )
    .parse()
    .dbg_expect("failed to parse role");

    let can_execute_multisig_transactions_registry = CanExecuteTrigger {
        trigger: multisig_transactions_registry_id.clone(),
    };

    Register::role(
        // Temporarily grant a multisig role to the trigger authority to propagate the role to the signatories
        Role::new(role_id.clone(), owner.clone())
            .add_permission(can_execute_multisig_transactions_registry),
    )
    .execute()
    .dbg_expect("failed to register multisig role");

    SetKeyValue::trigger(
        multisig_transactions_registry_id,
        "signatories".parse().unwrap(),
        JsonString::new(&args.signatories),
    )
    .execute()
    .dbg_unwrap();

    for signatory in args.signatories {
        Grant::account_role(role_id.clone(), signatory)
            .execute()
            .dbg_expect("failed to grant multisig role to account");
    }

    Revoke::account_role(role_id.clone(), owner)
        .execute()
        .dbg_expect("failed to revoke multisig role from owner");
}
