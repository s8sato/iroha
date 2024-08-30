//! Trigger of world-level authority to enable multisig functionality for domains

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::format;

use dlmalloc::GlobalDlmalloc;
use iroha_trigger::{debug::dbg_panic, prelude::*};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

// Binary containing common logic to each domain for handling multisig accounts
const WASM: &[u8] = core::include_bytes!(concat!(core::env!("OUT_DIR"), "/multisig_accounts.wasm"));

#[iroha_trigger::main]
fn main(_id: TriggerId, _owner: AccountId, event: EventBox) {
    let domain = match event {
        EventBox::Data(DataEvent::Domain(DomainEvent::Created(domain))) => domain,
        _ => dbg_panic("should be triggered only by domain created events"),
    };

    let accounts_registry_id: TriggerId = format!("multisig_accounts_{}", domain.id())
        .parse()
        .dbg_unwrap();

    let executable = WasmSmartContract::from_compiled(WASM.to_vec());
    let accounts_registry = Trigger::new(
        accounts_registry_id.clone(),
        Action::new(
            executable,
            Repeats::Indefinitely,
            // FIXME #5022 This trigger should continue to function regardless of domain ownership changes
            domain.owned_by().clone(),
            ExecuteTriggerEventFilter::new().for_trigger(accounts_registry_id.clone()),
        ),
    );

    Register::trigger(accounts_registry)
        .execute()
        .dbg_expect("accounts registry should be successfully registered");
}
