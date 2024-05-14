//! Runtime Executor which copies default validation logic but forbids any queries and fails to migrate.

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::{borrow::ToOwned as _, format};

use anyhow::anyhow;
use iroha_executor::{parse, prelude::*};
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
struct Executor {
    verdict: Result,
    block_height: u64,
}

#[entrypoint]
pub fn migrate(_block_height: u64) -> MigrationResult {
    // Performing side-effects to check in the test that it won't be applied after failure

    // Registering a new domain (using ISI)
    let domain_id = parse!(DomainId, "failed_migration_test_domain");
    Register::domain(Domain::new(domain_id))
        .execute()
        .map_err(|error| {
            format!(
                "{:?}",
                anyhow!(error).context("Failed to register test domain")
            )
        })?;

    Err("This executor always fails to migrate".to_owned())
}
