//! Runtime Executor which allows any instruction executed by `admin@admin` account.
//! If authority is not `admin@admin` then default validation is used as a backup.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use iroha_executor::{parse, prelude::*};
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
#[visit(custom(visit_instruction))]
struct Executor {
    verdict: Result,
    block_height: u64,
}

fn visit_instruction(executor: &mut Executor, authority: &AccountId, isi: &InstructionBox) {
    if parse!("ed012076E5CA9698296AF9BE2CA45F525CB3BCFDEB7EE068BA56F973E9DD90564EF4FC@admin" as AccountId) == *authority {
        execute!(executor, isi);
    }

    iroha_executor::default::visit_instruction(executor, authority, isi);
}

#[entrypoint]
pub fn migrate(_block_height: u64) -> MigrationResult {
    Ok(())
}
