use iroha_core::{prelude::*, state::State};
use iroha_data_model::{isi::InstructionBox, prelude::*};
use iroha_sample_params::{alias::Alias, SAMPLE_PARAMS};

#[path = "./common.rs"]
mod common;

use common::*;

pub struct StateValidateBlocks {
    state: State,
    instructions: Vec<Vec<InstructionBox>>,
    key_pair: KeyPair,
    account_id: AccountId,
}

impl StateValidateBlocks {
    /// Create [`State`] and blocks for benchmarking
    ///
    /// # Panics
    ///
    /// - Failed to parse [`AccountId`]
    /// - Failed to generate [`KeyPair`]
    /// - Failed to create instructions for block
    pub fn setup(rt: &tokio::runtime::Handle) -> Self {
        let domains = 100;
        let accounts_per_domain = 1000;
        let assets_per_domain = 1000;
        let account_id: AccountId = "alice@wonderland".parse_alias();
        let sp = &SAMPLE_PARAMS;
        let alice_keypair = sp.signatory["alice"].make_key_pair();
        let state = build_state(rt, &account_id);

        let nth = 100;
        let instructions = [
            populate_state(domains, accounts_per_domain, assets_per_domain, &account_id),
            delete_every_nth(domains, accounts_per_domain, assets_per_domain, nth),
            restore_every_nth(domains, accounts_per_domain, assets_per_domain, nth),
        ]
        .into_iter()
        .collect::<Vec<_>>();

        Self {
            state,
            instructions,
            key_pair: alice_keypair,
            account_id,
        }
    }

    /// Run benchmark body.
    ///
    /// # Errors
    /// - Not enough blocks
    /// - Failed to apply block
    ///
    /// # Panics
    /// If state height isn't updated after applying block
    pub fn measure(
        Self {
            state,
            instructions,
            key_pair,
            account_id,
        }: Self,
    ) {
        for (instructions, i) in instructions.into_iter().zip(1..) {
            let mut state_block = state.block();
            let block = create_block(
                &mut state_block,
                instructions,
                account_id.clone(),
                &key_pair,
            );
            let _events = state_block.apply_without_execution(&block);
            assert_eq!(state_block.height(), i);
            state_block.commit();
        }
    }
}
