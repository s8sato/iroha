//! Implementations for transaction queries.

use std::sync::Arc;

use eyre::Result;
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::{BlockHeader, SignedBlock},
    prelude::*,
    query::{dsl::CompoundPredicate, error::QueryExecutionFail, CommittedTransaction},
};
use iroha_telemetry::metrics;
use nonzero_ext::nonzero;

use super::*;
use crate::smartcontracts::ValidQuery;

/// Iterates transactions of a block in reverse order
pub(crate) struct BlockTransactionIter {
    block: Arc<SignedBlock>,
    index: usize,
    first_time_trigger_index: usize,
}

impl BlockTransactionIter {
    fn new(block: Arc<SignedBlock>) -> Self {
        let first_time_trigger_index = block.external_transactions().len();
        let last_time_trigger_index = block.results().len() - 1;

        Self {
            block,
            index: last_time_trigger_index,
            first_time_trigger_index,
        }
    }
}

impl Iterator for BlockTransactionIter {
    type Item = Self;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index != 0 {
            self.index -= 1;
            return Some(Self {
                block: Arc::clone(&self.block),
                ..*self
            });
        }

        None
    }
}

impl BlockTransactionIter {
    fn block_hash(&self) -> HashOf<BlockHeader> {
        self.block.hash()
    }

    fn entrypoint(&self) -> (HashOf<TransactionEntrypoint>, TransactionEntrypoint) {
        let entrypoint_hash = self.block.entrypoint_hashes().nth(self.index).unwrap();
        if self.index < self.first_time_trigger_index {
            let entrypoint = self
                .block
                .external_transactions()
                .nth(self.index)
                .unwrap()
                .clone();
            (entrypoint_hash, TransactionEntrypoint::External(entrypoint))
        } else {
            let entrypoint = self
                .block
                .time_triggers()
                .nth(self.index - self.first_time_trigger_index)
                .unwrap()
                .clone();
            (entrypoint_hash, TransactionEntrypoint::Time(entrypoint))
        }
    }

    fn result(&self) -> (HashOf<TransactionResult>, TransactionResult) {
        let result_hash = self.block.result_hashes().nth(self.index).unwrap();
        let result = self.block.results().nth(self.index).unwrap().clone();
        (result_hash, result)
    }
}

impl ValidQuery for FindTransactions {
    #[metrics(+"find_transactions")]
    fn execute(
        self,
        filter: CompoundPredicate<CommittedTransaction>,
        state_ro: &impl StateReadOnly,
    ) -> Result<impl Iterator<Item = Self::Item>, QueryExecutionFail> {
        Ok(state_ro
            .all_blocks(nonzero!(1_usize))
            .rev()
            .flat_map(BlockTransactionIter::new)
            .map(|iter| {
                let (entrypoint_hash, entrypoint) = iter.entrypoint();
                let (result_hash, result) = iter.result();

                CommittedTransaction {
                    block_hash: iter.block_hash(),
                    entrypoint_hash,
                    entrypoint,
                    result_hash,
                    result,
                }
            })
            .filter(move |tx| filter.applies(tx)))
    }
}
