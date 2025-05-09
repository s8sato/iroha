//! `Transaction`-related functionality of Iroha.
//!
//!
//! Types represent various stages of a `Transaction`'s lifecycle. For
//! example, `Transaction` is the start, when a transaction had been
//! received by Torii.
//!
//! This is also where the actual execution of instructions, as well
//! as various forms of validation are performed.

use std::time::{Duration, SystemTime};

use eyre::Result;
use iroha_crypto::SignatureOf;
pub use iroha_data_model::prelude::*;
use iroha_data_model::{
    isi::error::Mismatch,
    query::error::FindError,
    transaction::{error::TransactionLimitError, TransactionPayload},
};
use iroha_logger::{debug, error};
use iroha_macro::FromVariant;
use mv::storage::StorageReadOnly;

use crate::{
    smartcontracts::{wasm, wasm::cache::WasmCache},
    state::{StateBlock, StateTransaction},
};

/// `AcceptedTransaction` — a transaction accepted by Iroha peer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct AcceptedTransaction(pub(super) SignedTransaction);

/// Verification failed of some signature due to following reason
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureVerificationFail {
    /// Signature which verification has failed
    pub signature: SignatureOf<TransactionPayload>,
    /// Error which happened during verification
    pub reason: String,
}

impl core::fmt::Display for SignatureVerificationFail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Failed to verify signatures: {}", self.reason,)
    }
}

impl std::error::Error for SignatureVerificationFail {}

/// Error type for transaction from [`SignedTransaction`] to [`AcceptedTransaction`]
#[derive(Debug, displaydoc::Display, PartialEq, Eq, FromVariant, thiserror::Error)]
pub enum AcceptTransactionFail {
    /// Failure during limits check
    TransactionLimit(#[source] TransactionLimitError),
    /// Failure during signature verification
    SignatureVerification(#[source] SignatureVerificationFail),
    /// The genesis account can only sign transactions in the genesis block
    UnexpectedGenesisAccountSignature,
    /// Chain id doesn't correspond to the id of current blockchain: {0}
    ChainIdMismatch(Mismatch<ChainId>),
    /// Transaction creation time is in the future
    TransactionInTheFuture,
}

impl AcceptedTransaction {
    fn validate(
        tx: &SignedTransaction,
        expected_chain_id: &ChainId,
        max_clock_drift: Duration,
    ) -> Result<(), AcceptTransactionFail> {
        let actual_chain_id = tx.chain();

        if expected_chain_id != actual_chain_id {
            return Err(AcceptTransactionFail::ChainIdMismatch(Mismatch {
                expected: expected_chain_id.clone(),
                actual: actual_chain_id.clone(),
            }));
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        if tx.creation_time().saturating_sub(now) > max_clock_drift {
            return Err(AcceptTransactionFail::TransactionInTheFuture);
        }

        Ok(())
    }
    /// Accept genesis transaction. Transition from [`SignedTransaction`] to [`AcceptedTransaction`].
    ///
    /// # Errors
    ///
    /// - if transaction chain id doesn't match
    pub fn accept_genesis(
        tx: SignedTransaction,
        expected_chain_id: &ChainId,
        max_clock_drift: Duration,
        genesis_account: &AccountId,
    ) -> Result<Self, AcceptTransactionFail> {
        Self::validate(&tx, expected_chain_id, max_clock_drift)?;

        if genesis_account != tx.authority() {
            return Err(AcceptTransactionFail::UnexpectedGenesisAccountSignature);
        }

        Ok(Self(tx))
    }

    /// Accept transaction. Transition from [`SignedTransaction`] to [`AcceptedTransaction`].
    ///
    /// # Errors
    ///
    /// - if it does not adhere to limits
    pub fn accept(
        tx: SignedTransaction,
        expected_chain_id: &ChainId,
        max_clock_drift: Duration,
        limits: TransactionParameters,
    ) -> Result<Self, AcceptTransactionFail> {
        Self::validate(&tx, expected_chain_id, max_clock_drift)?;

        if *iroha_genesis::GENESIS_DOMAIN_ID == *tx.authority().domain() {
            return Err(AcceptTransactionFail::UnexpectedGenesisAccountSignature);
        }

        match &tx.instructions() {
            Executable::Instructions(instructions) => {
                let instruction_limit = limits
                    .max_instructions
                    .get()
                    .try_into()
                    .expect("INTERNAL BUG: max instructions exceeds usize::MAX");

                if instructions.len() > instruction_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "Too many instructions in payload, max number is {}, but got {}",
                                limits.max_instructions,
                                instructions.len()
                            ),
                        },
                    ));
                }
            }
            // TODO: Can we check the number of instructions in wasm? Because we do this check
            // when executing wasm where we deny wasm if number of instructions exceeds the limit.
            //
            // Should we allow infinite instructions in wasm? And deny only based on fuel and size
            Executable::Wasm(smart_contract) => {
                let smart_contract_size_limit = limits
                    .smart_contract_size
                    .get()
                    .try_into()
                    .expect("INTERNAL BUG: smart contract size exceeds usize::MAX");

                if smart_contract.size_bytes() > smart_contract_size_limit {
                    return Err(AcceptTransactionFail::TransactionLimit(
                        TransactionLimitError {
                            reason: format!(
                                "WASM binary size is too large: max {}, got {} \
                                (configured by \"Parameter::SmartContractLimits\")",
                                limits.smart_contract_size,
                                smart_contract.size_bytes()
                            ),
                        },
                    ));
                }
            }
        }

        Ok(Self(tx))
    }
}

impl From<AcceptedTransaction> for SignedTransaction {
    fn from(source: AcceptedTransaction) -> Self {
        source.0
    }
}

impl From<AcceptedTransaction> for (AccountId, Executable) {
    fn from(source: AcceptedTransaction) -> Self {
        source.0.into()
    }
}

impl AsRef<SignedTransaction> for AcceptedTransaction {
    fn as_ref(&self) -> &SignedTransaction {
        &self.0
    }
}

impl StateBlock<'_> {
    /// Move transaction lifecycle forward by checking if the
    /// instructions can be applied to the [`StateBlock`].
    ///
    /// Validation is skipped for genesis.
    ///
    /// # Errors
    /// Fails if validation of instruction fails (e.g. permissions mismatch).
    pub fn validate_transaction(
        &mut self,
        tx: AcceptedTransaction,
        wasm_cache: &mut WasmCache<'_, '_, '_>,
    ) -> Result<SignedTransaction, (SignedTransaction, TransactionRejectionReason)> {
        let mut state_transaction = self.transaction();
        if let Err(rejection_reason) =
            Self::validate_transaction_internal(tx.clone(), &mut state_transaction, wasm_cache)
        {
            return Err((tx.0, rejection_reason));
        }
        state_transaction.apply();

        Ok(tx.0)
    }

    fn validate_transaction_internal(
        tx: AcceptedTransaction,
        state_transaction: &mut StateTransaction<'_, '_>,
        wasm_cache: &mut WasmCache<'_, '_, '_>,
    ) -> Result<(), TransactionRejectionReason> {
        let authority = tx.as_ref().authority();

        if state_transaction.world.accounts.get(authority).is_none() {
            return Err(TransactionRejectionReason::AccountDoesNotExist(
                FindError::Account(authority.clone()),
            ));
        }

        debug!(tx=%tx.as_ref().hash(), "Validating transaction");
        Self::validate_transaction_with_runtime_executor(
            tx.clone(),
            state_transaction,
            wasm_cache,
        )?;

        if let (authority, Executable::Wasm(bytes)) = tx.into() {
            Self::validate_wasm(authority, state_transaction, bytes)?
        }

        debug!("Transaction validated successfully; processing data triggers");
        state_transaction.execute_data_triggers_dfs()?;
        debug!("Data triggers executed successfully");

        Ok(())
    }

    fn validate_wasm(
        authority: AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
        wasm: WasmSmartContract,
    ) -> Result<(), TransactionRejectionReason> {
        debug!("Validating wasm");

        wasm::RuntimeBuilder::<wasm::state::SmartContract>::new()
            .build()
            .and_then(|mut wasm_runtime| {
                wasm_runtime.validate(
                    state_transaction,
                    authority,
                    wasm,
                    state_transaction
                        .world
                        .parameters
                        .transaction
                        .max_instructions,
                )
            })
            .map_err(|error| WasmExecutionFail {
                reason: format!("{:?}", eyre::Report::from(error)),
            })
            .map_err(TransactionRejectionReason::WasmExecution)
    }

    /// Validate transaction with runtime executors.
    ///
    /// Note: transaction instructions will be executed on the given `state_transaction`.
    fn validate_transaction_with_runtime_executor(
        tx: AcceptedTransaction,
        state_transaction: &mut StateTransaction<'_, '_>,
        wasm_cache: &mut WasmCache<'_, '_, '_>,
    ) -> Result<(), TransactionRejectionReason> {
        let tx: SignedTransaction = tx.into();
        let authority = tx.authority().clone();

        state_transaction
            .world
            .executor
            .clone() // Cloning executor is a cheap operation
            .execute_transaction(state_transaction, &authority, tx, wasm_cache)
            .map_err(|error| {
                if let ValidationFail::InternalError(msg) = &error {
                    error!(
                        error = msg,
                        "Internal error occurred during transaction validation, \
                         is Runtime Executor correct?"
                    )
                }
                error.into()
            })
    }
}

#[cfg(test)]
mod tests {
    use iroha_data_model::prelude::EventBox;

    use crate::state::{State, StateBlock};

    /// The origin that initiates a chain of data triggers.
    enum TriggerOrigin {
        /// A user-submitted transaction.
        ExternalTransaction,
        /// A scheduled time-based trigger.
        TimeTrigger,
    }

    mod time_trigger {
        use super::*;

        /// # Scenario
        ///
        /// 1. Transaction transfers an asset from Alice to Bob.
        /// 2. Data trigger fires and transfers the asset from Bob to Carol.
        /// 3. Time trigger should fire and transfer the asset from Carol to Dave.
        /// 4. Data trigger should fire and transfer the asset from Dave to Eve.
        #[test]
        fn fires_after_external_transactions() {
            let sandbox = Sandbox::new()
                .with_data_trigger("bob", "carol")
                .with_time_trigger("carol", "dave")
                .with_data_trigger("dave", "eve");
            let mut block = sandbox.block();
            block.batched_transfer(1, "alice", "bob");
            let events = block.apply();
            dbg!(&events);
            block.assert_balances([
                ("alice", 9),
                ("bob", 0),
                ("carol", 0),
                ("dave", 0),
                ("eve", 1),
            ]);
        }
    }

    mod data_trigger {
        use super::*;

        /// # Scenario
        ///
        /// 1. Transaction transfers an asset from Alice to Bob.
        /// 2. Trigger should fire and transfer the asset from Bob to Carol.
        /// 3. Transaction should transfer the asset from Carol to Dave.
        #[test]
        fn fires_for_each_transaction() {
            let sandbox = Sandbox::new().with_data_trigger("bob", "carol");
            let mut block = sandbox.block();
            block.batched_transfer(1, "alice", "bob");
            block.batched_transfer(1, "carol", "dave");
            let events = block.apply();
            dbg!(&events);
            block.assert_balances([("alice", 9), ("bob", 0), ("carol", 0), ("dave", 1)]);
        }

        /// # Scenario
        ///
        /// 1. Transaction transfers an asset from Alice to Bob twice.
        /// 2. Trigger should fire once and transfer one from Bob to Carol.
        #[test]
        fn fires_at_most_once_per_transaction() {
            let sandbox = Sandbox::new().with_data_trigger("bob", "carol");
            let mut block = sandbox.block();
            block.batched_transfer(2, "alice", "bob");
            let events = block.apply();
            dbg!(&events);
            block.assert_balances([("alice", 8), ("bob", 1), ("carol", 1)]);
        }

        /// All or none of the initial transaction and subsequent data triggers should take effect.
        #[test]
        fn atomically_chains_from_transaction() {
            aborts_on_execution_error(TriggerOrigin::ExternalTransaction);
            aborts_on_depleting_lives(TriggerOrigin::ExternalTransaction);
            aborts_on_exceeding_depth(TriggerOrigin::ExternalTransaction);
            commits_on_success(TriggerOrigin::ExternalTransaction);
        }

        /// All or none of the initial time trigger and subsequent data triggers should take effect.
        #[test]
        fn atomically_chains_from_time_trigger() {
            aborts_on_execution_error(TriggerOrigin::TimeTrigger);
            aborts_on_depleting_lives(TriggerOrigin::TimeTrigger);
            aborts_on_exceeding_depth(TriggerOrigin::TimeTrigger);
            commits_on_success(TriggerOrigin::TimeTrigger);
        }

        fn aborts_on_execution_error(origin: TriggerOrigin) {
            let mut sandbox = Sandbox::new()
                .with_data_trigger("bob", "carol")
                .with_data_trigger("carol", "dave")
                // This trigger execution fails.
                .with_data_trigger("dave", "john_doe");
            if let TriggerOrigin::TimeTrigger = origin {
                sandbox = sandbox.with_time_trigger("alice", "bob");
            }
            let mut block = sandbox.block();
            if let TriggerOrigin::ExternalTransaction = origin {
                block.batched_transfer(1, "alice", "bob");
            }
            let events = block.apply();
            dbg!(&events);
            // Everything should be rolled back.
            block.assert_balances([("alice", 10), ("bob", 0), ("carol", 0), ("dave", 0)]);
        }

        fn aborts_on_depleting_lives(origin: TriggerOrigin) {
            let mut sandbox = Sandbox::new()
                .with_data_trigger("bob", "carol")
                .with_data_trigger("carol", "dave")
                // This trigger depletes after a loop.
                .with_data_trigger_limited("dave", "bob", 2);
            if let TriggerOrigin::TimeTrigger = origin {
                sandbox = sandbox.with_time_trigger("alice", "bob");
            }
            let mut block = sandbox.block();
            if let TriggerOrigin::ExternalTransaction = origin {
                block.batched_transfer(1, "alice", "bob");
            }
            let events = block.apply();
            dbg!(&events);
            // Everything should be rolled back.
            block.assert_balances([("alice", 10), ("bob", 0), ("carol", 0), ("dave", 0)]);
        }

        fn aborts_on_exceeding_depth(origin: TriggerOrigin) {
            let mut sandbox = Sandbox::new()
                .with_max_execution_depth(2)
                .with_data_trigger("bob", "carol")
                .with_data_trigger("carol", "dave")
                // The execution sequence exceeds the depth limit.
                .with_data_trigger("dave", "eve");
            if let TriggerOrigin::TimeTrigger = origin {
                sandbox = sandbox.with_time_trigger("alice", "bob");
            }
            let mut block = sandbox.block();
            if let TriggerOrigin::ExternalTransaction = origin {
                block.batched_transfer(1, "alice", "bob");
            }
            let events = block.apply();
            dbg!(&events);
            // Everything should be rolled back.
            block.assert_balances([("alice", 10), ("bob", 0), ("carol", 0), ("dave", 0)]);
        }

        fn commits_on_success(origin: TriggerOrigin) {
            let mut sandbox = Sandbox::new()
                .with_data_trigger("bob", "carol")
                .with_data_trigger("carol", "dave")
                .with_data_trigger("dave", "eve");
            if let TriggerOrigin::TimeTrigger = origin {
                sandbox = sandbox.with_time_trigger("alice", "bob");
            }
            let mut block = sandbox.block();
            if let TriggerOrigin::ExternalTransaction = origin {
                block.batched_transfer(1, "alice", "bob");
            }
            let events = block.apply();
            dbg!(&events);
            // The execution sequence should take effect.
            block.assert_balances([
                ("alice", 9),
                ("bob", 0),
                ("carol", 0),
                ("dave", 0),
                ("eve", 1),
            ]);
        }
    }

    type AccountBalances = std::collections::HashMap<&'static str, u32>;

    struct Sandbox(State);

    struct SandboxBlock<'state>(StateBlock<'state>);

    impl Sandbox {
        const DOMAIN: &'static str = "wonderland";
        const ASSET: &'static str = "rose";
        const ACCOUNTS: [&'static str; 5] = ["alice", "bob", "carol", "dave", "eve"];

        fn new() -> Self {
            todo!()
        }

        fn with_time_trigger(self, src: &str, dest: &str) -> Self {
            todo!()
        }

        fn with_data_trigger(self, src: &str, dest: &str) -> Self {
            todo!()
        }

        fn with_data_trigger_limited(self, src: &str, dest: &str, repeats: u32) -> Self {
            todo!()
        }

        fn with_max_execution_depth(self, depth: u8) -> Self {
            todo!()
        }

        fn block(&self) -> SandboxBlock<'_> {
            todo!()
        }
    }

    impl SandboxBlock<'_> {
        fn batched_transfer(&mut self, repeats: u32, src: &str, dest: &str) {
            todo!()
        }

        fn apply(&mut self) -> Vec<EventBox> {
            todo!()
        }

        fn assert_balances(&self, balances: impl Into<AccountBalances>) {
            todo!()
        }
    }
}
