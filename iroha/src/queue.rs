//! Module with queue actor // SATO no longer actor?

use std::time::Duration;

use crossbeam_queue::ArrayQueue;
use dashmap::{mapref::entry::Entry, DashMap};
use eyre::{Report, Result};
use thiserror::Error;

use self::config::QueueConfiguration;
use crate::{prelude::*, wsv::WorldTrait};

/// Lockfree queue for transactions
///
/// Multiple producers, single consumer
#[derive(Debug)]
pub struct Queue {
    queue: ArrayQueue<Hash>,
    txs: DashMap<Hash, VersionedAcceptedTransaction>,
    /// Length of dashmap.
    ///
    /// DashMap right now just iterates over itself and calculates its length like this:
    /// self.txs.iter().len()
    txs_in_block: usize,
    max_txs: usize,
    ttl: Duration,
}

/// Queue push error
#[derive(Error, Debug)]
pub enum Error {
    /// Queue is full
    #[error("Queue is full")]
    Full,
    /// Transaction expired
    #[error("Transaction is expired")]
    Expired,
    /// Transaction is already in blockchain
    #[error("Transaction is already applied")]
    InBlockchain,
    /// Signature condition check failed
    #[error("Failure during signature condition execution")]
    SignatureCondition(
        #[from]
        #[source]
        Report,
    ),
}

// SATO Queue<W: WorldTrait>
impl Queue {
    /// Makes queue from configuration
    pub fn from_configuration(cfg: &QueueConfiguration) -> Self {
        Self {
            queue: ArrayQueue::new(cfg.maximum_transactions_in_queue as usize),
            txs: DashMap::new(),
            max_txs: cfg.maximum_transactions_in_queue as usize,
            txs_in_block: cfg.maximum_transactions_in_block as usize,
            ttl: Duration::from_millis(cfg.transaction_time_to_live_ms),
        }
    }

    fn is_pending<W: WorldTrait>(
        &self,
        tx: &VersionedAcceptedTransaction,
        wsv: &WorldStateView<W>,
    ) -> bool {
        !tx.is_expired(self.ttl) && !tx.is_in_blockchain(wsv)
    }

    /// Returns all pending transactions.
    pub fn all_transactions<W: WorldTrait>(
        &self,
        wsv: &WorldStateView<W>,
    ) -> Vec<VersionedAcceptedTransaction> {
        self.txs
            .iter()
            .filter(|e| self.is_pending(e.value(), wsv))
            .map(|e| e.value().clone())
            .collect()
    }

    fn check_tx<W: WorldTrait>(
        &self,
        tx: &VersionedAcceptedTransaction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        if tx.is_expired(self.ttl) {
            return Err(Error::Expired);
        }
        if tx.is_in_blockchain(wsv) {
            return Err(Error::InBlockchain);
        }
        tx.check_signature_condition(wsv)?;
        Ok(())
    }

    /// Pushes transaction into queue.
    ///
    /// # Errors
    /// See [`Error`]
    #[allow(
        clippy::unwrap_in_result,
        clippy::expect_used,
        clippy::missing_panics_doc
    )]
    pub fn push<W: WorldTrait>(
        &self,
        tx: VersionedAcceptedTransaction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), (VersionedAcceptedTransaction, Error)> {
        if let Err(e) = self.check_tx(&tx, wsv) {
            return Err((tx, e));
        }
        if self.txs.len() >= self.max_txs {
            return Err((tx, Error::Full));
        }

        let hash = tx.hash();
        let entry = match self.txs.entry(hash) {
            Entry::Occupied(mut old_tx) => {
                // MST case
                old_tx
                    .get_mut()
                    .as_mut_inner_v1()
                    .signatures
                    .append(&mut tx.into_inner_v1().signatures);
                return Ok(());
            }
            Entry::Vacant(entry) => entry,
        };

        entry.insert(tx);

        if let Err(hash) = self.queue.push(hash) {
            let (_, tx) = self.txs.remove(&hash).expect("Inserted just before match");
            return Err((tx, Error::Full));
        }
        Ok(())
    }

    /// Pops single transaction.
    ///
    /// Records unsigned transaction in seen.
    #[allow(
        clippy::expect_used,
        clippy::unwrap_in_result,
        clippy::cognitive_complexity
    )]
    fn pop<W: WorldTrait>(
        &self,
        wsv: &WorldStateView<W>,
        seen: &mut Vec<Hash>,
    ) -> Option<VersionedAcceptedTransaction> {
        loop {
            let hash = self.queue.pop()?;
            let entry = match self.txs.entry(hash) {
                Entry::Occupied(entry) => entry,
                // As practice shows this code is not `unreachable!()`.
                // When transactions are submitted quickly it can be reached.
                Entry::Vacant(_) => continue,
            };
            if self.check_tx(entry.get(), wsv).is_err() {
                entry.remove_entry();
                continue;
            }

            seen.push(hash);

            if entry
                .get()
                .check_signature_condition(wsv)
                .expect("Checked in `check_tx` just above")
            {
                return Some(entry.get().clone());
            }
        }
    }

    /// Gets transactions till they fill whole block or till the end of queue.
    ///
    /// BEWARE: Shouldn't be called in parallel with itself.
    #[allow(clippy::missing_panics_doc, clippy::unwrap_in_result)]
    pub fn get_transactions_for_block<W: WorldTrait>(
        &self,
        wsv: &WorldStateView<W>,
    ) -> Vec<VersionedAcceptedTransaction> {
        let mut seen = Vec::new();

        let out = std::iter::repeat_with(|| self.pop(wsv, &mut seen))
            .take_while(Option::is_some)
            .map(Option::unwrap)
            .take(self.txs_in_block)
            .collect::<Vec<_>>();

        #[allow(clippy::expect_used)]
        seen.into_iter()
            .try_for_each(|hash| self.queue.push(hash))
            .expect("As we never exceed the number of transactions pending");
        out
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use serde::{Deserialize, Serialize};

    const DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 2_u32.pow(13);
    // 24 hours
    const DEFAULT_TRANSACTION_TIME_TO_LIVE_MS: u64 = 24 * 60 * 60 * 1000;
    const DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE: u32 = 2_u32.pow(16);

    /// Configuration for `Queue`.
    #[derive(Copy, Clone, Deserialize, Serialize, Debug, Configurable)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(default)]
    #[config(env_prefix = "QUEUE_")]
    pub struct QueueConfiguration {
        /// The upper limit of the number of transactions per block.
        pub maximum_transactions_in_block: u32,
        /// The upper limit of the number of transactions waiting in this queue.
        pub maximum_transactions_in_queue: u32,
        /// The transaction will be dropped after this time if it is still in a `Queue`.
        pub transaction_time_to_live_ms: u64,
    }

    impl Default for QueueConfiguration {
        fn default() -> Self {
            Self {
                maximum_transactions_in_block: DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK,
                maximum_transactions_in_queue: DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE,
                transaction_time_to_live_ms: DEFAULT_TRANSACTION_TIME_TO_LIVE_MS,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction, clippy::all, clippy::pedantic)]

    use std::{
        iter,
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };

    use iroha_data_model::{domain::DomainsMap, peer::PeersIds, prelude::*};
    use rand::Rng;

    use super::*;
    use crate::wsv::World;

    fn accepted_tx(
        account: &str,
        domain: &str,
        proposed_ttl_ms: u64,
        key: Option<&KeyPair>,
    ) -> VersionedAcceptedTransaction {
        let key = key
            .cloned()
            .unwrap_or_else(|| KeyPair::generate().expect("Failed to generate keypair."));

        let message = std::iter::repeat_with(rand::random::<char>)
            .take(16)
            .collect();
        let tx = Transaction::new(
            vec![FailBox { message }.into()],
            <Account as Identifiable>::Id::new(account, domain),
            proposed_ttl_ms,
        )
        .sign(&key)
        .expect("Failed to sign.");
        VersionedAcceptedTransaction::from_transaction(tx, 4096)
            .expect("Failed to accept Transaction.")
    }

    pub fn world_with_test_domains(public_key: PublicKey) -> World {
        let domains = DomainsMap::new();
        let mut domain = Domain::new("wonderland");
        let account_id = AccountId::new("alice", "wonderland");
        let mut account = Account::new(account_id.clone());
        account.signatories.push(public_key);
        domain.accounts.insert(account_id, account);
        domains.insert("wonderland".to_string(), domain);
        World::with(domains, PeersIds::new())
    }

    #[test]
    fn push_tx() {
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
        });
        let wsv = WorldStateView::new(world_with_test_domains(
            KeyPair::generate().unwrap().public_key,
        ));

        queue
            .push(accepted_tx("alice", "wonderland", 100_000, None), &wsv)
            .expect("Failed to push tx into queue");
    }

    #[test]
    fn push_tx_overflow() {
        let max_txs_in_queue = 10;
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: max_txs_in_queue,
        });
        let wsv = WorldStateView::new(world_with_test_domains(
            KeyPair::generate().unwrap().public_key,
        ));

        for _ in 0..max_txs_in_queue {
            queue
                .push(accepted_tx("alice", "wonderland", 100_000, None), &wsv)
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        assert!(matches!(
            queue.push(accepted_tx("alice", "wonderland", 100_000, None), &wsv),
            Err((_, Error::Full))
        ));
    }

    #[test]
    fn push_tx_signature_condition_failure() {
        let max_txs_in_queue = 10;
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: max_txs_in_queue,
        });
        let wsv = WorldStateView::new(world_with_test_domains(
            KeyPair::generate().unwrap().public_key,
        ));
        let mut domain = wsv.domain_mut("wonderland").unwrap();
        domain
            .accounts
            .get_mut(&<Account as Identifiable>::Id::new("alice", "wonderland"))
            .unwrap()
            .signature_check_condition = SignatureCheckCondition(0_u32.into());
        drop(domain);

        assert!(matches!(
            queue.push(accepted_tx("alice", "wonderland", 100_000, None), &wsv),
            Err((_, Error::SignatureCondition(_)))
        ));
    }

    #[test]
    fn push_multisignature_tx() {
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
        });
        let tx = Transaction::new(
            Vec::new(),
            <Account as Identifiable>::Id::new("alice", "wonderland"),
            100_000,
        );
        let get_tx = || {
            VersionedAcceptedTransaction::from_transaction(
                tx.clone()
                    .sign(&KeyPair::generate().expect("Failed to generate keypair."))
                    .expect("Failed to sign."),
                4096,
            )
            .expect("Failed to accept Transaction.")
        };
        let wsv = WorldStateView::new(world_with_test_domains(
            KeyPair::generate().unwrap().public_key,
        ));

        queue.push(get_tx(), &wsv).unwrap();
        queue.push(get_tx(), &wsv).unwrap();

        assert_eq!(queue.queue.len(), 1);
        let signature_count = queue
            .txs
            .get(&queue.queue.pop().unwrap())
            .unwrap()
            .as_inner_v1()
            .signatures
            .len();
        assert_eq!(signature_count, 2);
    }

    #[test]
    fn get_available_txs() {
        let max_block_tx = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = WorldStateView::new(world_with_test_domains(alice_key.public_key.clone()));
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
        });
        for _ in 0..5 {
            queue
                .push(
                    accepted_tx("alice", "wonderland", 100_000, Some(&alice_key)),
                    &wsv,
                )
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        let available = queue.get_transactions_for_block(&wsv);
        assert_eq!(available.len(), max_block_tx as usize);
    }

    #[test]
    fn push_tx_already_in_blockchain() {
        let max_block_tx = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = WorldStateView::new(world_with_test_domains(alice_key.public_key.clone()));
        let tx = accepted_tx("alice", "wonderland", 100_000, Some(&alice_key));
        wsv.transactions.insert(tx.hash());
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
        });
        assert!(matches!(
            queue.push(tx, &wsv),
            Err((_, Error::InBlockchain))
        ));
        assert_eq!(queue.txs.len(), 0);
    }

    #[test]
    fn get_tx_drop_if_in_blockchain() {
        let max_block_tx = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = WorldStateView::new(world_with_test_domains(alice_key.public_key.clone()));
        let tx = accepted_tx("alice", "wonderland", 100_000, Some(&alice_key));
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
        });
        queue.push(tx.clone(), &wsv).unwrap();
        wsv.transactions.insert(tx.hash());
        assert_eq!(queue.get_transactions_for_block(&wsv).len(), 0);
        assert_eq!(queue.txs.len(), 0);
    }

    #[test]
    fn get_available_txs_with_timeout() {
        let max_block_tx = 6;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = WorldStateView::new(world_with_test_domains(alice_key.public_key.clone()));
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 200,
            maximum_transactions_in_queue: 100,
        });
        for _ in 0..(max_block_tx - 1) {
            queue
                .push(
                    accepted_tx("alice", "wonderland", 100, Some(&alice_key)),
                    &wsv,
                )
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        queue
            .push(
                accepted_tx("alice", "wonderland", 200, Some(&alice_key)),
                &wsv,
            )
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(101));
        assert_eq!(queue.get_transactions_for_block(&wsv).len(), 1);

        let wsv = WorldStateView::new(world_with_test_domains(alice_key.public_key.clone()));

        queue
            .push(
                accepted_tx("alice", "wonderland", 300, Some(&alice_key)),
                &wsv,
            )
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(210));
        assert_eq!(queue.get_transactions_for_block(&wsv).len(), 0);
    }

    // Queue should only drop transactions which are already committed or ttl expired.
    // Others should stay in the queue until that moment.
    #[test]
    fn transactions_available_after_pop() {
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = WorldStateView::new(world_with_test_domains(alice_key.public_key.clone()));
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
        });
        queue
            .push(
                accepted_tx("alice", "wonderland", 100_000, Some(&alice_key)),
                &wsv,
            )
            .expect("Failed to push tx into queue");

        let a = queue
            .get_transactions_for_block(&wsv)
            .into_iter()
            .map(|tx| tx.hash())
            .collect::<Vec<_>>();
        let b = queue
            .get_transactions_for_block(&wsv)
            .into_iter()
            .map(|tx| tx.hash())
            .collect::<Vec<_>>();
        assert_eq!(a.len(), 1);
        assert_eq!(a, b);
    }

    #[test]
    fn concurrent_stress_test() {
        let max_block_tx = 10;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains(
            alice_key.public_key.clone(),
        )));
        let queue = Arc::new(Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100_000_000,
        }));

        let start_time = Instant::now();
        let run_for = Duration::from_secs(5);

        let queue_arc_clone_1 = Arc::clone(&queue);
        let queue_arc_clone_2 = Arc::clone(&queue);
        let wsv_arc_clone_1 = Arc::clone(&wsv);
        let wsv_arc_clone_2 = Arc::clone(&wsv);

        // Spawn a thread where we push transactions
        let push_txs_handle = thread::spawn(move || {
            while start_time.elapsed() < run_for {
                let tx = accepted_tx("alice", "wonderland", 100_000, Some(&alice_key));
                match queue_arc_clone_1.push(tx, &wsv_arc_clone_1) {
                    Ok(()) => (),
                    Err((_, Error::Full)) => (),
                    Err((_, err)) => panic!("{}", err),
                }
            }
        });

        // Spawn a thread where we get_transactions_for_block and add them to WSV
        let get_txs_handle = thread::spawn(move || {
            while start_time.elapsed() < run_for {
                for tx in queue_arc_clone_2.get_transactions_for_block(&wsv_arc_clone_2) {
                    wsv_arc_clone_2.transactions.insert(tx.hash());
                }
                // Simulate random small delays
                thread::sleep(Duration::from_millis(rand::thread_rng().gen_range(0, 25)));
            }
        });

        push_txs_handle.join().unwrap();
        get_txs_handle.join().unwrap();

        // Last update for queue to drop invalid txs.
        let _ = queue.get_transactions_for_block(&wsv);

        // Validate the queue state.
        let array_queue: Vec<_> = iter::repeat_with(|| queue.queue.pop())
            .take_while(Option::is_some)
            .map(Option::unwrap)
            .collect();

        assert_eq!(array_queue.len(), queue.txs.len());
        for tx in array_queue {
            assert!(queue.txs.contains_key(&tx));
        }
    }
}
