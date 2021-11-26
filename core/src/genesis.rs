//! This module contains execution Genesis Block logic, and `GenesisBlock` definition.
#![allow(clippy::module_name_repetitions)]

use std::{collections::HashSet, fmt::Debug, fs::File, io::BufReader, ops::Deref, path::Path};

use eyre::{eyre, Result, WrapErr};
use iroha_actor::Addr;
use iroha_crypto::KeyPair;
use iroha_data_model::{account::Account, isi::Instruction, prelude::*};
use iroha_schema::prelude::*;
use serde::Deserialize;
use tokio::{time, time::Duration};

use self::config::GenesisConfiguration;
use crate::{
    kura::KuraTrait,
    sumeragi::{
        network_topology::{GenesisBuilder as GenesisTopologyBuilder, Topology},
        Sumeragi,
    },
    tx::VersionedAcceptedTransaction,
    wsv::WorldTrait,
    Identifiable, IrohaNetwork,
};

type Online = Vec<PeerId>;
type Offline = Vec<PeerId>;

/// Time to live for genesis transactions.
const GENESIS_TRANSACTIONS_TTL_MS: u64 = 100_000;

/// Genesis network trait for mocking
#[async_trait::async_trait]
pub trait GenesisNetworkTrait:
    Deref<Target = Vec<VersionedAcceptedTransaction>> + Sync + Send + 'static + Sized + Debug
{
    /// Construct `GenesisNetwork` from configuration.
    ///
    /// # Errors
    /// Fail if genesis block loading fails
    fn from_configuration<P: AsRef<Path> + Debug>(
        submit_genesis: bool,
        block_path: P,
        genesis_config: &GenesisConfiguration,
        max_instructions_number: u64,
    ) -> Result<Option<Self>>;

    /// Waits for a minimum number of `peers` needed for consensus to be online.
    /// Returns initialized network [`Topology`] with the set A consisting of online peers.
    async fn wait_for_peers(
        &self,
        this_peer_id: PeerId,
        network_topology: Topology,
        network: Addr<IrohaNetwork>,
    ) -> Result<Topology>;

    /// Submits genesis transactions.
    ///
    /// # Errors
    /// Returns error if waiting for peers or genesis round itself fails
    async fn submit_transactions<K: KuraTrait, W: WorldTrait>(
        &self,
        sumeragi: &mut Sumeragi<Self, K, W>,
        network: Addr<IrohaNetwork>,
    ) -> Result<()> {
        let genesis_topology = self
            .wait_for_peers(sumeragi.peer_id.clone(), sumeragi.topology.clone(), network)
            .await?;
        iroha_logger::info!("Initializing iroha using the genesis block.");
        sumeragi
            .start_genesis_round(self.deref().clone(), genesis_topology)
            .await
    }
}

/// `GenesisNetwork` contains initial transactions and genesis setup related parameters.
#[derive(Clone, Debug)]
pub struct GenesisNetwork {
    /// transactions from `GenesisBlock`, any transaction is accepted
    pub transactions: Vec<VersionedAcceptedTransaction>,
    /// Number of attempts to connect to peers, while waiting for them to submit genesis.
    pub wait_for_peers_retry_count: u64,
    /// Period in milliseconds in which to retry connecting to peers, while waiting for them to submit genesis.
    pub wait_for_peers_retry_period_ms: u64,
}

impl Deref for GenesisNetwork {
    type Target = Vec<VersionedAcceptedTransaction>;
    fn deref(&self) -> &Self::Target {
        &self.transactions
    }
}

async fn try_get_online_topology(
    this_peer_id: &PeerId,
    network_topology: &Topology,
    network: Addr<IrohaNetwork>,
) -> Result<Topology> {
    let (online_peers, offline_peers) =
        check_peers_status(this_peer_id, network_topology, network).await;
    let set_a_len = network_topology.min_votes_for_commit() as usize;
    if online_peers.len() < set_a_len {
        return Err(eyre!("Not enough online peers for consensus."));
    }
    let genesis_topology = if network_topology.sorted_peers().len() == 1 {
        network_topology.clone()
    } else {
        let set_a: HashSet<_> = online_peers[..set_a_len].iter().cloned().collect();
        let set_b: HashSet<_> = online_peers[set_a_len..]
            .iter()
            .cloned()
            .chain(offline_peers.into_iter())
            .collect();
        #[allow(clippy::expect_used)]
        GenesisTopologyBuilder::new()
            .with_leader(this_peer_id.clone())
            .with_set_a(set_a)
            .with_set_b(set_b)
            .reshuffle_after(network_topology.reshuffle_after())
            .build()
            .expect("Preconditions should be already checked.")
    };
    iroha_logger::info!("Waiting for active peers finished.");
    Ok(genesis_topology)
}

/// Checks which peers are online and which are offline
/// Returns (online, offline) peers respectively
async fn check_peers_status(
    this_peer_id: &PeerId,
    network_topology: &Topology,
    network: Addr<IrohaNetwork>,
) -> (Online, Offline) {
    #[allow(clippy::expect_used)]
    let peers = network
        .send(iroha_p2p::network::GetConnectedPeers)
        .await
        .expect("Could not get connected peers from Network!")
        .peers;
    iroha_logger::info!(peer_count = peers.len(), "Peers status");

    let (online, offline): (Vec<_>, Vec<_>) = network_topology
        .sorted_peers()
        .iter()
        .cloned()
        .partition(|id| peers.contains(id) || this_peer_id == id);

    (online, offline)
}

#[async_trait::async_trait]
impl GenesisNetworkTrait for GenesisNetwork {
    fn from_configuration<P: AsRef<Path> + Debug>(
        submit_genesis: bool,
        block_path: P,
        genesis_config: &GenesisConfiguration,
        max_instructions_number: u64,
    ) -> Result<Option<GenesisNetwork>> {
        if !submit_genesis {
            return Ok(None);
        }
        let file = File::open(block_path).wrap_err("Failed to open a genesis block file")?;
        let reader = BufReader::new(file);
        let raw_block: RawGenesisBlock =
            serde_json::from_reader(reader).wrap_err("Failed to deserialize json from reader")?;
        let genesis_key_pair = KeyPair {
            public_key: genesis_config
                .account_public_key
                .clone()
                .ok_or_else(|| eyre!("Genesis account public key is empty."))?,
            private_key: genesis_config
                .account_private_key
                .clone()
                .ok_or_else(|| eyre!("Genesis account private key is empty."))?,
        };
        Ok(Some(GenesisNetwork {
            transactions: raw_block
                .transactions
                .iter()
                .map(|raw_transaction| {
                    raw_transaction.sign_and_accept(&genesis_key_pair, max_instructions_number)
                })
                .filter_map(Result::ok)
                .collect(),
            wait_for_peers_retry_count: genesis_config.wait_for_peers_retry_count,
            wait_for_peers_retry_period_ms: genesis_config.wait_for_peers_retry_period_ms,
        }))
    }

    async fn wait_for_peers(
        &self,
        this_peer_id: PeerId,
        network_topology: Topology,
        network: Addr<IrohaNetwork>,
    ) -> Result<Topology> {
        iroha_logger::info!("Waiting for active peers",);
        for i in 0..self.wait_for_peers_retry_count {
            if let Ok(topology) =
                try_get_online_topology(&this_peer_id, &network_topology, network.clone()).await
            {
                iroha_logger::info!("Got topology");
                return Ok(topology);
            }

            let reconnect_in_ms = self.wait_for_peers_retry_period_ms * i;
            iroha_logger::info!("Retrying to connect in {} ms", reconnect_in_ms);
            time::sleep(Duration::from_millis(reconnect_in_ms)).await;
        }
        Err(eyre!("Waiting for peers failed."))
    }
}

/// `RawGenesisBlock` is an initial block of the network
#[derive(Clone, Deserialize, Debug, IntoSchema)]
pub struct RawGenesisBlock {
    /// Transactions
    pub transactions: Vec<GenesisTransaction>,
}

/// `GenesisTransaction` is a transaction for initialize settings.
#[derive(Clone, Deserialize, Debug, IntoSchema)]
pub struct GenesisTransaction {
    /// Instructions
    pub isi: Vec<Instruction>,
}

impl GenesisTransaction {
    /// Convert `GenesisTransaction` into `AcceptedTransaction` with signature
    /// # Errors
    /// Fails if signing fails
    pub fn sign_and_accept(
        &self,
        genesis_key_pair: &KeyPair,
        max_instruction_number: u64,
    ) -> Result<VersionedAcceptedTransaction> {
        let transaction = Transaction::new(
            self.isi.clone(),
            <Account as Identifiable>::Id::genesis_account(),
            GENESIS_TRANSACTIONS_TTL_MS,
        )
        .sign(genesis_key_pair)?;
        VersionedAcceptedTransaction::from_transaction(transaction, max_instruction_number)
    }
}

/// This module contains all genesis configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use iroha_crypto::{PrivateKey, PublicKey};
    use serde::{Deserialize, Serialize};

    const DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT: u64 = 100;
    const DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS: u64 = 500;

    #[derive(Clone, Deserialize, Serialize, Debug, Default, Configurable, PartialEq, Eq)]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "IROHA_GENESIS_")]
    /// Configuration of the genesis block and its submission process.
    pub struct GenesisConfiguration {
        /// Genesis account public key, should be supplied to all the peers.
        /// The type is `Option` just because it might be loaded from environment variables and not from `config.json`.
        #[serde(default)]
        #[config(serde_as_str)]
        pub account_public_key: Option<PublicKey>,
        /// Genesis account private key, only needed on the peer that submits the genesis block.
        #[serde(default)]
        pub account_private_key: Option<PrivateKey>,
        /// Number of attempts to connect to peers, while waiting for them to submit genesis.
        #[serde(default = "default_wait_for_peers_retry_count")]
        pub wait_for_peers_retry_count: u64,
        /// Period in milliseconds in which to retry connecting to peers, while waiting for them to submit genesis.
        #[serde(default = "default_wait_for_peers_retry_period_ms")]
        pub wait_for_peers_retry_period_ms: u64,
    }

    const fn default_wait_for_peers_retry_count() -> u64 {
        DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT
    }

    const fn default_wait_for_peers_retry_period_ms() -> u64 {
        DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS_BLOCK_PATH: &str = "tests/genesis.json";

    #[test]
    fn load_genesis_block() -> Result<()> {
        let genesis_key_pair = KeyPair::generate()?;
        let _genesis_block = GenesisNetwork::from_configuration(
            true,
            GENESIS_BLOCK_PATH,
            &GenesisConfiguration {
                account_public_key: Some(genesis_key_pair.public_key),
                account_private_key: Some(genesis_key_pair.private_key),
                ..GenesisConfiguration::default()
            },
            4096,
        )?;
        Ok(())
    }
}
