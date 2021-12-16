//! This module contains execution Genesis Block logic, and `GenesisBlock` definition.
#![allow(clippy::module_name_repetitions)]

use std::{collections::HashSet, fmt::Debug, fs::File, io::BufReader, ops::Deref, path::Path};

use eyre::{eyre, Result, WrapErr};
use iroha_actor::Addr;
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{account::Account, isi::Instruction, prelude::*};
use iroha_schema::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::{time, time::Duration};

pub use self::config::GenesisConfiguration;
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
    /// Construct [`GenesisNetwork`] from configuration.
    ///
    /// # Errors
    /// Fails if genesis block is not found or cannot be deserialised.
    fn from_configuration(
        submit_genesis: bool,
        raw_block: RawGenesisBlock,
        genesis_config: &GenesisConfiguration,
        max_instructions_number: u64,
    ) -> Result<Option<Self>>;

    /// Waits for a minimum number of [`Peer`]s needed for consensus to be online.
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
        time::sleep(Duration::from_millis(self.genesis_submission_delay_ms())).await;
        iroha_logger::info!("Initializing iroha using the genesis block.");
        sumeragi
            .start_genesis_round(self.deref().clone(), genesis_topology)
            .await
    }

    /// See [`GenesisConfiguration`] docs.
    fn genesis_submission_delay_ms(&self) -> u64;
}

/// [`GenesisNetwork`] contains initial transactions and genesis setup related parameters.
#[derive(Clone, Debug)]
pub struct GenesisNetwork {
    /// transactions from `GenesisBlock`, any transaction is accepted
    pub transactions: Vec<VersionedAcceptedTransaction>,
    /// Number of attempts to connect to peers, while waiting for them to submit genesis.
    pub wait_for_peers_retry_count: u64,
    /// Period in milliseconds in which to retry connecting to peers, while waiting for them to submit genesis.
    pub wait_for_peers_retry_period_ms: u64,
    /// Delay before genesis block submission after minimum number of peers were discovered to be online.
    /// Used to ensure that other peers had time to connect to each other.
    pub genesis_submission_delay_ms: u64,
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
    let set_a_len = network_topology.min_votes_for_commit();
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

/// Checks which [`Peer`]s are online and which are offline
/// Returns `(online, offline)` [`Peer`]s.
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
        .partition(|id| peers.contains(&id.public_key) || this_peer_id.public_key == id.public_key);

    (online, offline)
}

#[async_trait::async_trait]
impl GenesisNetworkTrait for GenesisNetwork {
    fn from_configuration(
        submit_genesis: bool,
        raw_block: RawGenesisBlock,
        genesis_config: &GenesisConfiguration,
        max_instructions_number: u64,
    ) -> Result<Option<GenesisNetwork>> {
        if !submit_genesis {
            return Ok(None);
        }
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
            genesis_submission_delay_ms: genesis_config.genesis_submission_delay_ms,
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

    fn genesis_submission_delay_ms(&self) -> u64 {
        self.genesis_submission_delay_ms
    }
}

/// `RawGenesisBlock` is an initial block of the network
#[derive(Clone, Deserialize, Debug, IntoSchema, Default, Serialize)]
pub struct RawGenesisBlock {
    /// Transactions
    pub transactions: Vec<GenesisTransaction>,
}

impl RawGenesisBlock {
    /// Construct a genesis block from a `.json` file at the specified path.
    ///
    /// # Errors
    /// If file not found or deserialization from file fails.
    pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<Self> {
        let file = File::open(&path).wrap_err(format!("Failed to open {:?}", &path))?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).wrap_err(format!(
            "Failed to deserialise raw genesis block from {:?}",
            &path
        ))
    }

    /// Create a [`RawGenesisBlock`] with specified [`Domain`] and [`NewAccount`].
    pub fn new(name: &str, domain_name: &str, public_key: &PublicKey) -> Self {
        RawGenesisBlock {
            transactions: vec![GenesisTransaction::new(name, domain_name, public_key)],
        }
    }
}

/// `GenesisTransaction` is a transaction for initialize settings.
#[derive(Default, Clone, Deserialize, Debug, IntoSchema, Serialize)]
pub struct GenesisTransaction {
    /// Instructions
    pub isi: Vec<Instruction>,
}

impl GenesisTransaction {
    /// Convert `GenesisTransaction` into `AcceptedTransaction` with signature
    ///
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

    /// Create a [`GenesisTransaction`] with the specified [`Domain`] and [`NewAccount`].
    pub fn new(name: &str, domain_name: &str, public_key: &PublicKey) -> Self {
        let name = match Name::new(name) {
            Ok(name) => name,
            Err(error) => {
                iroha_logger::error!(%error, "Invalid account name");
                return Self::default()
            },
        };
        let domain_id: DomainId = match Name::new(domain_name) {
            Ok(name) => name.into(),
            Err(error) => {
                iroha_logger::error!(%error, "Invalid domain name");
                return Self::default()
            },
        };
        Self {
            isi: vec![
                RegisterBox::new(IdentifiableBox::Domain(Domain::new(domain_id).into())).into(),
                RegisterBox::new(IdentifiableBox::NewAccount(
                    NewAccount::with_signatory(
                        iroha_data_model::account::Id::new(name, domain_id),
                        public_key.clone(),
                    )
                    .into(),
                ))
                .into(),
            ],
        }
    }
}

/// Module with genesis configuration logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use iroha_crypto::{PrivateKey, PublicKey};
    use serde::{Deserialize, Serialize};

    const DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT: u64 = 100;
    const DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS: u64 = 500;
    const DEFAULT_GENESIS_SUBMISSION_DELAY_MS: u64 = 1000;

    #[derive(Clone, Deserialize, Serialize, Debug, Configurable, PartialEq, Eq)]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "IROHA_GENESIS_")]
    /// Configuration of the genesis block and the process of its submission.
    pub struct GenesisConfiguration {
        /// The genesis account public key, should be supplied to all peers.
        /// The type is `Option` just because it might be loaded from environment variables and not from `config.json`.
        #[config(serde_as_str)]
        pub account_public_key: Option<PublicKey>,
        /// Genesis account private key, only needed on the peer that submits the genesis block.
        pub account_private_key: Option<PrivateKey>,
        /// Number of attempts to connect to peers, while waiting for them to submit genesis.
        #[serde(default = "default_wait_for_peers_retry_count")]
        pub wait_for_peers_retry_count: u64,
        /// Period in milliseconds in which to retry connecting to peers, while waiting for them to submit genesis.
        #[serde(default = "default_wait_for_peers_retry_period_ms")]
        pub wait_for_peers_retry_period_ms: u64,
        /// Delay before genesis block submission after minimum number of peers were discovered to be online.
        /// Used to ensure that other peers had time to connect to each other.
        #[serde(default = "default_genesis_submission_delay_ms")]
        pub genesis_submission_delay_ms: u64,
    }

    impl Default for GenesisConfiguration {
        fn default() -> Self {
            Self {
                account_public_key: None,
                account_private_key: None,
                wait_for_peers_retry_count: DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT,
                wait_for_peers_retry_period_ms: DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS,
                genesis_submission_delay_ms: DEFAULT_GENESIS_SUBMISSION_DELAY_MS,
            }
        }
    }

    const fn default_wait_for_peers_retry_count() -> u64 {
        DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT
    }

    const fn default_wait_for_peers_retry_period_ms() -> u64 {
        DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS
    }

    const fn default_genesis_submission_delay_ms() -> u64 {
        DEFAULT_GENESIS_SUBMISSION_DELAY_MS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_default_genesis_block() -> Result<()> {
        let genesis_key_pair = KeyPair::generate()?;
        let _genesis_block = GenesisNetwork::from_configuration(
            true,
            RawGenesisBlock::default(),
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
