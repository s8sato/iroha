//! Iroha - A simple, enterprise-grade decentralized ledger.

pub mod block;
pub mod block_sync;
pub mod config;
pub mod event;
pub mod genesis;
mod init;
pub mod kura;
mod merkle;
pub mod modules;
pub mod queue;
pub mod smartcontracts;
pub mod sumeragi;
#[cfg(feature = "telemetry")]
mod telemetry;
pub mod torii;
pub mod tx;
pub mod wsv;

use std::{path::PathBuf, sync::Arc, time::Duration};

use eyre::{eyre, Result, WrapErr};
use genesis::GenesisNetworkTrait;
use iroha_actor::{broker::*, prelude::*};
use iroha_data_model::prelude::*;
use parity_scale_codec::{Decode, Encode};
use smartcontracts::permissions::{IsInstructionAllowedBoxed, IsQueryAllowedBoxed};
use tokio::{sync::broadcast, task::JoinHandle};
use wsv::{World, WorldTrait};

use crate::{
    block::VersionedValidBlock,
    block_sync::{
        message::VersionedMessage as BlockSyncMessage, BlockSynchronizer, BlockSynchronizerTrait,
    },
    config::Configuration,
    genesis::GenesisNetwork,
    kura::{Kura, KuraTrait},
    prelude::*,
    queue::Queue,
    sumeragi::{message::VersionedMessage as SumeragiMessage, Sumeragi, SumeragiTrait},
    torii::Torii,
};

/// The interval at which sumeragi checks if there are tx in the `queue`.
pub const TX_RETRIEVAL_INTERVAL: Duration = Duration::from_millis(100);

/// Specialized type of Iroha Network
pub type IrohaNetwork = iroha_p2p::Network<NetworkMessage>;

/// The network message
#[derive(Clone, Debug, Encode, Decode, iroha_actor::Message)]
pub enum NetworkMessage {
    /// Blockchain message
    SumeragiMessage(Box<SumeragiMessage>),
    /// Block sync message
    BlockSync(Box<BlockSyncMessage>),
    /// Health check message
    Health,
}

/// Iroha is an [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29) of the
/// system. It configures, coordinates and manages transactions and queries processing, work of consensus and storage.
pub struct Iroha<
    W = World,
    G = GenesisNetwork,
    S = Sumeragi<G, W>,
    K = Kura<W>,
    B = BlockSynchronizer<S, W>,
> where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    S: SumeragiTrait<GenesisNetwork = G, World = W>,
    K: KuraTrait<World = W>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    /// World state view
    pub wsv: Arc<WorldStateView<W>>,
    /// Queue of transactions
    pub queue: Arc<Queue>,
    /// Sumeragi consensus
    pub sumeragi: AlwaysAddr<S>,
    /// Kura - block storage
    pub kura: AlwaysAddr<K>,
    /// Block synchronization actor
    pub block_sync: AlwaysAddr<B>,
    /// Torii web server
    pub torii: Option<Torii<W>>,
}

impl<W, G, S, K, B> Iroha<W, G, S, K, B>
where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    S: SumeragiTrait<GenesisNetwork = G, World = W>,
    K: KuraTrait<World = W>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    /// To make `Iroha` peer work all actors should be started first.
    /// After that moment it you can start it with listening to torii events.
    ///
    /// # Errors
    /// Can fail if fails:
    /// - Reading genesis from disk
    /// - Reading telemetry configs and setuping telemetry
    /// - Initialization of sumeragi
    pub async fn new(
        args: &Arguments,
        instruction_validator: IsInstructionAllowedBoxed<K::World>,
        query_validator: IsQueryAllowedBoxed<K::World>,
    ) -> Result<Self> {
        let broker = Broker::new();
        Self::with_broker(args, instruction_validator, query_validator, broker).await
    }

    /// Creates Iroha with specified broker // SATO what is broker?
    /// # Errors
    /// Can fail if fails:
    /// - Reading genesis from disk
    /// - Reading telemetry configs and setuping telemetry
    /// - Initialization of sumeragi
    pub async fn with_broker(
        args: &Arguments,
        instruction_validator: IsInstructionAllowedBoxed<K::World>,
        query_validator: IsQueryAllowedBoxed<K::World>,
        broker: Broker,
    ) -> Result<Self> {
        let mut config = Configuration::from_path(&args.config_path)?;
        config.load_trusted_peers_from_path(&args.trusted_peers_path)?;
        config.load_environment()?;
        Self::with_broker_and_config(args, config, instruction_validator, query_validator, broker)
            .await
    }

    /// Creates Iroha with specified broker and custom config that overrides `args`
    /// # Errors
    /// Can fail if fails:
    /// - Reading genesis from disk
    /// - Reading telemetry configs and setuping telemetry
    /// - Initialization of sumeragi
    pub async fn with_broker_and_config(
        args: &Arguments,
        config: Configuration,
        instruction_validator: IsInstructionAllowedBoxed<K::World>,
        query_validator: IsQueryAllowedBoxed<K::World>,
        broker: Broker,
    ) -> Result<Self> {
        let genesis = G::from_configuration(
            args.submit_genesis,
            &args.genesis_path,
            &config.genesis_configuration,
            config.torii_configuration.torii_max_instruction_number,
        )
        .wrap_err("Failed to initialize genesis.")?;

        Self::with_genesis(
            genesis,
            config,
            instruction_validator,
            query_validator,
            broker,
        )
        .await
    }

    /// Creates Iroha with specified broker, config, and genesis
    /// # Errors
    /// Can fail if fails:
    /// - Reading telemetry configs and setuping telemetry
    /// - Initialization of sumeragi
    #[allow(clippy::non_ascii_literal)]
    pub async fn with_genesis(
        genesis: Option<G>,
        config: Configuration,
        instruction_validator: IsInstructionAllowedBoxed<K::World>,
        query_validator: IsQueryAllowedBoxed<K::World>,
        broker: Broker,
    ) -> Result<Self> {
        // TODO: use channel for prometheus/telemetry endpoint
        #[allow(unused)]
        let telemetry = iroha_logger::init(config.logger_configuration);
        iroha_logger::info!("Hyperledgerいろは2にようこそ！");

        let listen_addr = config.torii_configuration.torii_p2p_addr.clone();
        iroha_logger::info!("Starting peer on {}", &listen_addr);
        #[allow(clippy::expect_used)]
        let network = IrohaNetwork::new(broker.clone(), listen_addr, config.public_key.clone())
            .await
            .expect("Unable to start P2P-network");
        let network_addr = network.start().await;

        let (events_sender, _) = broadcast::channel(100);
        let wsv = Arc::new(WorldStateView::from_config(
            config.wsv_configuration,
            W::with(
                init::domains(&config).wrap_err("Failed to get initial domains")?,
                config.sumeragi_configuration.trusted_peers.peers.clone(),
            ),
        ));
        let queue = Arc::new(Queue::from_configuration(&config.queue_configuration));

        #[cfg(feature = "telemetry")]
        if let Some(telemetry) = telemetry {
            telemetry::start(&config.telemetry, telemetry)
                .await
                .wrap_err("Failed to setup telemetry")?;
        }
        let query_validator = Arc::new(query_validator);
        let sumeragi: AlwaysAddr<_> = S::from_configuration(
            &config.sumeragi_configuration,
            events_sender.clone(),
            Arc::clone(&wsv),
            instruction_validator,
            Arc::clone(&query_validator),
            genesis,
            Arc::clone(&queue),
            broker.clone(),
            network_addr.clone(),
        )
        .wrap_err("Failed to initialize Sumeragi.")?
        .start()
        .await
        .expect_running();

        let kura =
            K::from_configuration(&config.kura_configuration, Arc::clone(&wsv), broker.clone())
                .await?
                .start()
                .await
                .expect_running();
        let block_sync = B::from_configuration(
            &config.block_sync_configuration,
            Arc::clone(&wsv),
            sumeragi.clone(),
            PeerId::new(
                &config.torii_configuration.torii_p2p_addr,
                &config.public_key,
            ),
            config
                .sumeragi_configuration
                .n_topology_shifts_before_reshuffle,
            broker.clone(),
        )
        .start()
        .await
        .expect_running();

        let torii = Torii::from_configuration(
            config.torii_configuration.clone(),
            Arc::clone(&wsv),
            Arc::clone(&queue),
            query_validator,
            events_sender,
        );
        let torii = Some(torii);
        Ok(Self {
            wsv,
            queue,
            sumeragi,
            kura,
            block_sync,
            torii,
        })
    }

    /// To make `Iroha` peer work it should be started first. After that moment it will listen for
    /// incoming requests and messages.
    ///
    /// # Errors
    /// Can fail if initing kura fails
    #[iroha_futures::telemetry_future]
    pub async fn start(&mut self) -> Result<()> {
        iroha_logger::info!("Starting Iroha.");
        self.torii
            .take()
            .ok_or_else(|| eyre!("Seems like peer was already started"))?
            .start()
            .await
            .wrap_err("Failed to start Torii")
    }

    /// Starts iroha in separate tokio task.
    /// # Errors
    /// Can fail if initing kura fails
    pub fn start_as_task(&mut self) -> Result<JoinHandle<eyre::Result<()>>> {
        iroha_logger::info!("Starting Iroha as task.");
        let torii = self
            .torii
            .take()
            .ok_or_else(|| eyre!("Seems like peer was already started"))?;
        Ok(tokio::spawn(async move {
            torii.start().await.wrap_err("Failed to start Torii")
        }))
    }
}

/// Allow to check if an item is included in a blockchain.
// SATO Belongable<T>
pub trait IsInBlockchain {
    /// Checks if this item has already been committed or rejected.
    // SATO fn belongs(&self, t: T) -> bool;
    fn is_in_blockchain<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool;
}

const CONFIGURATION_PATH: &str = "config.json";
const TRUSTED_PEERS_PATH: &str = "trusted_peers.json";
const GENESIS_PATH: &str = "genesis.json";

/// Arguments for Iroha2 - usually parsed from cli.
#[derive(Debug)]
#[cfg_attr(feature = "cli", derive(structopt::StructOpt))]
#[cfg_attr(feature = "cli", structopt(name = "Hyperledger Iroha 2"))]
pub struct Arguments {
    /// Set this flag on the peer that should submit genesis on the network initial start.
    #[cfg_attr(feature = "cli", structopt(long))]
    pub submit_genesis: bool,
    /// Set custom genesis file path.
    #[cfg_attr(feature = "cli", structopt(parse(from_os_str), long, default_value = GENESIS_PATH))]
    pub genesis_path: PathBuf,
    /// Set custom config file path.
    #[cfg_attr(feature = "cli", structopt(parse(from_os_str), long, default_value = CONFIGURATION_PATH))]
    pub config_path: PathBuf,
    /// Set custom trusted peers file path.
    #[cfg_attr(feature = "cli", structopt(parse(from_os_str), long, default_value = TRUSTED_PEERS_PATH))]
    pub trusted_peers_path: PathBuf,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            submit_genesis: false,
            genesis_path: GENESIS_PATH.into(),
            config_path: CONFIGURATION_PATH.into(),
            trusted_peers_path: TRUSTED_PEERS_PATH.into(),
        }
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.

    #[doc(inline)]
    pub use iroha_crypto::{Hash, KeyPair, PrivateKey, PublicKey, Signature};

    #[doc(inline)]
    pub use crate::{
        block::{
            CommittedBlock, PendingBlock, ValidBlock, VersionedCommittedBlock, VersionedValidBlock,
        },
        smartcontracts::permissions::AllowAll,
        smartcontracts::Query,
        tx::{
            AcceptedTransaction, ValidTransaction, VersionedAcceptedTransaction,
            VersionedValidTransaction,
        },
        wsv::WorldStateView,
        IsInBlockchain,
    };
}
