//! Module for starting peers and networks. Used only for tests

#![allow(
    missing_docs,
    clippy::pedantic,
    clippy::restriction,
    clippy::future_not_send
)]

use std::{collections::HashMap, fmt::Debug, thread, time::Duration};

use eyre::{Error, Result};
use futures::{prelude::*, stream::FuturesUnordered};
use iroha_actor::{broker::*, prelude::*};
use iroha_client::{client::Client, config::Configuration as ClientConfiguration};
use iroha_core::{
    block_sync::{BlockSynchronizer, BlockSynchronizerTrait},
    config::Configuration,
    genesis::{GenesisNetwork, GenesisNetworkTrait, RawGenesisBlock},
    kura::{Kura, KuraTrait},
    prelude::*,
    smartcontracts::permissions::{IsInstructionAllowedBoxed, IsQueryAllowedBoxed},
    sumeragi::{config::SumeragiConfiguration, Sumeragi, SumeragiTrait},
    torii::config::ToriiConfiguration,
    wsv::{World, WorldTrait},
    Iroha,
};
use iroha_data_model::{peer::Peer as DataModelPeer, prelude::*};
use iroha_logger::{Configuration as LoggerConfiguration, InstrumentFutures};
use rand::seq::IteratorRandom;
use tempfile::TempDir;
use tokio::{
    runtime::{self, Runtime},
    task::{self, JoinHandle},
    time,
};

#[derive(Debug, Clone, Copy)]
struct ShutdownRuntime;

/// Network of peers
pub struct Network<
    W = World,
    G = GenesisNetwork,
    K = Kura<W>,
    S = Sumeragi<G, K, W>,
    B = BlockSynchronizer<S, W>,
> where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    K: KuraTrait<World = W>,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K, World = W>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    /// Genesis peer which sends genesis block to everyone
    pub genesis: Peer<W, G, K, S, B>,
    /// Peers excluding the `genesis` peer. Use [`Network::peers`] function to get all instead.
    pub peers: HashMap<PeerId, Peer<W, G, K, S, B>>,
}

impl From<Peer> for Box<iroha_core::tx::Peer> {
    fn from(val: Peer) -> Self {
        Box::new(iroha_core::tx::Peer { id: val.id.clone() })
    }
}

/// Peer structure
pub struct Peer<
    W = World,
    G = GenesisNetwork,
    K = Kura<W>,
    S = Sumeragi<G, K, W>,
    B = BlockSynchronizer<S, W>,
> where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    K: KuraTrait<World = W>,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K, World = W>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    /// id of peer
    pub id: PeerId,
    /// api address
    pub api_address: String,
    /// p2p address
    pub p2p_address: String,
    /// status address
    pub status_address: String,
    /// Key pair of peer
    pub key_pair: KeyPair,
    /// Broker
    pub broker: Broker,

    /// Shutdown handle
    shutdown: Option<JoinHandle<()>>,

    /// Iroha itself
    pub iroha: Option<Iroha<W, G, K, S, B>>,
}

impl std::cmp::PartialEq for Peer {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl std::cmp::Eq for Peer {}

pub fn get_key_pair() -> KeyPair {
    KeyPair {
        public_key: PublicKey::from_str(
            r#"ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"#,
        )
        .unwrap(),
        private_key: PrivateKey {
            digest_function: "ed25519".to_string(),
            payload: hex_literal::hex!("9AC47ABF 59B356E0 BD7DCBBB B4DEC080 E302156A 48CA907E 47CB6AEA 1D32719E 7233BFC8 9DCBD68C 19FDE6CE 61582252 98EC1131 B6A130D1 AEB454C1 AB5183C0"
            )
            .into(),
        },
    }
}

pub trait TestGenesis: Sized {
    fn test(submit_genesis: bool) -> Option<Self>;
}

impl<G: GenesisNetworkTrait> TestGenesis for G {
    fn test(submit_genesis: bool) -> Option<Self> {
        let cfg = Configuration::test();
        let mut genesis = RawGenesisBlock::new("alice", "wonderland", &get_key_pair().public_key)
            .expect("Valid names never fail to parse");
        genesis.transactions[0].isi.push(
            RegisterBox::new(IdentifiableBox::AssetDefinition(
                AssetDefinition::new_quantity(AssetDefinitionId::test("rose", "wonderland")).into(),
            ))
            .into(),
        );
        genesis.transactions[0].isi.push(
            RegisterBox::new(IdentifiableBox::AssetDefinition(
                AssetDefinition::new_quantity(AssetDefinitionId::test("tulip", "wonderland"))
                    .into(),
            ))
            .into(),
        );
        genesis.transactions[0].isi.push(
            MintBox::new(
                Value::U32(13),
                IdBox::AssetId(AssetId::new(
                    AssetDefinitionId::test("rose", "wonderland"),
                    AccountId::test("alice", "wonderland"),
                )),
            )
            .into(),
        );
        G::from_configuration(
            submit_genesis,
            genesis,
            &cfg.genesis,
            cfg.sumeragi.max_instruction_number,
        )
        .expect("Failed to init genesis")
    }
}

impl<W, G, K, S, B> Network<W, G, K, S, B>
where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    K: KuraTrait<World = W>,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K, World = W>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    pub async fn send_to_actor_on_peers<M, A>(
        &self,
        select_actor: impl Fn(&Iroha<W, G, K, S, B>) -> &Addr<A>,
        msg: M,
    ) -> Vec<(M::Result, PeerId)>
    where
        M: Message + Clone + Send + 'static,
        M::Result: Send,
        A: Actor + ContextHandler<M>,
    {
        let fut = self
            .peers()
            .map(|peer| (select_actor(peer.iroha.as_ref().unwrap()), peer.id.clone()))
            .map(|(actor, peer_id)| async { (actor.send(msg.clone()).await, peer_id) })
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>();
        time::timeout(Duration::from_secs(60), fut)
            .await
            .unwrap()
            .into_iter()
            .map(|(result, peer_id)| (result.unwrap(), peer_id))
            .collect()
    }

    /// Starts network with peers with default configuration and specified options in a new async runtime.
    /// Returns its info and client for connecting to it.
    pub fn start_test_with_runtime(n_peers: u32, max_txs_in_block: u32) -> (Runtime, Self, Client) {
        let rt = Runtime::test();
        let (network, client) = rt.block_on(Self::start_test(n_peers, max_txs_in_block));
        (rt, network, client)
    }

    /// Starts network with peers with default configuration and specified options.
    /// Returns its info and client for connecting to it.
    pub async fn start_test(n_peers: u32, max_txs_in_block: u32) -> (Self, Client) {
        Self::start_test_with_offline(n_peers, max_txs_in_block, 0).await
    }

    /// Starts network with peers with default configuration and specified options.
    /// Returns its info and client for connecting to it.
    pub async fn start_test_with_offline_and_set_n_shifts(
        n_peers: u32,
        max_txs_in_block: u32,
        offline_peers: u32,
        n_shifts: u64,
    ) -> (Self, Client) {
        let mut configuration = Configuration::test();
        configuration.queue.maximum_transactions_in_block = max_txs_in_block;
        configuration.sumeragi.n_topology_shifts_before_reshuffle = n_shifts;
        let network = Network::new_with_offline_peers(Some(configuration), n_peers, offline_peers)
            .await
            .expect("Failed to init peers");
        let client = Client::test(
            &network.genesis.api_address,
            &network.genesis.status_address,
        );
        (network, client)
    }

    /// Starts network with peers with default configuration and specified options.
    /// Returns its info and client for connecting to it.
    pub async fn start_test_with_offline(
        n_peers: u32,
        maximum_transactions_in_block: u32,
        offline_peers: u32,
    ) -> (Self, Client) {
        Self::start_test_with_offline_and_set_n_shifts(
            n_peers,
            maximum_transactions_in_block,
            offline_peers,
            SumeragiConfiguration::default().n_topology_shifts_before_reshuffle,
        )
        .await
    }

    /// Adds peer to network and waits for it to start block synchronization.
    pub async fn add_peer(&self) -> (Peer, Client) {
        let mut client = Client::test(&self.genesis.api_address, &self.genesis.status_address);
        let mut peer = Peer::new().expect("Failed to create new peer");
        let mut config = Configuration::test();
        config.sumeragi.trusted_peers.peers = self.peers().map(|peer| &peer.id).cloned().collect();
        peer.start_with_config(GenesisNetwork::test(false), config)
            .await;
        time::sleep(Configuration::pipeline_time() + Configuration::block_sync_gossip_time()).await;
        let add_peer = RegisterBox::new(IdentifiableBox::Peer(
            DataModelPeer::new(peer.id.clone()).into(),
        ));
        client.submit(add_peer).expect("Failed to add new peer.");
        let client = Client::test(&peer.api_address, &peer.status_address);
        (peer, client)
    }

    /// Creates new network with some offline peers
    ///
    /// # Panics
    /// Panics if fails to find or decode default configuration
    pub async fn new_with_offline_peers(
        default_configuration: Option<Configuration>,
        n_peers: u32,
        offline_peers: u32,
    ) -> Result<Self> {
        let n_peers = n_peers - 1;
        let mut genesis = Peer::new()?;
        let mut peers = (0..n_peers)
            .map(|_| Peer::new())
            .map(|result| result.map(|peer| (peer.id.clone(), peer)))
            .collect::<Result<HashMap<_, _>>>()?;

        let mut configuration = default_configuration.unwrap_or_else(Configuration::test);
        configuration.sumeragi.trusted_peers.peers = peers
            .values()
            .chain(std::iter::once(&genesis))
            .map(|peer| peer.id.clone())
            .collect();

        let rng = &mut rand::thread_rng();
        let online_peers = n_peers - offline_peers;
        let futures = FuturesUnordered::new();

        futures.push(genesis.start_with_config(G::test(true), configuration.clone()));
        for peer in peers
            .values_mut()
            .choose_multiple(rng, online_peers as usize)
        {
            futures.push(peer.start_with_config(G::test(false), configuration.clone()));
        }
        futures.collect::<()>().await;

        time::sleep(Duration::from_millis(500) * (n_peers + 1)).await;

        Ok(Self { genesis, peers })
    }

    /// Returns all peers.
    pub fn peers(&self) -> impl Iterator<Item = &Peer<W, G, K, S, B>> + '_ {
        std::iter::once(&self.genesis).chain(self.peers.values())
    }

    pub fn clients(&self) -> Vec<Client> {
        self.peers()
            .map(|peer| Client::test(&peer.api_address, &peer.status_address))
            .collect()
    }

    /// Get peer by its Id.
    pub fn peer_by_id(&self, id: &PeerId) -> Option<&Peer<W, G, K, S, B>> {
        self.peers.get(id).or(if self.genesis.id == *id {
            Some(&self.genesis)
        } else {
            None
        })
    }

    /// Creates new network from configuration and with that number of peers
    pub async fn new(default_configuration: Option<Configuration>, n_peers: u32) -> Result<Self> {
        Self::new_with_offline_peers(default_configuration, n_peers, 0).await
    }

    pub async fn send_all<M: iroha_actor::broker::BrokerMessage + Sync>(&self, m: M) {
        for peer in self.peers() {
            iroha_logger::info!(?peer.id, "Sending message");
            peer.send(m.clone()).await
        }
    }

    pub async fn send_all_default<M: iroha_actor::broker::BrokerMessage + Sync + Default>(&self) {
        for peer in self.peers() {
            iroha_logger::info!(?peer.id, "Sending message");
            peer.send_default::<M>().await
        }
    }
}

/// Wait for peers to have committed genesis block.
///
/// # Panics
/// When unsuccessful after `MAX_RETRIES`.
pub fn wait_for_genesis_committed(clients: Vec<Client>, offline_peers: u32) {
    const POLL_PERIOD: Duration = Duration::from_millis(1000);
    const MAX_RETRIES: u32 = 60 * 3; // 3 minutes

    for _ in 0..MAX_RETRIES {
        let without_genesis_peers = clients.iter().fold(0u32, |acc, client| {
            if let Ok(status) = client.get_status() {
                if status.blocks < 1 {
                    acc + 1
                } else {
                    acc
                }
            } else {
                acc + 1
            }
        });
        if without_genesis_peers <= offline_peers {
            return;
        }
        thread::sleep(POLL_PERIOD);
    }
    panic!(
        "Failed to wait for online peers to commit genesis block. Total wait time: {:?}",
        POLL_PERIOD * MAX_RETRIES
    );
}

impl<W, G, K, S, B> Drop for Peer<W, G, K, S, B>
where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    K: KuraTrait<World = W>,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K, World = W>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    fn drop(&mut self) {
        iroha_logger::info!(
            p2p_addr = %self.p2p_address,
            api_addr = %self.api_address,
            "Stopping peer",
        );
        self.stop()
    }
}

impl<W, G, K, S, B> Peer<W, G, K, S, B>
where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    K: KuraTrait<World = W>,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K, World = W>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    pub async fn send<M: iroha_actor::broker::BrokerMessage + Sync>(&self, m: M) {
        self.broker.issue_send(m).await
    }

    pub async fn send_default<M: iroha_actor::broker::BrokerMessage + Sync + Default>(&self) {
        self.send(M::default()).await
    }

    pub fn stop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            shutdown.abort();
            iroha_logger::info!("Shutting down peer...");
        }
    }

    /// Returns per peer config with all addresses, keys, and id set up
    fn get_config(&self, configuration: Configuration) -> Configuration {
        Configuration {
            sumeragi: SumeragiConfiguration {
                key_pair: self.key_pair.clone(),
                peer_id: self.id.clone(),
                ..configuration.sumeragi
            },
            torii: ToriiConfiguration {
                p2p_addr: self.p2p_address.clone(),
                api_url: self.api_address.clone(),
                telemetry_url: self.status_address.clone(),
                ..configuration.torii
            },
            logger: LoggerConfiguration {
                compact_mode: false,
                ..configuration.logger
            },
            public_key: self.key_pair.public_key.clone(),
            private_key: self.key_pair.private_key.clone(),
            ..configuration
        }
    }

    /// Starts peer with config, permissions and temporary directory
    pub async fn start_with_config_permissions_dir(
        &mut self,
        configuration: Configuration,
        permissions: impl Into<IsInstructionAllowedBoxed<W>> + Send + 'static,
        temp_dir: &TempDir,
    ) {
        let mut configuration = self.get_config(configuration);
        configuration
            .kura
            .block_store_path(temp_dir.path())
            .unwrap();
        let info_span = iroha_logger::info_span!(
            "test-peer",
            p2p_addr = %self.p2p_address,
            api_addr = %self.api_address,
            status_addr = %self.status_address
        );
        let broker = self.broker.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let handle = task::spawn(
            async move {
                let mut iroha = <Iroha<W, G, K, S, B>>::with_genesis(
                    G::test(true),
                    configuration,
                    permissions.into(),
                    AllowAll.into(),
                    broker,
                )
                .await
                .expect("Failed to start iroha");
                let jh = iroha.start_as_task().unwrap();
                sender.send(iroha).unwrap();
                jh.await.unwrap().unwrap();
            }
            .instrument(info_span),
        );

        self.iroha = Some(receiver.recv().unwrap());
        self.shutdown = Some(handle);
    }

    /// Starts peer with config and permissions
    pub async fn start_with_config_permissions(
        &mut self,
        configuration: Configuration,
        genesis: Option<G>,
        instruction_validator: impl Into<IsInstructionAllowedBoxed<W>> + Send + 'static,
        query_validator: impl Into<IsQueryAllowedBoxed<W>> + Send + 'static,
    ) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir.");
        let mut configuration = self.get_config(configuration);
        configuration
            .kura
            .block_store_path(temp_dir.path())
            .unwrap();
        let info_span = iroha_logger::info_span!(
            "test-peer",
            p2p_addr = %self.p2p_address,
            api_addr = %self.api_address,
            status_addr = %self.status_address
        );
        let broker = self.broker.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let join_handle = tokio::spawn(
            async move {
                let _temp_dir = temp_dir;
                let mut iroha = <Iroha<W, G, K, S, B>>::with_genesis(
                    genesis,
                    configuration,
                    instruction_validator.into(),
                    query_validator.into(),
                    broker,
                )
                .await
                .expect("Failed to start iroha");
                let jh = iroha.start_as_task().unwrap();
                sender.send(iroha).unwrap();
                jh.await.unwrap().unwrap();
            }
            .instrument(info_span),
        );

        self.iroha = Some(receiver.recv().unwrap());
        time::sleep(Duration::from_millis(300)).await;
        self.shutdown = Some(join_handle);
    }

    /// Starts peer with config
    pub async fn start_with_config(&mut self, genesis: Option<G>, configuration: Configuration) {
        self.start_with_config_permissions(configuration, genesis, AllowAll, AllowAll)
            .await;
    }

    /// Starts peer with config
    pub async fn start_with_genesis(&mut self, genesis: Option<G>) {
        self.start_with_config(genesis, Configuration::test()).await;
    }

    /// Starts peer
    pub async fn start(&mut self, submit_genesis: bool) {
        self.start_with_genesis(G::test(submit_genesis)).await;
    }

    /// Creates peer
    pub fn new() -> Result<Self> {
        let key_pair = KeyPair::generate()?;
        let p2p_address = format!(
            "127.0.0.1:{}",
            unique_port::get_unique_free_port().map_err(Error::msg)?
        );
        let api_address = format!(
            "127.0.0.1:{}",
            unique_port::get_unique_free_port().map_err(Error::msg)?
        );
        let status_address = format!(
            "127.0.0.1:{}",
            unique_port::get_unique_free_port().map_err(Error::msg)?
        );
        let id = PeerId {
            address: p2p_address.clone(),
            public_key: key_pair.public_key.clone(),
        };
        let shutdown = None;
        Ok(Self {
            id,
            key_pair,
            p2p_address,
            api_address,
            status_address,
            shutdown,
            iroha: None,
            broker: Broker::new(),
        })
    }

    /// Starts peer with default configuration.  **IMPORTANT**: Retain
    /// all three parameters for the scope of the test. Do not ignore
    /// the first two elements of the tuple.
    /// Returns its info and client for connecting to it.
    pub fn start_test_with_runtime() -> (Runtime, Self, Client) {
        let rt = Runtime::test();
        let (peer, client) = rt.block_on(Self::start_test());
        (rt, peer, client)
    }

    /// Starts peer with default configuration.
    /// Returns its info and client for connecting to it.
    pub async fn start_test() -> (Self, Client) {
        Self::start_test_with_permissions(AllowAll.into(), AllowAll.into()).await
    }

    /// Starts peer with default configuration and specified permissions.
    /// Returns its info and client for connecting to it.
    pub async fn start_test_with_permissions(
        instruction_validator: IsInstructionAllowedBoxed<W>,
        query_validator: IsQueryAllowedBoxed<W>,
    ) -> (Self, Client) {
        let mut configuration = Configuration::test();
        let mut peer = Self::new().expect("Failed to create peer.");
        configuration.sumeragi.trusted_peers.peers = std::iter::once(peer.id.clone()).collect();
        peer.start_with_config_permissions(
            configuration.clone(),
            G::test(true),
            instruction_validator,
            query_validator,
        )
        .await;
        let client = Client::test(&peer.api_address, &peer.status_address);
        time::sleep(Duration::from_millis(
            configuration.sumeragi.pipeline_time_ms(),
        ))
        .await;
        (peer, client)
    }
}

pub trait TestRuntime {
    /// Creates test runtime
    fn test() -> Self;
}

pub trait TestConfiguration {
    /// Creates test configuration
    fn test() -> Self;
    /// Returns default pipeline time.
    fn pipeline_time() -> Duration;
    /// Returns default time between block sync requests
    fn block_sync_gossip_time() -> Duration;
}

pub trait TestClientConfiguration {
    /// Creates test client configuration
    fn test(api_url: &str, telemetry_url: &str) -> Self;
}

pub trait TestClient: Sized {
    /// Creates test client from api url
    fn test(api_url: &str, telemetry_url: &str) -> Self;

    /// Creates test client from api url and keypair
    fn test_with_key(api_url: &str, telemetry_url: &str, keys: KeyPair) -> Self;

    /// Creates test client from api url, keypair, and account id
    fn test_with_account(
        api_url: &str,
        telemetry_url: &str,
        keys: KeyPair,
        account_id: &AccountId,
    ) -> Self;

    /// loops for events with filter and handler function
    fn for_each_event(self, event_filter: EventFilter, f: impl Fn(Result<Event>));

    /// Submits instruction with polling
    fn submit_till<R>(
        &mut self,
        instruction: impl Into<Instruction> + Debug,
        request: R,
        f: impl Fn(&R::Output) -> bool,
    ) -> R::Output
    where
        R: ValidQuery<World> + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug;

    /// Submits instructions with polling
    fn submit_all_till<R>(
        &mut self,
        instructions: Vec<Instruction>,
        request: R,
        f: impl Fn(&R::Output) -> bool,
    ) -> R::Output
    where
        R: ValidQuery<World> + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug;

    /// Polls request till predicate `f` is satisfied, with default period and max attempts.
    fn poll_request<R>(&mut self, request: R, f: impl Fn(&R::Output) -> bool) -> R::Output
    where
        R: ValidQuery<World> + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug;

    /// Polls request till predicate `f` is satisfied with `period` and `max_attempts` supplied.
    fn poll_request_with_period<R>(
        &mut self,
        request: R,
        period: Duration,
        max_attempts: u32,
        f: impl Fn(&R::Output) -> bool,
    ) -> R::Output
    where
        R: ValidQuery<World> + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug;
}

pub trait TestQueryResult {
    /// Tries to find asset by id
    fn find_asset_by_id(&self, asset_id: &AssetDefinitionId) -> Option<&Asset>;
}

impl TestRuntime for Runtime {
    fn test() -> Self {
        runtime::Builder::new_multi_thread()
            .thread_stack_size(32 * 1024 * 1024)
            .enable_all()
            .build()
            .unwrap()
    }
}

use std::collections::HashSet;

impl TestConfiguration for Configuration {
    fn test() -> Self {
        let mut configuration =
            iroha_core::samples::get_config(HashSet::new(), Some(get_key_pair()));
        configuration
            .load_environment()
            .expect("Failed to load configuration from environment");
        let keypair = KeyPair::generate().unwrap();
        configuration.public_key = keypair.public_key;
        configuration.private_key = keypair.private_key;
        configuration
    }

    fn pipeline_time() -> Duration {
        Duration::from_millis(Self::test().sumeragi.pipeline_time_ms())
    }

    fn block_sync_gossip_time() -> Duration {
        Duration::from_millis(Self::test().block_sync.gossip_period_ms)
    }
}

use std::str::FromStr;

impl TestClientConfiguration for ClientConfiguration {
    fn test(api_url: &str, telemetry_url: &str) -> Self {
        let mut configuration = iroha_client::samples::get_client_config(&get_key_pair());
        if !api_url.starts_with("http") {
            configuration.torii_api_url = "http://".to_owned() + api_url;
        } else {
            configuration.torii_api_url = api_url.to_owned();
        }
        if !telemetry_url.starts_with("http") {
            configuration.torii_telemetry_url = "http://".to_owned() + telemetry_url;
        } else {
            configuration.torii_telemetry_url = telemetry_url.to_owned();
        }
        configuration
    }
}

impl TestClient for Client {
    fn test(api_url: &str, telemetry_url: &str) -> Self {
        Client::new(&ClientConfiguration::test(api_url, telemetry_url))
    }

    fn test_with_key(api_url: &str, telemetry_url: &str, keys: KeyPair) -> Self {
        let mut configuration = ClientConfiguration::test(api_url, telemetry_url);
        configuration.public_key = keys.public_key;
        configuration.private_key = keys.private_key;
        Client::new(&configuration)
    }

    fn test_with_account(
        api_url: &str,
        telemetry_url: &str,
        keys: KeyPair,
        account_id: &AccountId,
    ) -> Self {
        let mut configuration = ClientConfiguration::test(api_url, telemetry_url);
        configuration.account_id = account_id.clone();
        configuration.public_key = keys.public_key;
        configuration.private_key = keys.private_key;
        Client::new(&configuration)
    }

    fn for_each_event(mut self, event_filter: EventFilter, f: impl Fn(Result<Event>)) {
        for event in self
            .listen_for_events(event_filter)
            .expect("Failed to create event iterator.")
        {
            f(event)
        }
    }

    fn submit_till<R>(
        &mut self,
        instruction: impl Into<Instruction> + Debug,
        request: R,
        f: impl Fn(&R::Output) -> bool,
    ) -> R::Output
    where
        R: ValidQuery<World> + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug,
    {
        self.submit(instruction)
            .expect("Failed to submit instruction.");
        self.poll_request(request, f)
    }

    fn submit_all_till<R>(
        &mut self,
        instructions: Vec<Instruction>,
        request: R,
        f: impl Fn(&R::Output) -> bool,
    ) -> R::Output
    where
        R: ValidQuery<World> + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug,
    {
        self.submit_all(instructions)
            .expect("Failed to submit instruction.");
        self.poll_request(request, f)
    }

    fn poll_request_with_period<R>(
        &mut self,
        request: R,
        period: Duration,
        max_attempts: u32,
        f: impl Fn(&R::Output) -> bool,
    ) -> R::Output
    where
        R: ValidQuery<World> + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug,
    {
        let mut query_result = None;
        for _ in 0..max_attempts {
            thread::sleep(period);
            query_result = match self.request(request.clone()) {
                Ok(result) if f(&result) => return result,
                result => Some(result),
            }
        }
        panic!("Failed to wait for query request completion that would satisfy specified closure. Got this query result instead: {:?}", &query_result)
    }

    fn poll_request<R>(&mut self, request: R, f: impl Fn(&R::Output) -> bool) -> R::Output
    where
        R: ValidQuery<World> + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug,
    {
        self.poll_request_with_period(request, Configuration::pipeline_time(), 10, f)
    }
}

impl TestQueryResult for QueryResult {
    fn find_asset_by_id(&self, asset_id: &AssetDefinitionId) -> Option<&Asset> {
        let assets = if let QueryResult(Value::Vec(assets)) = self {
            assets
        } else {
            panic!("Wrong Query Result Type.");
        };
        assets.iter().find_map(|asset| {
            if let Value::Identifiable(IdentifiableBox::Asset(asset)) = asset {
                if &asset.id.definition_id == asset_id {
                    return Some(asset.as_ref());
                }
            }
            None
        })
    }
}
