//! This module provides `WorldStateView` - in-memory representations of the current blockchain
//! state.

use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use config::Configuration;
use dashmap::{
    mapref::one::{Ref as DashmapRef, RefMut as DashmapRefMut},
    DashSet,
};
use eyre::Result;
use iroha_data_model::{domain::DomainsMap, peer::PeersIds, prelude::*};
use tokio::task;

use crate::{
    block::Chain,
    prelude::*,
    smartcontracts::{FindError, ParentHashNotFound},
};

/// World proxy for using with `WorldTrait`
#[derive(Debug, Default, Clone)]
pub struct World(iroha_data_model::world::World);

// SATO Deref
impl Deref for World {
    type Target = iroha_data_model::world::World;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for World {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl WorldTrait for World {
    /// Creates `World` with these `domains` and `trusted_peers_ids`
    fn with(
        domains: impl IntoIterator<Item = (Name, Domain)>,
        trusted_peers_ids: impl IntoIterator<Item = PeerId>,
    ) -> Self {
        Self(iroha_data_model::world::World::with(
            domains,
            trusted_peers_ids,
        ))
    }
}

impl World {
    /// Creates an empty `World`.
    pub fn new() -> Self {
        Self::default()
    }
}

/// World trait for mocking
pub trait WorldTrait:
    Deref<Target = iroha_data_model::world::World>
    + DerefMut
    + Send
    + Sync
    + 'static
    + Debug
    + Default
    + Sized
    + Clone
{
    /// Creates `World` with these `domains` and `trusted_peers_ids`
    fn with(
        domains: impl IntoIterator<Item = (Name, Domain)>,
        trusted_peers_ids: impl IntoIterator<Item = PeerId>,
    ) -> Self;
}

/// Current state of the blockchain alligned with `Iroha` module.
#[derive(Debug, Clone)]
pub struct WorldStateView<W: WorldTrait> {
    /// The world - contains `domains`, `triggers`, etc..
    pub world: W,
    /// Configuration of World State View.
    pub config: Configuration,
    /// Blockchain.
    blocks: Arc<Chain>,
    /// Hashes of transactions
    pub transactions: DashSet<Hash>,
}

impl<W: WorldTrait + Default> Default for WorldStateView<W> {
    fn default() -> Self {
        Self::new(W::default())
    }
}

/// WARNING!!! INTERNAL USE ONLY!!!
impl<W: WorldTrait> WorldStateView<W> {
    /// Default `WorldStateView` constructor.
    pub fn new(world: W) -> Self {
        WorldStateView {
            world,
            config: Configuration::default(),
            transactions: DashSet::new(),
            blocks: Arc::new(Chain::new()),
        }
    }

    /// [`WorldStateView`] constructor with configuration.
    pub fn from_config(config: Configuration, world: W) -> Self {
        WorldStateView {
            world,
            blocks: Arc::new(Chain::new()),
            transactions: DashSet::new(),
            config,
        }
    }

    /// Initializes WSV with the blocks from block storage.
    #[iroha_futures::telemetry_future]
    pub async fn init(&self, blocks: Vec<VersionedCommittedBlock>) {
        for block in blocks {
            self.apply(block).await
        }
    }

    /// Apply `CommittedBlock` with changes in form of **Iroha Special Instructions** to `self`.
    #[iroha_futures::telemetry_future]
    #[iroha_logger::log(skip(self, block))]
    pub async fn apply(&self, block: VersionedCommittedBlock) {
        for transaction in &block.as_inner_v1().transactions {
            if let Err(error) = transaction.proceed(self) {
                iroha_logger::warn!(%error, "Failed to proceed transaction on WSV");
            }
            let _ = self.transactions.insert(transaction.hash());
            // Yeild control cooperatively to the task scheduler.
            // The transaction processing is a long CPU intensive task, so this should be included here.
            task::yield_now().await;
        }
        for rejected_transaction in &block.as_inner_v1().rejected_transactions {
            let _ = self.transactions.insert(rejected_transaction.hash());
        }
        self.blocks.push(block);
    }

    /// Hash of latest block
    pub fn latest_block_hash(&self) -> Hash {
        self.blocks
            .latest_block()
            .map_or(Hash([0_u8; 32]), |block_entry| block_entry.value().hash())
    }

    /// Height of blockchain
    pub fn height(&self) -> u64 {
        self.blocks
            .latest_block()
            .map_or(0, |block_entry| block_entry.value().header().height)
    }

    /// Returns blocks after hash
    ///
    /// # Errors
    /// Block with `hash` was not found.
    pub fn blocks_after(
        &self,
        hash: Hash,
        max_blocks: u32,
    ) -> Result<Vec<VersionedCommittedBlock>> {
        let from_pos = self
            .blocks
            .iter()
            .position(|block_entry| block_entry.value().header().previous_block_hash == hash)
            .ok_or(FindError::Block(ParentHashNotFound(hash)))?;
        Ok(self
            .blocks
            .iter()
            .skip(from_pos)
            .take(max_blocks as usize)
            .map(|block_entry| block_entry.value().clone())
            .collect())
    }

    /// Get `World` without an ability to modify it.
    pub fn world(&self) -> &W {
        &self.world
    }

    /// Add new `Domain` entity.
    pub fn add_domain(&mut self, domain: Domain) {
        self.world.domains.insert(domain.name.clone(), domain);
    }

    /// Returns reference for domains map
    pub fn domains(&self) -> &DomainsMap {
        &self.world.domains
    }

    /// Returns reference for trusted peer ids
    pub fn trusted_peers_ids(&self) -> &PeersIds {
        &self.world.trusted_peers_ids
    }

    /// Get `Domain` without an ability to modify it.
    ///
    /// # Errors
    /// Fails if there is no domain
    pub fn domain(&self, name: &str) -> Result<DashmapRef<Name, Domain>> {
        let domain = self
            .world
            .domains
            .get(name)
            .ok_or_else(|| FindError::Domain(name.to_owned()))?;
        Ok(domain)
    }

    /// Get `Domain` with an ability to modify it.
    ///
    /// # Errors
    /// Fails if there is no domain
    pub fn domain_mut(&self, name: &str) -> Result<DashmapRefMut<Name, Domain>> {
        let domain = self
            .world
            .domains
            .get_mut(name)
            .ok_or_else(|| FindError::Domain(name.to_owned()))?;
        Ok(domain)
    }

    /// Get `Account` and pass it to closure.
    /// # Errors
    /// Fails if there is no domain or account
    pub fn map_account<T>(
        &self,
        id: &<Account as Identifiable>::Id,
        f: impl FnOnce(&Account) -> T,
    ) -> Result<T> {
        let domain = self.domain(&id.domain_name)?;
        let account = domain
            .accounts
            .get(id)
            .ok_or_else(|| FindError::Account(id.clone()))?;
        Ok(f(account))
    }

    /// Get `Account` and pass it to closure to modify it
    /// # Errors
    /// Fails if there is no domain or account
    pub fn modify_account(
        &self,
        id: &<Account as Identifiable>::Id,
        f: impl FnOnce(&mut Account) -> Result<()>,
    ) -> Result<()> {
        let mut domain = self.domain_mut(&id.domain_name)?;
        let account = domain
            .accounts
            .get_mut(id)
            .ok_or_else(|| FindError::Account(id.clone()))?;
        f(account)
    }

    /// Get `Account`'s `Asset`s and pass it to closure
    ///
    /// # Errors
    /// Fails if account finding fails
    pub fn account_assets(&self, id: &<Account as Identifiable>::Id) -> Result<Vec<Asset>> {
        self.map_account(id, |account| account.assets.values().cloned().collect())
    }

    /// Get all `PeerId`s without an ability to modify them.
    pub fn peers(&self) -> Vec<Peer> {
        let mut vec = self
            .world
            .trusted_peers_ids
            .iter()
            .map(|peer| Peer::new((&*peer).clone()))
            .collect::<Vec<Peer>>();
        vec.sort();
        vec
    }

    /// Get `Asset` by its id
    ///
    /// # Errors
    /// Fails if there are no such asset or account
    pub fn asset(&self, id: &<Asset as Identifiable>::Id) -> Result<Asset> {
        self.map_account(&id.account_id, |account| -> Result<Asset> {
            account
                .assets
                .get(id)
                .ok_or_else(|| FindError::Asset(id.clone()).into())
                .map(Clone::clone)
        })?
    }

    /// Get `Asset` by its id
    ///
    /// # Errors
    /// Fails if there are no such asset or account
    pub fn modify_asset(
        &self,
        id: &<Asset as Identifiable>::Id,
        f: impl FnOnce(&mut Asset) -> Result<()>,
    ) -> Result<()> {
        self.modify_account(&id.account_id, |account| {
            let mut asset = account
                .assets
                .get_mut(id)
                .ok_or_else(|| FindError::Asset(id.clone()))?;
            f(&mut asset)?;
            if asset.value.is_zero_value() {
                account.assets.remove(id);
            }
            Ok(())
        })
    }

    /// Tries to get asset or inserts new with `default_asset_value`.
    ///
    /// # Errors
    /// Fails if there is no account with such name.
    pub fn asset_or_insert(
        &self,
        id: &<Asset as Identifiable>::Id,
        default_asset_value: impl Into<AssetValue>,
    ) -> Result<Asset> {
        self.modify_account(&id.account_id, |account| {
            let _ = account
                .assets
                .entry(id.clone())
                .or_insert_with(|| Asset::new(id.clone(), default_asset_value.into()));
            Ok(())
        })?;
        self.asset(id)
    }

    /// Add new `Asset` entity.
    /// # Errors
    /// Fails if there is no account for asset
    pub fn add_asset(&self, asset: Asset) -> Result<()> {
        let id = asset.id.account_id.clone();
        self.modify_account(&id, move |account| {
            account.assets.insert(asset.id.clone(), asset);
            Ok(())
        })
    }

    /// Get `AssetDefinitionEntry` without an ability to modify it.
    ///
    /// # Errors
    /// Fails if asset definition entry does not exist
    pub fn asset_definition_entry(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
    ) -> Result<AssetDefinitionEntry> {
        self.domain(&id.domain_name)?
            .asset_definitions
            .get(id)
            .ok_or_else(|| FindError::AssetDefinition(id.clone()).into())
            .map(Clone::clone)
    }

    /// Get `AssetDefinitionEntry` with an ability to modify it.
    ///
    /// # Errors
    /// Fails if asset definition entry does not exist
    pub fn modify_asset_definition_entry(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
        f: impl FnOnce(&mut AssetDefinitionEntry) -> Result<()>,
    ) -> Result<()> {
        let mut domain = self.domain_mut(&id.domain_name)?;
        let asset_definition_entry = domain
            .asset_definitions
            .get_mut(id)
            .ok_or_else(|| FindError::AssetDefinition(id.clone()))?;
        f(asset_definition_entry)
    }

    /// Checks if this `transaction_hash` is already committed or rejected.
    pub fn has_transaction(&self, transaction_hash: &Hash) -> bool {
        self.transactions.get(transaction_hash).is_some()
    }

    /// Get committed and rejected transaction of the account.
    pub fn transactions_values_by_account_id(
        &self,
        account_id: &AccountId,
    ) -> Vec<TransactionValue> {
        let mut transactions = self
            .blocks
            .iter()
            .flat_map(|block_entry| {
                let block = block_entry.value().as_inner_v1();
                block
                    .rejected_transactions
                    .iter()
                    .filter(|transaction| &transaction.payload().account_id == account_id)
                    .cloned()
                    .map(TransactionValue::RejectedTransaction)
                    .chain(
                        block
                            .transactions
                            .iter()
                            .filter(|transaction| &transaction.payload().account_id == account_id)
                            .cloned()
                            .map(VersionedTransaction::from)
                            .map(TransactionValue::Transaction),
                    )
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        transactions.sort();
        transactions
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use iroha_data_model::{metadata::Limits as MetadataLimits, LengthLimits};
    use serde::{Deserialize, Serialize};

    const DEFAULT_METADATA_LIMITS: MetadataLimits =
        MetadataLimits::new(2_u32.pow(20), 2_u32.pow(12));
    const DEFAULT_IDENT_LENGTH_LIMITS: LengthLimits = LengthLimits::new(1, 2_u32.pow(7));

    /// [`WorldStateView`](super::WorldStateView) configuration.
    #[derive(Clone, Deserialize, Serialize, Debug, Copy, Configurable)]
    #[config(env_prefix = "WSV_")]
    #[serde(rename_all = "UPPERCASE", default)]
    pub struct Configuration {
        /// [`MetadataLimits`] for every asset with store.
        pub asset_metadata_limits: MetadataLimits,
        /// [`MetadataLimits`] of any asset definition's metadata.
        pub asset_definition_metadata_limits: MetadataLimits,
        /// [`MetadataLimits`] of any account's metadata.
        pub account_metadata_limits: MetadataLimits,
        /// [`LengthLimits`]for the number of chars in identifiers that can be stored in the WSV.
        pub ident_length_limits: LengthLimits,
    }

    impl Default for Configuration {
        fn default() -> Self {
            Configuration {
                asset_metadata_limits: DEFAULT_METADATA_LIMITS,
                asset_definition_metadata_limits: DEFAULT_METADATA_LIMITS,
                account_metadata_limits: DEFAULT_METADATA_LIMITS,
                ident_length_limits: DEFAULT_IDENT_LENGTH_LIMITS,
            }
        }
    }
}
