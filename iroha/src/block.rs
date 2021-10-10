//! This module contains `Block` structures for each state, it's transitions, implementations and related traits
//! implementations.

#![allow(clippy::module_name_repetitions)]

use std::{iter, time::SystemTime};

use dashmap::{iter::Iter as MapIter, mapref::one::Ref as MapRef, DashMap};
use eyre::Result;
use iroha_crypto::{KeyPair, Signatures};
use iroha_data_model::{events::prelude::*, transaction::prelude::*};
use iroha_derive::Io;
use iroha_version::{declare_versioned_with_scale, version_with_scale};
use parity_scale_codec::{Decode, Encode};

use crate::{
    merkle::MerkleTree,
    prelude::*,
    smartcontracts::permissions::{IsInstructionAllowedBoxed, IsQueryAllowedBoxed},
    sumeragi::{network_topology::Topology, view_change::ProofChain as ViewChangeProofs},
    tx::{VersionedAcceptedTransaction, VersionedValidTransaction},
    wsv::WorldTrait,
};

/// The chain of the previous block hash if there is no previous block - the blockchain is empty.
#[derive(Debug, Clone, Copy)]
pub struct EmptyChainHash;

impl From<EmptyChainHash> for Hash {
    fn from(EmptyChainHash: EmptyChainHash) -> Hash {
        Hash([0_u8; 32])
    }
}

/// Blockchain.
#[derive(Debug, Default)]
pub struct Chain {
    blocks: DashMap<u64, VersionedCommittedBlock>,
}

impl Chain {
    /// Constructor.
    pub fn new() -> Self {
        Chain {
            blocks: DashMap::new(),
        }
    }

    /// Put latest block.
    pub fn push(&self, block: VersionedCommittedBlock) {
        let height = block.as_inner_v1().header.height;
        self.blocks.insert(height, block);
    }

    /// Iterator over height and block.
    pub fn iter(&self) -> MapIter<u64, VersionedCommittedBlock> {
        self.blocks.iter()
    }

    /// Latest block reference and its height.
    pub fn latest_block(&self) -> Option<MapRef<u64, VersionedCommittedBlock>> {
        self.blocks.get(&(self.blocks.len() as u64))
    }

    /// Length of the blockchain.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether blockchain is empty.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

declare_versioned_with_scale!(VersionedPendingBlock 1..2, Debug, Clone, iroha_derive::FromVariant);

/// Transaction data is permanently recorded in files called blocks. Blocks are organized into
/// a linear sequence over time (also known as the block chain).
/// Blocks lifecycle starts from "Pending" state which is represented by `PendingBlock` struct.
#[version_with_scale(n = 1, versioned = "VersionedPendingBlock", derive = "Debug, Clone")]
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct PendingBlock {
    /// Unix time (in milliseconds) of block forming by a peer.
    pub timestamp: u128,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<VersionedAcceptedTransaction>,
}

impl PendingBlock {
    /// Create a new `PendingBlock` from transactions.
    pub fn new(transactions: Vec<VersionedAcceptedTransaction>) -> PendingBlock {
        #[allow(clippy::expect_used)]
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get System Time.")
            .as_millis();
        PendingBlock {
            timestamp,
            transactions,
        }
    }

    /// Chain block with the existing blockchain.
    pub fn chain(
        self,
        height: u64,
        previous_block_hash: Hash,
        view_change_proofs: ViewChangeProofs,
        invalidated_blocks_hashes: Vec<Hash>,
    ) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            header: BlockHeader {
                timestamp: self.timestamp,
                height: height + 1,
                previous_block_hash,
                transactions_merkle_root_hash: Hash([0_u8; 32]),
                rejected_transactions_merkle_root_hash: Hash([0_u8; 32]),
                view_change_proofs,
                invalidated_blocks_hashes,
                genesis_topology: None,
            },
        }
    }

    /// Create a new blockchain with current block as a first block.
    pub fn chain_first_with_genesis_topology(self, genesis_topology: Topology) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            header: BlockHeader {
                timestamp: self.timestamp,
                height: 1,
                previous_block_hash: EmptyChainHash.into(),
                transactions_merkle_root_hash: Hash([0_u8; 32]),
                rejected_transactions_merkle_root_hash: Hash([0_u8; 32]),
                view_change_proofs: ViewChangeProofs::empty(),
                invalidated_blocks_hashes: Vec::new(),
                genesis_topology: Some(genesis_topology),
            },
        }
    }

    /// Create a new blockchain with current block as a first block.
    pub fn chain_first(self) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            header: BlockHeader {
                timestamp: self.timestamp,
                height: 1,
                previous_block_hash: EmptyChainHash.into(),
                transactions_merkle_root_hash: Hash([0_u8; 32]),
                rejected_transactions_merkle_root_hash: Hash([0_u8; 32]),
                view_change_proofs: ViewChangeProofs::empty(),
                invalidated_blocks_hashes: Vec::new(),
                genesis_topology: None,
            },
        }
    }
}

/// When `PendingBlock` chained with a blockchain it becomes `ChainedBlock`
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct ChainedBlock {
    /// Header
    pub header: BlockHeader,
    /// Array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<VersionedAcceptedTransaction>,
}

/// Header of the block. The hash should be taken from its byte representation.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct BlockHeader {
    /// Unix time (in milliseconds) of block forming by a peer.
    pub timestamp: u128,
    /// a number of blocks in the chain up to the block.
    pub height: u64,
    /// Hash of a previous block in the chain.
    /// Is an array of zeros for the first block.
    pub previous_block_hash: Hash,
    /// Hash of merkle tree root of the tree of valid transactions' hashes.
    pub transactions_merkle_root_hash: Hash,
    /// Hash of merkle tree root of the tree of rejected transactions' hashes.
    pub rejected_transactions_merkle_root_hash: Hash,
    // SATO Number of view changes?
    /// Number of view changes after the previous block was committed and before this block was committed.
    pub view_change_proofs: ViewChangeProofs,
    /// Hashes of the blocks that were rejected by consensus.
    pub invalidated_blocks_hashes: Vec<Hash>,
    /// Genesis topology
    pub genesis_topology: Option<Topology>,
}

impl BlockHeader {
    /// Calculate hash of the current block header.
    pub fn hash(&self) -> Hash {
        let bytes: Vec<u8> = self.into();
        Hash::new(&bytes)
    }

    /// Checks if it's a header of a genesis block.
    pub const fn is_genesis(&self) -> bool {
        self.height == 1
    }
}

impl ChainedBlock {
    /// Validate block transactions against current state of the world.
    pub fn validate<W: WorldTrait>(
        self,
        wsv: &WorldStateView<W>,
        is_instruction_allowed: &IsInstructionAllowedBoxed<W>,
        is_query_allowed: &IsQueryAllowedBoxed<W>,
    ) -> VersionedValidBlock {
        let mut transactions = Vec::new();
        let mut rejected_transactions = Vec::new();
        for transaction in self.transactions {
            match transaction.validate(
                wsv,
                is_instruction_allowed,
                is_query_allowed,
                self.header.is_genesis(),
            ) {
                Ok(transaction) => transactions.push(transaction),
                Err(transaction) => {
                    iroha_logger::warn!(
                        "Transaction validation failed: {}",
                        transaction.as_inner_v1().rejection_reason
                    );
                    rejected_transactions.push(transaction)
                }
            }
        }
        let mut header = self.header;
        header.transactions_merkle_root_hash =
            MerkleTree::build(transactions.iter().map(VersionedValidTransaction::hash)).root_hash();
        header.rejected_transactions_merkle_root_hash = MerkleTree::build(
            rejected_transactions
                .iter()
                .map(VersionedRejectedTransaction::hash),
        )
        .root_hash();
        ValidBlock {
            header,
            rejected_transactions,
            transactions,
            signatures: Signatures::default(),
        }
        .into()
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
}

declare_versioned_with_scale!(VersionedValidBlock 1..2, Debug, Clone, iroha_derive::FromVariant);

impl VersionedValidBlock {
    /// Same as [`as_v1`](`VersionedValidBlock::as_v1()`) but also does conversion
    pub const fn as_inner_v1(&self) -> &ValidBlock {
        match self {
            Self::V1(v1) => &v1.0,
        }
    }

    /// Same as [`as_inner_v1`](`VersionedValidBlock::as_inner_v1()`) but returns mutable reference
    pub fn as_mut_inner_v1(&mut self) -> &mut ValidBlock {
        match self {
            Self::V1(v1) => &mut v1.0,
        }
    }

    /// Same as [`into_v1`](`VersionedValidBlock::into_v1()`) but also does conversion
    pub fn into_inner_v1(self) -> ValidBlock {
        match self {
            Self::V1(v1) => v1.0,
        }
    }

    /// Returns header of valid block
    pub const fn header(&self) -> &BlockHeader {
        &self.as_inner_v1().header
    }

    /// Commit block to the store.
    pub fn commit(self) -> VersionedCommittedBlock {
        self.into_inner_v1().commit().into()
    }

    /// Validate block transactions against current state of the world.
    pub fn revalidate<W: WorldTrait>(
        self,
        wsv: &WorldStateView<W>,
        is_instruction_allowed: &IsInstructionAllowedBoxed<W>,
        is_query_allowed: &IsQueryAllowedBoxed<W>,
    ) -> VersionedValidBlock {
        self.into_inner_v1()
            .revalidate(wsv, is_instruction_allowed, is_query_allowed)
            .into()
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> Hash {
        self.as_inner_v1().header.hash()
    }

    /// Sign this block and get [`VersionedValidBlock`](`Self`).
    /// # Errors
    /// Look at [`ValidBlock`](`ValidBlock`) for more info
    pub fn sign(self, key_pair: &KeyPair) -> Result<VersionedValidBlock> {
        self.into_inner_v1().sign(key_pair).map(Into::into)
    }

    /// Signatures that are verified with the `hash` of this block as `payload`.
    pub fn verified_signatures(&self) -> Vec<Signature> {
        self.as_inner_v1().verified_signatures()
    }

    /// Checks if there are no transactions in this block.
    pub fn is_empty(&self) -> bool {
        self.as_inner_v1().is_empty()
    }

    /// Checks if block has transactions that are already in blockchain.
    pub fn has_committed_transactions<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool {
        self.as_inner_v1().has_committed_transactions(wsv)
    }

    /// # Errors
    /// Asserts specific instruction number of instruction in transaction constraint
    pub fn check_instruction_len(&self, max_instruction_len: u64) -> Result<()> {
        self.as_inner_v1()
            .check_instruction_len(max_instruction_len)
    }

    /// Returns true if block can be send for discussion
    pub fn validation_check<W: WorldTrait>(
        &self,
        wsv: &WorldStateView<W>,
        latest_block_hash: Hash,
        latest_view_change_hash: Hash,
        block_height: u64,
        max_instruction_number: u64,
    ) -> bool {
        !self.is_empty()
            && !self.has_committed_transactions(wsv)
            && latest_block_hash == self.header().previous_block_hash
            && latest_view_change_hash == self.header().view_change_proofs.latest_hash()
            && block_height + 1 == self.header().height
            && self.check_instruction_len(max_instruction_number).is_ok()
    }
}

/// After full validation `ChainedBlock` can transform into `ValidBlock`.
#[version_with_scale(n = 1, versioned = "VersionedValidBlock", derive = "Debug, Clone")]
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct ValidBlock {
    /// Header
    pub header: BlockHeader,
    /// Array of rejected transactions.
    pub rejected_transactions: Vec<VersionedRejectedTransaction>,
    /// Array of transactions.
    pub transactions: Vec<VersionedValidTransaction>,
    /// Signatures of peers which approved this block.
    pub signatures: Signatures,
}

impl ValidBlock {
    /// # Errors
    /// Asserts specific instruction number of instruction constraint
    pub fn check_instruction_len(&self, max_instruction_len: u64) -> Result<()> {
        self.transactions
            .iter()
            .map(|tx| tx.check_instruction_len(max_instruction_len))
            .collect::<Result<Vec<()>>>()
            .map(drop)?;
        self.rejected_transactions
            .iter()
            .map(|tx| tx.check_instruction_len(max_instruction_len))
            .collect::<Result<Vec<()>>>()
            .map(drop)?;
        Ok(())
    }

    /// Commit block to the store.
    //TODO: pass block store and block sender as parameters?
    pub fn commit(self) -> CommittedBlock {
        CommittedBlock {
            header: self.header,
            rejected_transactions: self.rejected_transactions,
            transactions: self.transactions,
            signatures: self.signatures,
        }
    }

    /// Validate block transactions against current state of the world.
    pub fn revalidate<W: WorldTrait>(
        self,
        wsv: &WorldStateView<W>,
        is_instruction_allowed: &IsInstructionAllowedBoxed<W>,
        is_query_allowed: &IsQueryAllowedBoxed<W>,
    ) -> ValidBlock {
        ValidBlock {
            signatures: self.signatures,
            ..ChainedBlock {
                header: self.header,
                transactions: self
                    .transactions
                    .into_iter()
                    .map(Into::into)
                    .chain(self.rejected_transactions.into_iter().map(Into::into))
                    .collect(),
            }
            .validate(wsv, is_instruction_allowed, is_query_allowed)
            .into_inner_v1()
        }
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Sign this block and get `ValidBlock`.
    ///
    /// # Errors
    /// Fails if generating signature fails
    pub fn sign(mut self, key_pair: &KeyPair) -> Result<ValidBlock> {
        let signature = Signature::new(key_pair.clone(), self.hash().as_ref())?;
        self.signatures.add(signature);
        Ok(self)
    }

    /// Signatures that are verified with the `hash` of this block as `payload`.
    pub fn verified_signatures(&self) -> Vec<Signature> {
        self.signatures.verified(self.hash().as_ref())
    }

    /// Checks if there are no transactions in this block.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty() && self.rejected_transactions.is_empty()
    }

    /// Checks if block has transactions that are already in blockchain.
    pub fn has_committed_transactions<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool {
        self.transactions
            .iter()
            .any(|transaction| transaction.is_in_blockchain(wsv))
            || self
                .rejected_transactions
                .iter()
                .any(|transaction| transaction.is_in_blockchain(wsv))
    }
}

impl From<&VersionedValidBlock> for Vec<Event> {
    fn from(block: &VersionedValidBlock) -> Self {
        block.as_inner_v1().into()
    }
}

impl From<&ValidBlock> for Vec<Event> {
    fn from(block: &ValidBlock) -> Self {
        block
            .transactions
            .iter()
            .cloned()
            .map(|transaction| {
                PipelineEvent::new(
                    PipelineEntityType::Transaction,
                    PipelineStatus::Validating,
                    transaction.hash(),
                )
                .into()
            })
            .chain(
                block
                    .rejected_transactions
                    .iter()
                    .cloned()
                    .map(|transaction| {
                        PipelineEvent::new(
                            PipelineEntityType::Transaction,
                            PipelineStatus::Validating,
                            transaction.hash(),
                        )
                        .into()
                    }),
            )
            .chain(iter::once(
                PipelineEvent::new(
                    PipelineEntityType::Block,
                    PipelineStatus::Validating,
                    block.hash(),
                )
                .into(),
            ))
            .collect()
    }
}

declare_versioned_with_scale!(VersionedCommittedBlock 1..2, Debug, Clone, iroha_derive::FromVariant);

impl VersionedCommittedBlock {
    /// Same as [`as_v1`](`VersionedCommittedBlock::as_v1()`) but also does conversion
    pub const fn as_inner_v1(&self) -> &CommittedBlock {
        match self {
            Self::V1(v1) => &v1.0,
        }
    }

    /// Same as [`as_inner_v1`](`VersionedCommittedBlock::as_inner_v1()`) but returns mutable reference
    pub fn as_mut_inner_v1(&mut self) -> &mut CommittedBlock {
        match self {
            Self::V1(v1) => &mut v1.0,
        }
    }

    /// Same as [`into_v1`](`VersionedCommittedBlock::into_v1()`) but also does conversion
    pub fn into_inner_v1(self) -> CommittedBlock {
        match self {
            Self::V1(v1) => v1.into(),
        }
    }

    /// Calculate hash of the current block.
    /// `VersionedCommitedBlock` should have the same hash as `VersionedCommitedBlock`.
    pub fn hash(&self) -> Hash {
        self.as_inner_v1().hash()
    }

    /// Returns header of valid block
    pub const fn header(&self) -> &BlockHeader {
        &self.as_inner_v1().header
    }

    /// Signatures that are verified with the `hash` of this block as `payload`.
    pub fn verified_signatures(&self) -> Vec<Signature> {
        self.as_inner_v1().verified_signatures()
    }
}

/// When Kura receives `ValidBlock`, the block is stored and
/// then sent to later stage of the pipeline as `CommitedBlock`.
#[version_with_scale(n = 1, versioned = "VersionedCommittedBlock", derive = "Debug, Clone")]
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct CommittedBlock {
    /// Header
    pub header: BlockHeader,
    /// Array of rejected transactions.
    pub rejected_transactions: Vec<VersionedRejectedTransaction>,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<VersionedValidTransaction>,
    /// Signatures of peers which approved this block
    pub signatures: Signatures,
}

impl CommittedBlock {
    /// Calculate hash of the current block.
    /// `CommitedBlock` should have the same hash as `ValidBlock`.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Signatures that are verified with the `hash` of this block as `payload`.
    pub fn verified_signatures(&self) -> Vec<Signature> {
        self.signatures.verified(self.hash().as_ref())
    }
}

impl From<CommittedBlock> for ValidBlock {
    fn from(
        CommittedBlock {
            header,
            rejected_transactions,
            transactions,
            signatures,
        }: CommittedBlock,
    ) -> Self {
        Self {
            header,
            rejected_transactions,
            transactions,
            signatures,
        }
    }
}

impl From<VersionedCommittedBlock> for VersionedValidBlock {
    fn from(block: VersionedCommittedBlock) -> Self {
        ValidBlock::from(block.into_inner_v1()).into()
    }
}

impl From<&VersionedCommittedBlock> for Vec<Event> {
    fn from(block: &VersionedCommittedBlock) -> Self {
        block.as_inner_v1().into()
    }
}

impl From<&CommittedBlock> for Vec<Event> {
    fn from(block: &CommittedBlock) -> Self {
        let rejected_tx = block
            .rejected_transactions
            .iter()
            .cloned()
            .map(|transaction| {
                PipelineEvent::new(
                    PipelineEntityType::Transaction,
                    PipelineStatus::Rejected(
                        transaction.as_inner_v1().rejection_reason.clone().into(),
                    ),
                    transaction.hash(),
                )
                .into()
            });
        let tx = block.transactions.iter().cloned().map(|transaction| {
            PipelineEvent::new(
                PipelineEntityType::Transaction,
                PipelineStatus::Committed,
                transaction.hash(),
            )
            .into()
        });
        let invalid_blocks = block
            .header
            .invalidated_blocks_hashes
            .iter()
            .copied()
            .map(|hash| {
                PipelineEvent::new(
                    PipelineEntityType::Block,
                    //TODO: store rejection reasons for blocks?
                    PipelineStatus::Rejected(PipelineRejectionReason::Block(
                        BlockRejectionReason::ConsensusBlockRejection,
                    )),
                    hash,
                )
                .into()
            });
        let current_block: iter::Once<Event> = iter::once(
            PipelineEvent::new(
                PipelineEntityType::Block,
                PipelineStatus::Committed,
                block.hash(),
            )
            .into(),
        );

        tx.chain(rejected_tx)
            .chain(invalid_blocks)
            .chain(current_block)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use iroha_crypto::{Hash, Signatures};

    use crate::{
        block::{BlockHeader, ValidBlock},
        sumeragi::view_change,
    };

    #[test]
    pub fn committed_and_valid_block_hashes_are_equal() {
        let valid_block = ValidBlock {
            header: BlockHeader {
                timestamp: 0,
                height: 0,
                previous_block_hash: Hash([0_u8; 32]),
                transactions_merkle_root_hash: Hash([0_u8; 32]),
                rejected_transactions_merkle_root_hash: Hash([0_u8; 32]),
                view_change_proofs: view_change::ProofChain::empty(),
                invalidated_blocks_hashes: Vec::new(),
                genesis_topology: None,
            },
            rejected_transactions: vec![],
            transactions: vec![],
            signatures: Signatures::default(),
        };
        let commited_block = valid_block.clone().commit();
        assert_eq!(valid_block.hash(), commited_block.hash())
    }
}
