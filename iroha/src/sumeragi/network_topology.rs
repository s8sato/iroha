//! Structs related to topology of the network - order and predefined roles of peers.

use std::{collections::HashSet, convert::TryInto, iter};

use eyre::{eyre, Result};
use iroha_crypto::{Hash, Signature};
use iroha_data_model::prelude::PeerId;
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

use super::view_change::{self, ProofChain as ViewChangeProofs};
use crate::block::EmptyChainHash;

/// Sorts peers based on the `hash`.
pub fn sort_peers_by_hash(peers: Vec<PeerId>, hash: Hash) -> Vec<PeerId> {
    sort_peers_by_hash_and_counter(peers, hash, 0)
}

/// Sorts peers based on the `hash` and `counter` combined as a seed.
pub fn sort_peers_by_hash_and_counter(
    mut peers: Vec<PeerId>,
    hash: Hash,
    counter: u64,
) -> Vec<PeerId> {
    peers.sort_by(|p1, p2| p1.address.cmp(&p2.address));
    let mut bytes: Vec<u8> = counter.to_le_bytes().to_vec();
    bytes.append(hash.as_ref().to_vec().as_mut());
    let Hash(bytes) = Hash::new(&bytes);
    let mut rng = StdRng::from_seed(bytes);
    peers.shuffle(&mut rng);
    peers
}

/// Shifts `sorted_peers` by one to the right.
#[allow(clippy::expect_used)]
pub fn shift_peers_by_one(mut peers: Vec<PeerId>) -> Vec<PeerId> {
    let last_element = peers.pop().expect("No elements found in sorted peers.");
    peers.insert(0, last_element);
    peers
}

/// Shifts `sorted_peers` by `n` to the right.
pub fn shift_peers_by_n(mut peers: Vec<PeerId>, n: u64) -> Vec<PeerId> {
    for _ in 0..n {
        peers = shift_peers_by_one(peers);
    }
    peers
}

macro_rules! field_is_some_or_err {
    ($s:ident.$f:ident) => {
        $s.$f.ok_or(eyre!(
            "Field with name {} should not be `None`.",
            stringify!($f)
        ))
    };
}

/// Alternative builder for genesis case.
/// Can set custom topology roles.
#[derive(Clone, Default, Debug)]
pub struct GenesisBuilder {
    leader: Option<PeerId>,

    set_a: Option<HashSet<PeerId>>,

    set_b: Option<HashSet<PeerId>>,

    reshuffle_after_n_view_changes: Option<u64>,
}

impl GenesisBuilder {
    /// Constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Specify which peer (it does not matter if currently in set a or b) should be leader in genesis round.
    pub fn with_leader(mut self, id: PeerId) -> Self {
        self.leader = Some(id);
        self
    }

    /// Set a - validators and leader and proxy tail.
    pub fn with_set_a(mut self, peers: HashSet<PeerId>) -> Self {
        self.set_a = Some(peers);
        self
    }

    /// Set b - observing peers
    pub fn with_set_b(mut self, peers: HashSet<PeerId>) -> Self {
        self.set_b = Some(peers);
        self
    }

    /// Set `reshuffle_after_n_view_changes` config param.
    pub fn reshuffle_after(mut self, n_view_changes: u64) -> Self {
        self.reshuffle_after_n_view_changes = Some(n_view_changes);
        self
    }

    /// Build and get topology.
    ///
    /// # Errors
    /// 1. Required field is ommitted.
    /// 2. Could not deduce max faults.
    /// 3. Not enough peers to be Byzantine fault tolerant
    /// 4. Max faults can not fit into u32.
    pub fn build(self) -> Result<Topology> {
        let leader = field_is_some_or_err!(self.leader)?;
        let mut set_a = field_is_some_or_err!(self.set_a)?;
        let mut set_b = field_is_some_or_err!(self.set_b)?;
        let reshuffle_after_n_view_changes =
            field_is_some_or_err!(self.reshuffle_after_n_view_changes)?;
        let max_faults_rem = (set_a.len() - 1) % 2;
        if max_faults_rem > 0 {
            return Err(eyre!("Could not deduce max faults. As given: 2f+1=set_a.len() We get a non integer f. f should be an integer."));
        }
        #[allow(clippy::integer_division)]
        let max_faults = (set_a.len() - 1_usize) / 2_usize;
        if set_b.len() < max_faults {
            return Err(eyre!(
                    "Not enough peers to be Byzantine fault tolerant. Expected least {} peers in `set_b`, got {}",
                    max_faults,
                    set_b.len(),
                ));
        }
        let _ = set_a.remove(&leader);
        let _ = set_b.remove(&leader);
        let sorted_peers: Vec<_> = iter::once(leader)
            .chain(set_a.into_iter())
            .chain(set_b.into_iter())
            .collect();
        Ok(Topology {
            sorted_peers,
            max_faults: max_faults.try_into()?,
            reshuffle_after_n_view_changes,
            at_block: EmptyChainHash.into(),
            view_change_proofs: ViewChangeProofs::empty(),
        })
    }
}

/// Builder of [`Topology`] struct.
#[derive(Clone, Debug, Default)]
pub struct Builder {
    /// Current order of peers. The roles of peers are defined based on this order.
    peers: Option<HashSet<PeerId>>,
    /// Maximum faulty peers in a network.
    max_faults: Option<u32>,

    reshuffle_after_n_view_changes: Option<u64>,

    at_block: Option<Hash>,

    view_change_proofs: ViewChangeProofs,
}

impl Builder {
    /// Constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set peers that participate in consensus.
    pub fn with_peers(mut self, peers: HashSet<PeerId>) -> Self {
        self.peers = Some(peers);
        self
    }

    /// Set maximum number of faulty peers that the network will tolerate.
    pub fn with_max_faults(mut self, max_faults: u32) -> Self {
        self.max_faults = Some(max_faults);
        self
    }

    /// Set `reshuffle_after_n_view_changes` config param.
    pub fn reshuffle_after(mut self, n_view_changes: u64) -> Self {
        self.reshuffle_after_n_view_changes = Some(n_view_changes);
        self
    }

    /// Set the latest committed block.
    pub fn at_block(mut self, block: Hash) -> Self {
        self.at_block = Some(block);
        self
    }

    /// Set number of view changes after the latest committed block. Default: 0
    pub fn with_view_changes(mut self, view_change_proofs: ViewChangeProofs) -> Self {
        self.view_change_proofs = view_change_proofs;
        self
    }

    /// Build and get topology.
    ///
    /// # Errors
    /// 1. Required field is ommitted.
    /// 2. Not enough peers to be Byzantine fault tolerant
    pub fn build(self) -> Result<Topology> {
        let peers = field_is_some_or_err!(self.peers)?;
        let max_faults = field_is_some_or_err!(self.max_faults)?;
        let reshuffle_after_n_view_changes =
            field_is_some_or_err!(self.reshuffle_after_n_view_changes)?;
        let at_block = field_is_some_or_err!(self.at_block)?;

        let min_peers = 3 * max_faults + 1;
        let peers: Vec<_> = peers.into_iter().collect();
        if peers.len() >= min_peers as usize {
            let sorted_peers =
                if self.view_change_proofs.len() as u64 > reshuffle_after_n_view_changes {
                    sort_peers_by_hash_and_counter(
                        peers,
                        at_block,
                        self.view_change_proofs.len() as u64,
                    )
                } else {
                    let peers = sort_peers_by_hash(peers, at_block);
                    shift_peers_by_n(peers, self.view_change_proofs.len() as u64)
                };
            Ok(Topology {
                sorted_peers,
                max_faults,
                reshuffle_after_n_view_changes,
                at_block,
                view_change_proofs: self.view_change_proofs,
            })
        } else {
            Err(eyre!(
                "Not enough peers to be Byzantine fault tolerant. Expected a least {} peers, got {}",
                min_peers,
                peers.len(),
            ))
        }
    }
}

/// Network topology - order of peers that defines their roles in this round.
#[derive(Clone, Debug, Encode, Decode)]
pub struct Topology {
    /// Current order of peers. The roles of peers are defined based on this order.
    sorted_peers: Vec<PeerId>,
    /// Maximum faulty peers in a network.
    max_faults: u32,

    reshuffle_after_n_view_changes: u64, // SATO renewal_period

    at_block: Hash,

    view_change_proofs: ViewChangeProofs,
}

impl Topology {
    /// Get Builder struct.
    pub fn builder() -> Builder {
        Builder::new()
    }

    /// Into Builder.
    pub fn into_builder(self) -> Builder {
        Builder {
            peers: Some(self.sorted_peers.into_iter().collect()),
            max_faults: Some(self.max_faults),
            reshuffle_after_n_view_changes: Some(self.reshuffle_after_n_view_changes),
            at_block: Some(self.at_block),
            view_change_proofs: self.view_change_proofs,
        }
    }

    /// Apply new committed block hash.
    #[allow(clippy::expect_used)]
    pub fn apply_block(&mut self, block_hash: Hash) {
        *self = self
            .clone()
            .into_builder()
            .at_block(block_hash)
            .with_view_changes(ViewChangeProofs::empty())
            .build()
            .expect("Given a valid Topology, it is impossible to have error here.")
    }

    /// Apply a view change - change topology in case there were faults in the consensus round.
    #[allow(clippy::expect_used)]
    pub fn apply_view_change(&mut self, proof: view_change::Proof) {
        let mut view_change_proofs = self.view_change_proofs.clone();
        view_change_proofs.push(proof);
        *self = self
            .clone()
            .into_builder()
            .with_view_changes(view_change_proofs)
            .build()
            .expect("Given a valid Topology, it is impossible to have error here.")
    }

    /// Answers if the consensus stage is required with the current number of peers.
    pub fn is_consensus_required(&self) -> bool {
        self.sorted_peers.len() > 1
    }

    /// The minimum number of signatures needed to commit a block
    pub const fn min_votes_for_commit(&self) -> u32 {
        2 * self.max_faults + 1
    }

    /// The minimum number of signatures needed to perform a view change (change leader, proxy, etc.)
    pub const fn min_votes_for_view_change(&self) -> u32 {
        self.max_faults + 1
    }

    /// Peers of set A. They participate in the consensus.
    pub fn peers_set_a(&self) -> &[PeerId] {
        let n_a_peers = 2 * self.max_faults + 1;
        &self.sorted_peers[..n_a_peers as usize]
    }

    /// Peers of set B. The watch the consensus process.
    pub fn peers_set_b(&self) -> &[PeerId] {
        &self.sorted_peers[(2 * self.max_faults + 1) as usize..]
    }

    /// The leader of the current round.
    #[allow(clippy::expect_used)]
    pub fn leader(&self) -> &PeerId {
        self.peers_set_a()
            .first()
            .expect("Failed to get first peer.")
    }

    /// The proxy tail of the current round.
    #[allow(clippy::expect_used)]
    pub fn proxy_tail(&self) -> &PeerId {
        self.peers_set_a().last().expect("Failed to get last peer.")
    }

    /// The peers that validate the block in discussion this round and vote for it to be accepted by the blockchain.
    pub fn validating_peers(&self) -> &[PeerId] {
        let a_set = self.peers_set_a();
        if a_set.len() > 1 {
            &a_set[1..(a_set.len() - 1)]
        } else {
            &[]
        }
    }

    /// Get role of the peer by its id.
    pub fn role(&self, peer_id: &PeerId) -> Role {
        if self.leader() == peer_id {
            Role::Leader
        } else if self.proxy_tail() == peer_id {
            Role::ProxyTail
        } else if self.validating_peers().contains(peer_id) {
            Role::ValidatingPeer
        } else {
            Role::ObservingPeer
        }
    }

    /// Verifies that this `message` was signed by the `signature` of a peer with specified `role`.
    ///
    /// # Errors
    /// Fails if there are no such peer with this key and if signature verification fails
    pub fn verify_signature_with_role(
        &self,
        signature: &Signature,
        role: Role,
        message_payload: &[u8],
    ) -> Result<()> {
        if role
            .peers(self)
            .iter()
            .any(|peer| peer.public_key == signature.public_key)
        {
            Ok(())
        } else {
            Err(eyre!("No {:?} with this public key exists.", role))
        }
        .and(signature.verify(message_payload))
    }

    /// Returns signatures of the peers with the specified `roles` from all `signatures`.
    pub fn filter_signatures_by_roles(
        &self,
        roles: &[Role],
        signatures: &[Signature],
    ) -> Vec<Signature> {
        let roles: HashSet<Role> = roles.iter().copied().collect();
        let public_keys: Vec<_> = roles
            .iter()
            .flat_map(|role| role.peers(self))
            .map(|peer| peer.public_key)
            .collect();
        signatures
            .iter()
            .filter(|signature| public_keys.contains(&signature.public_key))
            .cloned()
            .collect()
    }

    /// Sorted peers that this topology has.
    pub fn sorted_peers(&self) -> &[PeerId] {
        &self.sorted_peers[..]
    }

    /// Config param telling topology when to reshuffle at view change.
    pub const fn reshuffle_after(&self) -> u64 {
        self.reshuffle_after_n_view_changes
    }

    /// Block hash on which this topology is based.
    pub const fn at_block(&self) -> Hash {
        self.at_block
    }

    /// Number of view changes.
    pub const fn view_change_proofs(&self) -> &ViewChangeProofs {
        &self.view_change_proofs
    }

    /// Number of view changes.
    pub const fn max_faults(&self) -> u32 {
        self.max_faults
    }
}

/// Possible Peer's roles in consensus.
#[derive(Copy, Clone, Debug, Hash, PartialOrd, Ord, Eq, PartialEq)]
pub enum Role {
    /// Leader.
    Leader,
    /// Validating Peer.
    ValidatingPeer,
    /// Observing Peer.
    ObservingPeer,
    /// Proxy Tail.
    ProxyTail,
}

impl Role {
    /// Returns peers that have this `Role` in this voting round.
    pub fn peers(self, network_topology: &Topology) -> Vec<PeerId> {
        match self {
            Role::Leader => vec![network_topology.leader().clone()],
            Role::ValidatingPeer => network_topology.validating_peers().to_vec(),
            Role::ObservingPeer => network_topology.peers_set_b().to_vec(),
            Role::ProxyTail => vec![network_topology.proxy_tail().clone()],
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use iroha_crypto::KeyPair;

    use super::*;

    #[test]
    #[should_panic]
    fn not_enough_peers() {
        let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let listen_address = "127.0.0.1".to_owned();
        let this_peer: HashSet<PeerId> = vec![PeerId {
            address: listen_address,
            public_key: key_pair.public_key,
        }]
        .into_iter()
        .collect();
        let _network_topology = Topology::builder()
            .with_peers(this_peer)
            .with_max_faults(3)
            .reshuffle_after(1)
            .build()
            .expect("Failed to create topology.");
    }

    #[test]
    #[should_panic]
    fn wrong_number_of_peers_genesis() {
        let peer_1: PeerId = PeerId {
            address: "127.0.0.1".to_owned(),
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        };
        let peer_2: PeerId = PeerId {
            address: "127.0.0.2".to_owned(),
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        };
        let peer_3: PeerId = PeerId {
            address: "127.0.0.3".to_owned(),
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        };
        // set_a.len() = 2, is wrong as it is not possible to get integer f in: 2f + 1 = 2
        let set_a: HashSet<_> = vec![peer_1.clone(), peer_2].into_iter().collect();
        let set_b = vec![peer_3].into_iter().collect();
        let _network_topology = GenesisBuilder::new()
            .with_leader(peer_1)
            .with_set_a(set_a)
            .with_set_b(set_b)
            .reshuffle_after(1)
            .build()
            .expect("Failed to create topology.");
    }

    #[test]
    fn correct_number_of_peers_genesis() {
        let peers = topology_test_peers();
        // set_a.len() = 2, is wrong as it is not possible to get integer f in: 2f + 1 = 2
        let set_a: HashSet<_> = topology_test_peers().iter().cloned().take(3).collect();
        let set_b: HashSet<_> = topology_test_peers().iter().cloned().skip(3).collect();
        let _network_topology = GenesisBuilder::new()
            .with_leader(peers.iter().next().unwrap().clone())
            .with_set_a(set_a)
            .with_set_b(set_b)
            .reshuffle_after(1)
            .build()
            .expect("Failed to create topology.");
    }

    #[allow(clippy::expect_used)]
    fn topology_test_peers() -> HashSet<PeerId> {
        vec![
            PeerId {
                address: "127.0.0.1:7878".to_owned(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
            PeerId {
                address: "127.0.0.1:7879".to_owned(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
            PeerId {
                address: "127.0.0.1:7880".to_owned(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
            PeerId {
                address: "127.0.0.1:7881".to_owned(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn different_order() {
        let peers: Vec<_> = topology_test_peers().into_iter().collect();
        let peers_1 = sort_peers_by_hash(peers.clone(), Hash([1_u8; 32]));
        let peers_2 = sort_peers_by_hash(peers, Hash([2_u8; 32]));
        assert_ne!(peers_1, peers_2);
    }

    #[test]
    fn same_order() {
        let peers: Vec<_> = topology_test_peers().into_iter().collect();
        let peers_1 = sort_peers_by_hash(peers.clone(), Hash([2_u8; 32]));
        let peers_2 = sort_peers_by_hash(peers, Hash([2_u8; 32]));
        assert_eq!(peers_1, peers_2);
    }

    #[test]
    fn same_order_by_hash_and_counter() {
        let peers: Vec<_> = topology_test_peers().into_iter().collect();
        let peers_1 = sort_peers_by_hash_and_counter(peers.clone(), Hash([2_u8; 32]), 1);
        let peers_2 = sort_peers_by_hash_and_counter(peers, Hash([2_u8; 32]), 1);
        assert_eq!(peers_1, peers_2);
    }

    #[test]
    fn different_order_by_hash_and_counter() {
        let peers: Vec<_> = topology_test_peers().into_iter().collect();
        let peers_1 = sort_peers_by_hash_and_counter(peers.clone(), Hash([2_u8; 32]), 1);
        let peers_2 = sort_peers_by_hash_and_counter(peers, Hash([2_u8; 32]), 2);
        assert_ne!(peers_1, peers_2);
    }
}
