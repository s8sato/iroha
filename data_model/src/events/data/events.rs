//! This module contains data events

use iroha_data_model_derive::Filter;
use iroha_data_primitives::small::SmallVec;

use super::*;

mod asset {
    //! This module contains `AssetEvent`, `AssetDefinitionEvent` and its impls

    use super::*;

    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema, Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum AssetEvent {
        Created(AssetId),
        Deleted(AssetId),
        Added(AssetId),
        Removed(AssetId),
        MetadataInserted(AssetId),
        MetadataRemoved(AssetId),
    }

    impl Origin for AssetEvent {
        type Origin = AssetId;

        fn origin(&self) -> &AssetId {
            match self {
                Self::Created(id)
                | Self::Deleted(id)
                | Self::Added(id)
                | Self::Removed(id)
                | Self::MetadataInserted(id)
                | Self::MetadataRemoved(id) => id,
            }
        }
    }

    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema, Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum AssetDefinitionEvent {
        Created(AssetDefinitionId),
        MintabilityChanged(AssetDefinitionId),
        Deleted(AssetDefinitionId),
        MetadataInserted(AssetDefinitionId),
        MetadataRemoved(AssetDefinitionId),
    }
    // NOTE: Whenever you add a new event here, please also update the
    // AssetDefinitionEventFilter enum and its `impl Filter for
    // AssetDefinitionEventFilter`.

    impl Origin for AssetDefinitionEvent {
        type Origin = AssetDefinitionId;

        fn origin(&self) -> &AssetDefinitionId {
            match self {
                Self::Created(id)
                | Self::Deleted(id)
                | Self::MintabilityChanged(id)
                | Self::MetadataInserted(id)
                | Self::MetadataRemoved(id) => id,
            }
        }
    }
}

mod peer {
    //! This module contains `PeerEvent` and its impls

    use super::*;

    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema, Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum PeerEvent {
        Added(PeerId),
        Removed(PeerId),
    }

    impl Origin for PeerEvent {
        type Origin = PeerId;

        fn origin(&self) -> &PeerId {
            match self {
                Self::Added(id) | Self::Removed(id) => id,
            }
        }
    }
}

mod role {
    //! This module contains `RoleEvent` and its impls

    use super::*;

    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema, Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum RoleEvent {
        Created(RoleId),
        Deleted(RoleId),
    }

    impl Origin for RoleEvent {
        type Origin = RoleId;

        fn origin(&self) -> &RoleId {
            match self {
                Self::Created(id) | Self::Deleted(id) => id,
            }
        }
    }
}

mod account {
    //! This module contains `AccountEvent` and its impls

    use super::*;

    /// Account event
    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema, Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum AccountEvent {
        Asset(AssetEvent),
        Created(AccountId),
        Deleted(AccountId),
        AuthenticationAdded(AccountId),
        AuthenticationRemoved(AccountId),
        PermissionAdded(AccountId),
        PermissionRemoved(AccountId),
        RoleRevoked(AccountId),
        RoleGranted(AccountId),
        MetadataInserted(AccountId),
        MetadataRemoved(AccountId),
    }

    impl Origin for AccountEvent {
        type Origin = AccountId;

        fn origin(&self) -> &AccountId {
            match self {
                Self::Asset(asset) => &asset.origin().account_id,
                Self::Created(id)
                | Self::Deleted(id)
                | Self::AuthenticationAdded(id)
                | Self::AuthenticationRemoved(id)
                | Self::PermissionAdded(id)
                | Self::PermissionRemoved(id)
                | Self::RoleRevoked(id)
                | Self::RoleGranted(id)
                | Self::MetadataInserted(id)
                | Self::MetadataRemoved(id) => id,
            }
        }
    }
}

mod domain {
    //! This module contains `DomainEvent` and its impls

    use super::*;

    /// Domain Event
    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema, Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum DomainEvent {
        Account(AccountEvent),
        AssetDefinition(AssetDefinitionEvent),
        Created(DomainId),
        Deleted(DomainId),
        MetadataInserted(DomainId),
        MetadataRemoved(DomainId),
    }

    impl Origin for DomainEvent {
        type Origin = DomainId;

        fn origin(&self) -> &DomainId {
            match self {
                Self::Account(account) => &account.origin().domain_id,
                Self::AssetDefinition(asset_definition) => &asset_definition.origin().domain_id,
                Self::Created(id)
                | Self::Deleted(id)
                | Self::MetadataInserted(id)
                | Self::MetadataRemoved(id) => id,
            }
        }
    }
}

mod trigger {
    //! This module contains `TriggerEvent` and its impls

    use super::*;

    /// Trigger Event
    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema, Filter,
    )]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum TriggerEvent {
        Created(TriggerId),
        Deleted(TriggerId),
        Extended(TriggerId),
        Shortened(TriggerId),
    }

    impl Origin for TriggerEvent {
        type Origin = TriggerId;

        fn origin(&self) -> &TriggerId {
            match self {
                Self::Created(id)
                | Self::Deleted(id)
                | Self::Extended(id)
                | Self::Shortened(id) => id,
            }
        }
    }
}

pub trait Origin {
    type Origin: Eq + Ord + PartialOrd + IntoSchema;

    fn origin(&self) -> &Self::Origin;
}

/// World event
///
/// Does not participate in `Event`, but useful for events warranties when modifying `wsv`
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
#[allow(missing_docs)]
pub enum WorldEvent {
    Peer(peer::PeerEvent),
    Domain(domain::DomainEvent),
    Role(role::RoleEvent),
    Trigger(trigger::TriggerEvent),
}

/// Event
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum Event {
    /// Peer event
    Peer(peer::PeerEvent),
    /// Domain event
    Domain(domain::DomainEvent),
    /// Account event
    Account(account::AccountEvent),
    /// Asset definition event
    AssetDefinition(asset::AssetDefinitionEvent),
    /// Asset event
    Asset(asset::AssetEvent),
    /// Trigger event
    Trigger(trigger::TriggerEvent),
    /// Role event
    Role(role::RoleEvent),
}

impl From<WorldEvent> for SmallVec<[Event; 3]> {
    fn from(world_event: WorldEvent) -> Self {
        let mut events = SmallVec::new();

        match world_event {
            WorldEvent::Domain(domain_event) => {
                match &domain_event {
                    DomainEvent::Account(account_event) => {
                        if let AccountEvent::Asset(asset_event) = account_event {
                            events.push(DataEvent::Asset(asset_event.clone()));
                        }
                        events.push(DataEvent::Account(account_event.clone()));
                    }
                    DomainEvent::AssetDefinition(asset_definition_event) => {
                        events.push(DataEvent::AssetDefinition(asset_definition_event.clone()));
                    }
                    _ => (),
                }
                events.push(DataEvent::Domain(domain_event));
            }
            WorldEvent::Peer(peer_event) => {
                events.push(DataEvent::Peer(peer_event));
            }
            WorldEvent::Role(role_event) => {
                events.push(DataEvent::Role(role_event));
            }
            WorldEvent::Trigger(trigger_event) => {
                events.push(DataEvent::Trigger(trigger_event));
            }
        }

        events
    }
}

pub mod prelude {
    pub use super::{
        account::{AccountEvent, AccountEventFilter, AccountFilter},
        asset::{
            AssetDefinitionEvent, AssetDefinitionEventFilter, AssetDefinitionFilter, AssetEvent,
            AssetEventFilter, AssetFilter,
        },
        domain::{DomainEvent, DomainEventFilter, DomainFilter},
        peer::{PeerEvent, PeerEventFilter, PeerFilter},
        role::{RoleEvent, RoleEventFilter, RoleFilter},
        trigger::{TriggerEvent, TriggerEventFilter, TriggerFilter},
        Event as DataEvent, WorldEvent, Origin
    };
}
