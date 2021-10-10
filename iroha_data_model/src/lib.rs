//! Iroha Data Model contains structures for Domains, Peers, Accounts and Assets with simple,
//! non-specific functions like serialization.

#![allow(clippy::module_name_repetitions)]

use std::{convert::TryFrom, error, fmt::Debug, ops::RangeInclusive};

use eyre::{eyre, Result, WrapErr};
use iroha_crypto::PublicKey;
use iroha_derive::FromVariant;
use iroha_macro::error::ErrorTryFromEnum;
use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    account::SignatureCheckCondition, permissions::PermissionToken, transaction::TransactionValue,
};

pub mod events;
pub mod expression;
pub mod isi;
pub mod query;

/// `Name` struct represents type for Iroha Entities names, like [`Domain`](`domain::Domain`)'s name or [`Account`](`account::Account`)'s
/// name.
pub type Name = String;

/// Represents a sequence of bytes. Used for storing encoded data.
pub type Bytes = Vec<u8>;

#[allow(clippy::missing_errors_doc)]
/// Similar to [`std::convert::AsMut`] but indicating that this reference conversion can fail.
pub trait TryAsMut<T> {
    /// The type returned in the event of a conversion error.
    type Error;

    /// Performs the conversion.
    fn try_as_mut(&mut self) -> Result<&mut T, Self::Error>;
}

#[allow(clippy::missing_errors_doc)]
/// Similar to [`std::convert::AsRef`] but indicating that this reference conversion can fail.
pub trait TryAsRef<T> {
    /// The type returned in the event of a conversion error.
    type Error;

    /// Performs the conversion.
    fn try_as_ref(&self) -> Result<&T, Self::Error>;
}

/// Represents Iroha Configuration parameters.
#[derive(
    Copy,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    PartialOrd,
    Ord,
    Hash,
    IntoSchema,
)]
pub enum Parameter {
    /// Maximum amount of Faulty Peers in the system.
    MaximumFaultyPeersAmount(u32),
    /// Maximum time for a leader to create a block.
    BlockTime(u128),
    /// Maximum time for a proxy tail to send commit message.
    CommitTime(u128),
    /// Time to wait for a transaction Receipt.
    TransactionReceiptTime(u128),
}

/// Sized container for all possible identifications.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    PartialEq,
    Eq,
    FromVariant,
    PartialOrd,
    Ord,
    IntoSchema,
)]
pub enum IdBox {
    /// [`AccountId`](`account::Id`) variant.
    AccountId(account::Id),
    /// [`AssetId`](`asset::Id`) variant.
    AssetId(asset::Id),
    /// [`AssetDefinitionId`](`asset::DefinitionId`) variant.
    AssetDefinitionId(asset::DefinitionId),
    /// [`DomainName`](`Name`) variant.
    DomainName(Name),
    /// [`PeerId`](`peer::Id`) variant.
    PeerId(peer::Id),
    /// [`RoleId`](`role::Id`) variant.
    #[cfg(feature = "roles")]
    RoleId(role::Id),
    /// `World`.
    WorldId,
}

/// Sized container for all possible entities.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    PartialEq,
    Eq,
    FromVariant,
    PartialOrd,
    Ord,
    IntoSchema,
)]
pub enum IdentifiableBox {
    /// [`Account`](`account::Account`) variant.
    Account(Box<account::Account>),
    /// [`NewAccount`](`account::NewAccount`) variant.
    NewAccount(Box<account::NewAccount>),
    /// [`Asset`](`asset::Asset`) variant.
    Asset(Box<asset::Asset>),
    /// [`AssetDefinition`](`asset::AssetDefinition`) variant.
    AssetDefinition(Box<asset::AssetDefinition>),
    /// [`Domain`](`domain::Domain`) variant.
    Domain(Box<domain::Domain>),
    /// [`Peer`](`peer::Peer`) variant.
    Peer(Box<peer::Peer>),
    /// [`Role`](`role::Role`) variant.
    #[cfg(feature = "roles")]
    Role(Box<role::Role>),
    /// [`World`](`world::World`).
    World,
}

/// Boxed [`Value`].
pub type ValueBox = Box<Value>;

/// Sized container for all possible values.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    PartialEq,
    Eq,
    FromVariant,
    PartialOrd,
    Ord,
    IntoSchema,
)]
#[allow(clippy::enum_variant_names)]
// SATO can be better separated
pub enum Value {
    /// `u32` integer.
    U32(u32),
    /// `bool` value.
    Bool(bool),
    /// `String` value.
    String(String),
    /// `Fixed` value
    Fixed(fixed::Fixed),
    /// `Vec` of `Value`.
    Vec(
        #[skip_from]
        #[skip_try_from]
        Vec<Value>,
    ),
    /// `Id` of `Asset`, `Account`, etc.
    Id(IdBox),
    /// `Identifiable` as `Asset`, `Account` etc.
    Identifiable(IdentifiableBox),
    /// `PublicKey`.
    PublicKey(PublicKey),
    /// Iroha `Parameter` variant.
    Parameter(Parameter),
    /// Signature check condition.
    SignatureCheckCondition(SignatureCheckCondition),
    /// Committed or rejected transactions
    TransactionValue(TransactionValue),
    /// Permission token.
    PermissionToken(PermissionToken),
}

#[allow(clippy::len_without_is_empty)]
impl Value {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        use Value::*;

        match self {
            U32(_) | Id(_) | PublicKey(_) | Bool(_) | Parameter(_) | Identifiable(_)
            | String(_) | Fixed(_) | TransactionValue(_) | PermissionToken(_) => 1,
            Vec(v) => v.iter().map(Self::len).sum::<usize>() + 1,
            SignatureCheckCondition(s) => s.0.len(),
        }
    }
}

macro_rules! from_and_try_from_value_idbox {
    ( $($variant:ident( $ty:ty ),)* ) => {
        $(
            impl TryFrom<Value> for $ty {
                type Error = ErrorTryFromEnum<Self, Value>;

                fn try_from(value: Value) -> Result<Self, Self::Error> {
                    if let Value::Id(IdBox::$variant(id)) = value {
                        Ok(id)
                    } else {
                        Err(Self::Error::default())
                    }
                }
            }

            impl From<$ty> for Value {
                fn from(id: $ty) -> Self {
                    Value::Id(IdBox::$variant(id))
                }
            }
        )*
    };
}

from_and_try_from_value_idbox!(
    AccountId(account::Id),
    AssetId(asset::Id),
    AssetDefinitionId(asset::DefinitionId),
    PeerId(peer::Id),
);
// TODO: Should we wrap String with new type in order to convert like here?
//from_and_try_from_value_idbox!((DomainName(Name), ErrorValueTryFromDomainName),);

macro_rules! from_and_try_from_value_identifiablebox {
    ( $( $variant:ident( Box< $ty:ty > ),)* ) => {
        $(
            impl TryFrom<Value> for $ty {
                type Error = ErrorTryFromEnum<Self, Value>;

                fn try_from(value: Value) -> Result<Self, Self::Error> {
                    if let Value::Identifiable(IdentifiableBox::$variant(id)) = value {
                        Ok(*id)
                    } else {
                        Err(Self::Error::default())
                    }
                }
            }

            impl From<$ty> for Value {
                fn from(id: $ty) -> Self {
                    Value::Identifiable(IdentifiableBox::$variant(Box::new(id)))
                }
            }
        )*
    };
}
macro_rules! from_and_try_from_value_identifiable {
    ( $( $variant:ident( $ty:ty ), )* ) => {
        $(
            impl TryFrom<Value> for $ty {
                type Error = ErrorTryFromEnum<Self, Value>;

                fn try_from(value: Value) -> Result<Self, Self::Error> {
                    if let Value::Identifiable(IdentifiableBox::$variant(id)) = value {
                        Ok(id)
                    } else {
                        Err(Self::Error::default())
                    }
                }
            }

            impl From<$ty> for Value {
                fn from(id: $ty) -> Self {
                    Value::Identifiable(IdentifiableBox::$variant(id))
                }
            }
        )*
    };
}

from_and_try_from_value_identifiablebox!(
    Account(Box<account::Account>),
    NewAccount(Box<account::NewAccount>),
    Asset(Box<asset::Asset>),
    AssetDefinition(Box<asset::AssetDefinition>),
    Domain(Box<domain::Domain>),
    Peer(Box<peer::Peer>),
);
from_and_try_from_value_identifiable!(
    Account(Box<account::Account>),
    NewAccount(Box<account::NewAccount>),
    Asset(Box<asset::Asset>),
    AssetDefinition(Box<asset::AssetDefinition>),
    Domain(Box<domain::Domain>),
    Peer(Box<peer::Peer>),
);

impl<V: Into<Value>> From<Vec<V>> for Value {
    fn from(values: Vec<V>) -> Value {
        Value::Vec(values.into_iter().map(Into::into).collect())
    }
}

impl<V> TryFrom<Value> for Vec<V>
where
    V: TryFrom<Value>,
    <V as TryFrom<Value>>::Error: Send + Sync + error::Error + 'static,
{
    type Error = eyre::Error;
    fn try_from(value: Value) -> Result<Vec<V>> {
        if let Value::Vec(vec) = value {
            vec.into_iter()
                .map(V::try_from)
                .collect::<Result<Vec<_>, _>>()
                .wrap_err("Failed to convert to vector")
        } else {
            Err(eyre!("Expected vector, but found something else"))
        }
    }
}

impl From<u128> for Value {
    fn from(n: u128) -> Value {
        // TODO: ???
        #[allow(clippy::cast_possible_truncation)]
        Value::U32(n as u32)
    }
}

/// Marker trait for values.
pub trait ValueMarker: Debug + Clone + Into<Value> {}

impl<V: Into<Value> + Debug + Clone> ValueMarker for V {}

/// This trait marks entity that implement it as identifiable with an `Id` type to find them by.
pub trait Identifiable: Debug + Clone {
    /// Defines the type of entity's identification.
    type Id: Into<IdBox> + Debug + Clone + Eq + Ord;
}

/// Limits of length of the identifiers (e.g. in [`domain::Domain`], [`account::NewAccount`], [`asset::AssetDefinition`]) in number of chars
#[derive(Debug, Clone, Copy, Decode, Encode, Serialize, Deserialize)]
pub struct LengthLimits {
    /// Minimal length in number of chars (inclusive).
    min: u32,
    /// Maximal length in number of chars (inclusive).
    max: u32,
}

impl LengthLimits {
    /// Constructor.
    pub const fn new(min: u32, max: u32) -> Self {
        Self { min, max }
    }
}

impl From<LengthLimits> for RangeInclusive<usize> {
    fn from(limits: LengthLimits) -> Self {
        RangeInclusive::new(limits.min as usize, limits.max as usize)
    }
}

pub mod world {
    //! Structures, traits and impls related to `World`.
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    #[cfg(feature = "roles")]
    use crate::role::RolesMap;
    use crate::{
        domain::{Domain, DomainsMap},
        isi::Instruction,
        peer::{Id as PeerId, PeersIds},
        IdBox, Identifiable, IdentifiableBox, Name, Parameter,
    };

    /// The global entity consisting of `domains`, `triggers` and etc.
    /// For example registration of domain, will have this as an ISI target.
    #[derive(Debug, Default, Clone)]
    pub struct World {
        /// Registered domains.
        pub domains: DomainsMap,
        /// Identifications of discovered trusted peers.
        pub trusted_peers_ids: PeersIds,
        /// Iroha `Triggers` registered on the peer.
        pub triggers: Vec<Instruction>,
        /// Iroha parameters.
        pub parameters: Vec<Parameter>,
        /// Roles.
        #[cfg(feature = "roles")]
        pub roles: RolesMap,
    }

    impl World {
        /// Creates an empty `World`.
        pub fn new() -> Self {
            Self::default()
        }

        /// Creates `World` with these `domains` and `trusted_peers_ids`
        pub fn with(
            domains: impl IntoIterator<Item = (Name, Domain)>,
            trusted_peers_ids: impl IntoIterator<Item = PeerId>,
        ) -> Self {
            let domains = domains.into_iter().collect();
            let trusted_peers_ids = trusted_peers_ids.into_iter().collect();
            World {
                domains,
                trusted_peers_ids,
                ..World::new()
            }
        }
    }

    /// The ID of the `World`. The `World` has only a single instance, therefore the ID has no fields.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Copy,
        Serialize,
        Deserialize,
        Decode,
        Encode,
        IntoSchema,
    )]
    pub struct WorldId;

    impl From<WorldId> for IdBox {
        fn from(_: WorldId) -> IdBox {
            IdBox::WorldId
        }
    }

    impl Identifiable for World {
        type Id = WorldId;
    }

    impl From<World> for IdentifiableBox {
        fn from(_: World) -> Self {
            IdentifiableBox::World
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{World, WorldId};
    }
}

#[cfg(feature = "roles")]
pub mod role {
    //! Structures, traits and impls related to `Role`s.

    use std::{
        collections::BTreeSet,
        convert::TryFrom,
        fmt::{Display, Formatter, Result as FmtResult},
    };

    use dashmap::DashMap;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{permissions::PermissionToken, IdBox, Identifiable, IdentifiableBox, Name, Value};

    /// `RolesMap` provides an API to work with collection of key (`Id`) - value
    /// (`Role`) pairs.
    pub type RolesMap = DashMap<Id, Role>;

    /// Identification of a role.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        Hash,
        IntoSchema,
    )]
    pub struct Id {
        /// Role name, should be unique .
        pub name: Name,
    }

    impl Id {
        /// Constructor.
        pub fn new(name: impl Into<Name>) -> Self {
            Id { name: name.into() }
        }
    }

    impl From<Name> for Id {
        fn from(name: Name) -> Self {
            Id::new(name)
        }
    }

    impl From<Id> for Value {
        fn from(id: Id) -> Self {
            Value::Id(IdBox::RoleId(id))
        }
    }

    impl TryFrom<Value> for Id {
        type Error = iroha_macro::error::ErrorTryFromEnum<Value, Id>;

        fn try_from(value: Value) -> Result<Self, Self::Error> {
            if let Value::Id(IdBox::RoleId(id)) = value {
                Ok(id)
            } else {
                Err(Self::Error::default())
            }
        }
    }

    impl Display for Id {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            write!(f, "{}", self.name)
        }
    }

    impl From<Role> for Value {
        fn from(role: Role) -> Self {
            IdentifiableBox::from(Box::new(role)).into()
        }
    }

    impl TryFrom<Value> for Role {
        type Error = iroha_macro::error::ErrorTryFromEnum<Value, Role>;

        fn try_from(value: Value) -> Result<Self, Self::Error> {
            if let Value::Identifiable(IdentifiableBox::Role(role)) = value {
                Ok(*role)
            } else {
                Err(Self::Error::default())
            }
        }
    }

    /// Role is a tag for a set of permission tokens.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        IntoSchema,
    )]
    pub struct Role {
        /// Unique name of the role.
        pub id: Id,
        /// Permission tokens.
        pub permissions: BTreeSet<PermissionToken>,
    }

    impl Role {
        /// Constructor.
        pub fn new(id: impl Into<Id>, permissions: impl Into<BTreeSet<PermissionToken>>) -> Role {
            Role {
                id: id.into(),
                permissions: permissions.into(),
            }
        }
    }

    impl Identifiable for Role {
        type Id = Id;
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{Id as RoleId, Role};
    }
}

pub mod permissions {
    //! Structures, traits and impls related to `Permission`s.

    use std::collections::BTreeMap;

    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{Name, Value};

    /// Stored proof of the account having a permission for a certain action.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        IntoSchema,
    )]
    pub struct PermissionToken {
        /// Name of the permission rule given to account.
        // SATO token name as string is not a good way in Rust
        pub name: Name,
        /// Params identifying how this rule applies. // SATO ?
        pub params: BTreeMap<Name, Value>,
    }

    impl PermissionToken {
        /// Constructor.
        pub fn new(name: impl Into<Name>, params: BTreeMap<Name, Value>) -> Self {
            PermissionToken {
                name: name.into(),
                params,
            }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::PermissionToken;
    }
}

pub mod account {
    //! Structures, traits and impls related to `Account`s.

    use std::{
        collections::{BTreeMap, BTreeSet},
        fmt,
        iter::FromIterator,
        ops::RangeInclusive,
    };

    use eyre::{eyre, Error, Result};
    //TODO: get rid of it?
    use iroha_crypto::prelude::*;
    use iroha_derive::Io;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    #[cfg(feature = "roles")]
    use crate::role::Id as RoleId;
    use crate::{
        asset::AssetsMap,
        domain::GENESIS_DOMAIN_NAME,
        expression::{ContainsAny, ContextValue, EvaluatesTo, ExpressionBox, WhereBuilder},
        metadata::Metadata,
        permissions::PermissionToken,
        world::World,
        Identifiable, Name, PublicKey, Value,
    };

    /// `AccountsMap` provides an API to work with collection of key (`Id`) - value
    /// (`Account`) pairs.
    pub type AccountsMap = BTreeMap<Id, Account>;
    type Signatories = Vec<PublicKey>;
    type Permissions = BTreeSet<PermissionToken>;

    /// Genesis account name.
    pub const GENESIS_ACCOUNT_NAME: &str = "genesis";

    /// The context value name for transaction signatories.
    pub const TRANSACTION_SIGNATORIES_VALUE: &str = "transaction_signatories";

    /// The context value name for account signatories.
    pub const ACCOUNT_SIGNATORIES_VALUE: &str = "account_signatories";

    /// Genesis account. Used to mainly be converted to ordinary `Account` struct.
    #[derive(Debug, Serialize, Deserialize, Decode, Encode, IntoSchema)]
    pub struct GenesisAccount {
        public_key: PublicKey,
    }

    impl GenesisAccount {
        /// Returns `GenesisAccount` instance.
        pub const fn new(public_key: PublicKey) -> Self {
            GenesisAccount { public_key }
        }
    }

    impl From<GenesisAccount> for Account {
        fn from(account: GenesisAccount) -> Self {
            Account::with_signatory(Id::genesis_account(), account.public_key)
        }
    }

    /// Condition which checks if the account has the right signatures.
    #[derive(
        Clone,
        Debug,
        PartialEq,
        Eq,
        Serialize,
        Deserialize,
        Io,
        Encode,
        Decode,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct SignatureCheckCondition(pub EvaluatesTo<bool>);

    impl SignatureCheckCondition {
        /// Gets reference to the raw `ExpressionBox`.
        pub const fn as_expression(&self) -> &ExpressionBox {
            let Self(condition) = self;
            &condition.expression
        }
    }

    impl From<EvaluatesTo<bool>> for SignatureCheckCondition {
        fn from(condition: EvaluatesTo<bool>) -> Self {
            SignatureCheckCondition(condition)
        }
    }

    /// Default signature condition check for accounts. Returns true if any of the signatories have signed a transaction.
    impl Default for SignatureCheckCondition {
        fn default() -> Self {
            Self(
                ContainsAny::new(
                    ContextValue::new(TRANSACTION_SIGNATORIES_VALUE),
                    ContextValue::new(ACCOUNT_SIGNATORIES_VALUE),
                )
                .into(),
            )
        }
    }

    /// Type which is used for registering `Account`
    #[derive(
        Clone,
        Debug,
        PartialEq,
        Eq,
        Serialize,
        Deserialize,
        Io,
        Encode,
        Decode,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    pub struct NewAccount {
        /// An Identification of the `NewAccount`.
        pub id: Id,
        /// `Account`'s signatories.
        pub signatories: Signatories,
        /// Metadata of this account as a key-value store.
        pub metadata: Metadata,
    }

    impl From<NewAccount> for Account {
        fn from(account: NewAccount) -> Self {
            let NewAccount {
                id,
                signatories,
                metadata,
            } = account;
            Self {
                id,
                signatories,
                metadata,
                assets: AssetsMap::new(),
                permission_tokens: Permissions::default(),
                signature_check_condition: SignatureCheckCondition::default(),
                #[cfg(feature = "roles")]
                roles: BTreeSet::default(),
            }
        }
    }

    impl NewAccount {
        /// Default `NewAccount` constructor.
        pub fn new(id: Id) -> Self {
            Self {
                id,
                signatories: Signatories::new(),
                metadata: Metadata::default(),
            }
        }

        /// Account with single `signatory` constructor.
        pub fn with_signatory(id: Id, signatory: PublicKey) -> Self {
            let signatories = vec![signatory];
            Self {
                id,
                signatories,
                metadata: Metadata::default(),
            }
        }

        /// Checks the length of the id in bytes is in a valid range
        ///
        /// # Errors
        /// Fails if limit check fails
        pub fn validate_len(&self, range: impl Into<RangeInclusive<usize>>) -> Result<()> {
            let range = range.into();
            if range.contains(&self.id.name.chars().count()) {
                Ok(())
            } else {
                Err(eyre!(
                    "Length of the account name must be in range {}-{}",
                    &range.start(),
                    &range.end()
                ))
            }
        }
    }

    /// Account entity is an authority which is used to execute `Iroha Special Instructions`.
    #[derive(
        Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Io, Encode, Decode, IntoSchema,
    )]
    pub struct Account {
        /// An Identification of the [`Account`].
        pub id: Id,
        /// Asset's in this [`Account`].
        pub assets: AssetsMap,
        /// [`Account`]'s signatories.
        pub signatories: Signatories,
        /// Permissions tokens of this account
        pub permission_tokens: Permissions,
        /// Condition which checks if the account has the right signatures.
        #[serde(default)]
        pub signature_check_condition: SignatureCheckCondition,
        /// Metadata of this account as a key-value store.
        pub metadata: Metadata,
        /// Roles of this account, they are tags for sets of permissions stored in [`World`].
        #[cfg(feature = "roles")]
        pub roles: BTreeSet<RoleId>,
    }

    impl PartialOrd for Account {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            self.id.partial_cmp(&other.id)
        }
    }

    impl Ord for Account {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.id.cmp(&other.id)
        }
    }

    /// Identification of an Account. Consists of Account's name and Domain's name.
    ///
    /// # Example
    ///
    /// ```
    /// use iroha_data_model::account::Id;
    ///
    /// let id = Id::new("user", "company");
    /// ```
    #[derive(
        Clone,
        Debug,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Serialize,
        Deserialize,
        Io,
        Encode,
        Decode,
        IntoSchema,
    )]
    pub struct Id {
        /// [`Account`]'s name.
        pub name: Name,
        /// [`Account`]'s [`Domain`](`crate::domain::Domain`)'s name.
        pub domain_name: Name,
    }

    impl Account {
        /// Default [`Account`] constructor.
        pub fn new(id: Id) -> Self {
            Account {
                id,
                assets: AssetsMap::new(),
                signatories: Vec::new(),
                permission_tokens: Permissions::new(),
                signature_check_condition: SignatureCheckCondition::default(),
                metadata: Metadata::new(),
                #[cfg(feature = "roles")]
                roles: BTreeSet::new(),
            }
        }

        /// Account with single `signatory` constructor.
        pub fn with_signatory(id: Id, signatory: PublicKey) -> Self {
            let signatories = vec![signatory];
            Account {
                id,
                assets: AssetsMap::new(),
                signatories,
                permission_tokens: Permissions::new(),
                signature_check_condition: SignatureCheckCondition::default(),
                metadata: Metadata::new(),
                #[cfg(feature = "roles")]
                roles: BTreeSet::new(),
            }
        }

        /// Returns a prebuilt expression that when executed
        /// returns if the needed signatures are gathered.
        pub fn check_signature_condition<'a>(
            &'a self,
            signatures: impl IntoIterator<Item = &'a Signature>,
        ) -> EvaluatesTo<bool> {
            let transaction_signatories: Signatories = signatures
                .into_iter()
                .map(|signature| &signature.public_key)
                .cloned()
                .collect();
            WhereBuilder::evaluate(self.signature_check_condition.as_expression().clone())
                .with_value(
                    TRANSACTION_SIGNATORIES_VALUE.to_owned(),
                    transaction_signatories,
                )
                .with_value(
                    ACCOUNT_SIGNATORIES_VALUE.to_owned(),
                    self.signatories.clone(),
                )
                .build()
                .into()
        }

        /// Inserts permission token into account.
        pub fn insert_permission_token(&mut self, token: PermissionToken) -> bool {
            self.permission_tokens.insert(token)
        }

        /// Returns a set of permission tokens granted to this account as part of roles and separately.
        #[cfg(feature = "roles")]
        pub fn permission_tokens(&self, world: &World) -> Permissions {
            let mut tokens = self.permission_tokens.clone();
            for role_id in &self.roles {
                if let Some(role) = world.roles.get(role_id) {
                    let mut role_tokens = role.permissions.clone();
                    tokens.append(&mut role_tokens);
                }
            }
            tokens
        }

        /// Returns a set of permission tokens granted to this account as part of roles and separately.
        #[cfg(not(feature = "roles"))]
        pub fn permission_tokens(&self, _: &World) -> Permissions {
            self.permission_tokens.clone()
        }
    }

    impl Id {
        /// `Id` constructor used to easily create an `Id` from two string slices - one for the
        /// account's name, another one for the container's name.
        pub fn new(name: &str, domain_name: &str) -> Self {
            Id {
                name: name.to_owned(),
                domain_name: domain_name.to_owned(),
            }
        }

        /// `Id` of the genesis account.
        pub fn genesis_account() -> Self {
            Id {
                name: GENESIS_ACCOUNT_NAME.to_owned(),
                domain_name: GENESIS_DOMAIN_NAME.to_owned(),
            }
        }
    }

    impl Identifiable for NewAccount {
        type Id = Id;
    }

    impl Identifiable for Account {
        type Id = Id;
    }

    impl FromIterator<Account> for Value {
        fn from_iter<T: IntoIterator<Item = Account>>(iter: T) -> Self {
            iter.into_iter()
                .map(|account| account.into())
                .collect::<Vec<Value>>()
                .into()
        }
    }

    /// Account Identification is represented by `name@domain_name` string.
    impl std::str::FromStr for Id {
        type Err = Error;

        fn from_str(string: &str) -> Result<Self, Self::Err> {
            let vector: Vec<&str> = string.split('@').collect();
            if vector.len() != 2 {
                return Err(eyre!("Id should have format `name@domain_name`"));
            }
            Ok(Id {
                name: String::from(vector[0]),
                domain_name: String::from(vector[1]),
            })
        }
    }

    impl fmt::Display for Id {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}@{}", self.name, self.domain_name)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Account, Id as AccountId, NewAccount, SignatureCheckCondition};
    }
}

/// An encapsulation of [`fixnum::FixedPoint`] in encodable form.
pub mod fixed {
    use core::cmp::Ordering;
    use std::convert::TryFrom;

    use fixnum::{
        ops::{CheckedAdd, CheckedSub, Zero},
        typenum::U9,
        ConvertError, FixedPoint,
    };
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode, Error, Input, Output};
    use serde::{Deserialize, Serialize};

    /// Base type for fixed implementation. May be changed in forks.
    /// To change implementation to i128 or other type you will need to change it in Cargo.toml.
    type Base = i64;

    /// Signed fixed point amount over 64 bits, 9 decimal places.
    ///
    /// MAX = (2 ^ (`BITS_COUNT` - 1) - 1) / 10 ^ PRECISION =
    ///     = (2 ^ (64 - 1) - 1) / 1e9 =
    ///     = 9223372036.854775807 ~ 9.2e9
    /// `ERROR_MAX` = 0.5 / (10 ^ PRECISION) =
    ///           = 0.5 / 1e9 =
    ///           = 5e-10
    pub type FixNum = FixedPoint<Base, U9>;

    /// An encapsulation of [`Fixed`] in encodable form.
    #[derive(Clone, Copy, Debug, Serialize, Deserialize, IntoSchema)]
    pub struct Fixed(FixNum);

    impl Fixed {
        /// Constant, representing zero value
        pub const ZERO: Fixed = Fixed(FixNum::ZERO);

        /// Checks if this instance is zero
        pub const fn is_zero(self) -> bool {
            *self.0.as_bits() == Base::ZERO
        }

        /// Checked addition
        pub fn checked_add(self, rhs: Self) -> Option<Self> {
            match self.0.cadd(rhs.0) {
                Ok(n) => Some(Fixed(n)),
                Err(_) => None,
            }
        }

        /// Checked subtraction
        pub fn checked_sub(self, rhs: Self) -> Option<Self> {
            match self.0.csub(rhs.0) {
                Ok(n) => Some(Fixed(n)),
                Err(_) => None,
            }
        }
    }

    impl TryFrom<f64> for Fixed {
        type Error = ConvertError;

        fn try_from(value: f64) -> Result<Self, Self::Error> {
            match FixNum::try_from(value) {
                Ok(n) => Ok(Fixed(n)),
                Err(e) => Err(e),
            }
        }
    }

    impl PartialEq for Fixed {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }

    impl Eq for Fixed {}

    impl PartialOrd for Fixed {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            self.0.partial_cmp(&other.0)
        }
    }

    impl Ord for Fixed {
        fn cmp(&self, other: &Self) -> Ordering {
            self.0.cmp(&other.0)
        }
    }

    impl Encode for Fixed {
        fn size_hint(&self) -> usize {
            std::mem::size_of::<Base>()
        }

        fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
            let bits = self.0.into_bits();
            let buf = bits.to_le_bytes();
            dest.write(&buf);
        }
    }

    impl Decode for Fixed {
        fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
            let mut buf = [0_u8; std::mem::size_of::<Base>()];
            input.read(&mut buf)?;
            let value = Base::from_le_bytes(buf);
            Ok(Fixed(FixedPoint::from_bits(value)))
        }

        fn encoded_fixed_size() -> Option<usize> {
            Some(std::mem::size_of::<Base>())
        }
    }

    /// Export of inner items.
    pub mod prelude {
        pub use super::Fixed;
    }
}

pub mod asset {
    //! This module contains [`Asset`] structure, it's implementation and related traits and
    //! instructions implementations.

    use std::{
        cmp::Ordering,
        collections::BTreeMap,
        fmt::{self, Display, Formatter},
        iter::FromIterator,
        ops::RangeInclusive,
        str::FromStr,
    };

    use eyre::{eyre, Error, Result, WrapErr};
    use iroha_derive::{FromVariant, Io};
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{
        account::prelude::*,
        fixed,
        fixed::Fixed,
        metadata::{Limits as MetadataLimits, Metadata},
        Identifiable, Name, TryAsMut, TryAsRef, Value,
    };

    /// [`AssetsMap`] provides an API to work with collection of key ([`Id`]) - value
    /// ([`Asset`]) pairs.
    pub type AssetsMap = BTreeMap<Id, Asset>;
    /// [`AssetDefinitionsMap`] provides an API to work with collection of key ([`DefinitionId`]) - value
    /// (`AssetDefinition`) pairs.
    pub type AssetDefinitionsMap = BTreeMap<DefinitionId, AssetDefinitionEntry>;

    /// An entry in [`AssetDefinitionsMap`].
    #[derive(
        Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Io, Encode, Decode, IntoSchema,
    )]
    pub struct AssetDefinitionEntry {
        /// Asset definition.
        pub definition: AssetDefinition,
        /// The account that registered this asset.
        pub registered_by: AccountId,
    }

    impl PartialOrd for AssetDefinitionEntry {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.definition.cmp(&other.definition))
        }
    }

    impl Ord for AssetDefinitionEntry {
        fn cmp(&self, other: &Self) -> Ordering {
            self.definition.cmp(&other.definition)
        }
    }

    impl AssetDefinitionEntry {
        /// Constructor.
        pub const fn new(
            definition: AssetDefinition,
            registered_by: AccountId,
        ) -> AssetDefinitionEntry {
            AssetDefinitionEntry {
                definition,
                registered_by,
            }
        }
    }

    /// Asset definition defines type of that asset.
    #[derive(
        Clone,
        Debug,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Serialize,
        Deserialize,
        Io,
        Encode,
        Decode,
        IntoSchema,
    )]
    pub struct AssetDefinition {
        /// Type of [`AssetValue`]
        pub value_type: AssetValueType,
        /// An Identification of the [`AssetDefinition`].
        pub id: DefinitionId,
        /// Metadata of this asset definition as a key-value store.
        pub metadata: Metadata,
    }

    /// Asset represents some sort of commodity or value.
    /// All possible variants of [`Asset`] entity's components.
    #[derive(
        Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Io, Encode, Decode, IntoSchema,
    )]
    pub struct Asset {
        /// Component Identification.
        pub id: Id,
        /// Asset's Quantity.
        pub value: AssetValue,
    }

    /// Asset's inner value type.
    #[derive(
        Copy,
        Clone,
        Debug,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Serialize,
        Deserialize,
        Io,
        Encode,
        Decode,
        IntoSchema,
    )]
    pub enum AssetValueType {
        /// Asset's Quantity.
        Quantity,
        /// Asset's Big Quantity.
        BigQuantity,
        /// Decimal quantity with fixed precision
        Fixed,
        /// Asset's key-value structured data.
        Store,
    }

    impl FromStr for AssetValueType {
        type Err = Error;
        fn from_str(value_type: &str) -> Result<AssetValueType> {
            serde_json::from_value(serde_json::json!(value_type))
                .wrap_err("Failed to deserialize value type")
        }
    }

    /// Asset's inner value.
    #[derive(
        Clone,
        Debug,
        PartialEq,
        Eq,
        Serialize,
        Deserialize,
        Io,
        Encode,
        Decode,
        FromVariant,
        IntoSchema,
    )]
    pub enum AssetValue {
        /// Asset's Quantity.
        Quantity(u32),
        /// Asset's Big Quantity.
        BigQuantity(u128),
        /// Asset's Decimal Quantity.
        Fixed(fixed::Fixed),
        /// Asset's key-value structured data.
        Store(Metadata),
    }

    impl AssetValue {
        /// Returns the asset type as a string.
        pub const fn value_type(&self) -> AssetValueType {
            match *self {
                AssetValue::Quantity(_) => AssetValueType::Quantity,
                AssetValue::BigQuantity(_) => AssetValueType::BigQuantity,
                AssetValue::Fixed(_) => AssetValueType::Fixed,
                AssetValue::Store(_) => AssetValueType::Store,
            }
        }
        /// Returns true if this value is zero, false if it contains [`Metadata`] or positive value
        pub const fn is_zero_value(&self) -> bool {
            match *self {
                AssetValue::Quantity(q) => q == 0_u32,
                AssetValue::BigQuantity(q) => q == 0_u128,
                AssetValue::Fixed(ref q) => q.is_zero(),
                AssetValue::Store(_) => false,
            }
        }
    }

    macro_rules! impl_try_as_for_asset_value {
        ( $($variant:ident( $ty:ty ),)* ) => {$(
            impl TryAsMut<$ty> for AssetValue {
                type Error = Error;

                fn try_as_mut(&mut self) -> Result<&mut $ty> {
                    if let AssetValue:: $variant (value) = self {
                        Ok(value)
                    } else {
                        Err(eyre!(
                            concat!(
                                "Expected source asset with value type:",
                                stringify!($variant),
                                ". Got: {:?}",
                            ),
                            self.value_type()
                        ))
                    }
                }
            }

            impl TryAsRef<$ty> for AssetValue {
                type Error = Error;

                fn try_as_ref(&self) -> Result<& $ty > {
                    if let AssetValue:: $variant (value) = self {
                        Ok(value)
                    } else {
                        Err(eyre!(
                            concat!(
                                "Expected source asset with value type:",
                                stringify!($variant),
                                ". Got: {:?}",
                            ),
                            self.value_type()
                        ))
                    }
                }
            }
        )*}
    }

    impl_try_as_for_asset_value! {
        Quantity(u32),
        BigQuantity(u128),
        Fixed(Fixed),
        Store(Metadata),
    }

    impl PartialOrd for Asset {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.id.cmp(&other.id))
        }
    }

    impl Ord for Asset {
        fn cmp(&self, other: &Self) -> Ordering {
            self.id.cmp(&other.id)
        }
    }

    /// Identification of an Asset Definition. Consists of Asset's name and Domain's name.
    ///
    /// # Example
    ///
    /// ```
    /// use iroha_data_model::asset::DefinitionId;
    ///
    /// let definition_id = DefinitionId::new("xor", "soramitsu");
    /// ```
    #[derive(
        Clone,
        Debug,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Serialize,
        Deserialize,
        Io,
        Encode,
        Decode,
        Hash,
        IntoSchema,
    )]
    pub struct DefinitionId {
        /// Asset's name.
        pub name: Name,
        /// Domain's name.
        pub domain_name: Name,
    }

    /// Identification of an Asset's components include Entity Id ([`Asset::Id`]) and [`Account::Id`].
    #[derive(
        Clone,
        Debug,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Serialize,
        Deserialize,
        Io,
        Encode,
        Decode,
        Hash,
        IntoSchema,
    )]
    pub struct Id {
        /// Entity Identification.
        pub definition_id: DefinitionId,
        /// Account Identification.
        pub account_id: AccountId,
    }

    impl AssetDefinition {
        /// Default [`AssetDefinition`] constructor.
        pub fn new(id: DefinitionId, value_type: AssetValueType) -> Self {
            AssetDefinition {
                value_type,
                id,
                metadata: Metadata::new(),
            }
        }

        /// Asset definition with quantity asset value type.
        pub fn new_quantity(id: DefinitionId) -> Self {
            AssetDefinition::new(id, AssetValueType::Quantity)
        }

        /// Asset definition with big quantity asset value type.
        pub fn new_big_quantity(id: DefinitionId) -> Self {
            AssetDefinition::new(id, AssetValueType::BigQuantity)
        }

        /// Asset definition with decimal quantity asset value type.
        pub fn with_precision(id: DefinitionId) -> Self {
            AssetDefinition::new(id, AssetValueType::Fixed)
        }

        /// Asset definition with store asset value type.
        pub fn new_store(id: DefinitionId) -> Self {
            AssetDefinition::new(id, AssetValueType::Store)
        }

        /// Checks the length of the id in bytes is in a valid range
        ///
        /// # Errors
        /// Fails if limit check fails
        pub fn validate_len(&self, range: impl Into<RangeInclusive<usize>>) -> Result<()> {
            let range = range.into();
            if range.contains(&self.id.name.len()) {
                Ok(())
            } else {
                Err(eyre!(
                    "Length of the asset defenition name must be in range {}-{}",
                    &range.start(),
                    &range.end()
                ))
            }
        }
    }

    impl Asset {
        /// Constructor
        pub fn new<V: Into<AssetValue>>(id: Id, value: V) -> Self {
            Asset {
                id,
                value: value.into(),
            }
        }

        /// `Asset` with `quantity` value constructor.
        pub fn with_quantity(id: Id, quantity: u32) -> Self {
            Asset {
                id,
                value: quantity.into(),
            }
        }

        /// `Asset` with `big_quantity` value constructor.
        pub fn with_big_quantity(id: Id, big_quantity: u128) -> Self {
            Asset {
                id,
                value: big_quantity.into(),
            }
        }

        /// `Asset` with a `parameter` inside `store` value constructor.
        ///
        /// # Errors
        /// Fails if limit check fails
        pub fn with_parameter(
            id: Id,
            key: String,
            value: Value,
            limits: MetadataLimits,
        ) -> Result<Self> {
            let mut store = Metadata::new();
            store.insert_with_limits(key, value, limits)?;
            Ok(Asset {
                id,
                value: store.into(),
            })
        }

        /// Returns the asset type as a string.
        pub const fn value_type(&self) -> AssetValueType {
            self.value.value_type()
        }
    }

    impl<T> TryAsMut<T> for Asset
    where
        AssetValue: TryAsMut<T, Error = Error>,
    {
        type Error = Error;

        fn try_as_mut(&mut self) -> Result<&mut T> {
            self.value.try_as_mut()
        }
    }

    impl<T> TryAsRef<T> for Asset
    where
        AssetValue: TryAsRef<T, Error = Error>,
    {
        type Error = Error;

        fn try_as_ref(&self) -> Result<&T> {
            self.value.try_as_ref()
        }
    }

    impl DefinitionId {
        /// [`Id`] constructor used to easily create an [`Id`] from three string slices - one for the
        /// asset definition's name, another one for the domain's name.
        pub fn new(name: &str, domain_name: &str) -> Self {
            DefinitionId {
                name: name.to_owned(),
                domain_name: domain_name.to_owned(),
            }
        }
    }

    impl Id {
        /// [`Id`] constructor used to easily create an [`Id`] from an names of asset definition and
        /// account.
        pub fn from_names(
            asset_definition_name: &str,
            asset_definition_domain_name: &str,
            account_name: &str,
            account_domain_name: &str,
        ) -> Self {
            Id {
                definition_id: DefinitionId::new(
                    asset_definition_name,
                    asset_definition_domain_name,
                ),
                account_id: AccountId::new(account_name, account_domain_name),
            }
        }

        /// [`Id`] constructor used to easily create an [`Id`] from an [`DefinitionId`](`crate::asset::DefinitionId`) and
        /// an [`AccountId`].
        pub const fn new(definition_id: DefinitionId, account_id: AccountId) -> Self {
            Id {
                definition_id,
                account_id,
            }
        }
    }

    impl Identifiable for Asset {
        type Id = Id;
    }

    impl Identifiable for AssetDefinition {
        type Id = DefinitionId;
    }

    impl FromIterator<Asset> for Value {
        fn from_iter<T: IntoIterator<Item = Asset>>(iter: T) -> Self {
            iter.into_iter()
                .map(|asset| asset.into())
                .collect::<Vec<Value>>()
                .into()
        }
    }

    impl FromIterator<AssetDefinition> for Value {
        fn from_iter<T: IntoIterator<Item = AssetDefinition>>(iter: T) -> Self {
            iter.into_iter()
                .map(|asset_definition| asset_definition.into())
                .collect::<Vec<Value>>()
                .into()
        }
    }

    /// Asset Identification is represented by `name#domain_name` string.
    impl FromStr for DefinitionId {
        type Err = Error;

        fn from_str(string: &str) -> Result<Self, Self::Err> {
            let vector: Vec<&str> = string.split('#').collect();
            if vector.len() != 2 {
                return Err(eyre!(
                    "Asset definition ID should have format `name#domain_name`.",
                ));
            }
            Ok(DefinitionId {
                name: String::from(vector[0]),
                domain_name: String::from(vector[1]),
            })
        }
    }

    impl Display for DefinitionId {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}#{}", self.name, self.domain_name)
        }
    }

    impl Display for Id {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}@{}", self.definition_id, self.account_id)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{
            Asset, AssetDefinition, AssetDefinitionEntry, AssetValue, AssetValueType,
            DefinitionId as AssetDefinitionId, Id as AssetId,
        };
    }
}

pub mod domain {
    //! This module contains [`Domain`](`crate::domain::Domain`) structure and related implementations and trait implementations.

    use std::{
        cmp::Ordering, collections::BTreeMap, convert::Infallible, iter, iter::FromIterator,
        ops::RangeInclusive, str::FromStr,
    };

    use dashmap::DashMap;
    use eyre::{eyre, Result};
    use iroha_crypto::PublicKey;
    use iroha_derive::Io;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{
        account::{Account, AccountsMap, GenesisAccount},
        asset::AssetDefinitionsMap,
        Identifiable, Name, Value,
    };

    /// Genesis domain name. Genesis domain should contain only genesis account.
    pub const GENESIS_DOMAIN_NAME: &str = "genesis";

    /// `DomainsMap` provides an API to work with collection of key (`Name`) - value
    /// (`Domain`) pairs.
    pub type DomainsMap = DashMap<Name, Domain>;

    /// Genesis domain. It will contain only one `genesis` account.
    #[derive(Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct GenesisDomain {
        genesis_key: PublicKey,
    }

    impl GenesisDomain {
        /// Returns `GenesisDomain`.
        pub const fn new(genesis_key: PublicKey) -> Self {
            Self { genesis_key }
        }
    }

    impl From<GenesisDomain> for Domain {
        fn from(domain: GenesisDomain) -> Self {
            Self {
                name: GENESIS_DOMAIN_NAME.to_owned(),
                accounts: iter::once((
                    <Account as Identifiable>::Id::genesis_account(),
                    GenesisAccount::new(domain.genesis_key).into(),
                ))
                .collect(),
                asset_definitions: BTreeMap::default(),
            }
        }
    }

    /// Named group of [`Account`] and [`Asset`](`crate::asset::Asset`) entities.
    #[derive(
        Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Io, Encode, Decode, IntoSchema,
    )]
    pub struct Domain {
        /// Domain name, for example company name.
        pub name: Name,
        /// Accounts of the domain.
        pub accounts: AccountsMap,
        /// Assets of the domain.
        pub asset_definitions: AssetDefinitionsMap,
    }

    impl FromStr for Domain {
        type Err = Infallible;
        fn from_str(name: &str) -> Result<Self, Self::Err> {
            Ok(Self::new(name))
        }
    }

    impl PartialOrd for Domain {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.name.cmp(&other.name))
        }
    }

    impl Ord for Domain {
        fn cmp(&self, other: &Self) -> Ordering {
            self.name.cmp(&other.name)
        }
    }

    impl Domain {
        /// Default `Domain` constructor.
        pub fn new(name: &str) -> Self {
            Domain {
                name: name.to_owned(),
                accounts: AccountsMap::new(),
                asset_definitions: AssetDefinitionsMap::new(),
            }
        }

        /// Checks the length of the id in bytes is in a valid range
        ///
        /// # Errors
        /// Fails if limit check fails
        pub fn validate_len(&self, range: impl Into<RangeInclusive<usize>>) -> Result<()> {
            let range = range.into();
            if range.contains(&self.name.len()) {
                Ok(())
            } else {
                Err(eyre!(
                    "Length of the domain name must be in range {}-{}",
                    &range.start(),
                    &range.end()
                ))
            }
        }

        /// Domain constructor with presetup accounts. Useful for testing purposes.
        pub fn with_accounts(name: &str, accounts: impl IntoIterator<Item = Account>) -> Self {
            let accounts_map = accounts
                .into_iter()
                .map(|account| (account.id.clone(), account))
                .collect();
            Domain {
                name: name.to_owned(),
                accounts: accounts_map,
                asset_definitions: AssetDefinitionsMap::new(),
            }
        }
    }

    impl Identifiable for Domain {
        type Id = Name;
    }

    impl FromIterator<Domain> for Value {
        fn from_iter<T: IntoIterator<Item = Domain>>(iter: T) -> Self {
            iter.into_iter()
                .map(|domain| domain.into())
                .collect::<Vec<Value>>()
                .into()
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Domain, GenesisDomain, GENESIS_DOMAIN_NAME};
    }
}

pub mod peer {
    //! This module contains [`Peer`] structure and related implementations and traits implementations.

    use std::{
        hash::{Hash, Hasher},
        iter::FromIterator,
    };

    use dashmap::DashSet;
    use iroha_derive::Io;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{Identifiable, PublicKey, Value};

    /// Ids of peers.
    pub type PeersIds = DashSet<Id>;

    /// Peer represents Iroha instance.
    #[derive(
        Clone,
        Debug,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Serialize,
        Deserialize,
        Io,
        Encode,
        Decode,
        IntoSchema,
    )]
    pub struct Peer {
        /// Peer Identification.
        pub id: Id,
    }

    /// Peer's identification.
    #[derive(
        Clone, Debug, Eq, PartialOrd, Ord, Serialize, Deserialize, Io, Encode, Decode, IntoSchema,
    )]
    pub struct Id {
        /// Address of the Peer's entrypoint.
        pub address: String,
        /// Public Key of the Peer.
        pub public_key: PublicKey,
    }

    impl Peer {
        /// Default `Peer` constructor.
        pub const fn new(id: Id) -> Self {
            Peer { id }
        }
    }

    impl Identifiable for Peer {
        type Id = Id;
    }

    impl Id {
        /// Default peer `Id` constructor.
        pub fn new(address: &str, public_key: &PublicKey) -> Self {
            Id {
                address: address.to_owned(),
                public_key: public_key.clone(),
            }
        }
    }

    impl PartialEq for Id {
        fn eq(&self, other: &Self) -> bool {
            self.public_key.eq(&other.public_key)
        }
    }

    impl Hash for Id {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.public_key.hash(state);
        }
    }

    impl FromIterator<Id> for Value {
        fn from_iter<T: IntoIterator<Item = Id>>(iter: T) -> Self {
            iter.into_iter()
                .map(|id| id.into())
                .collect::<Vec<Value>>()
                .into()
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub mod prelude {
        pub use super::{Id as PeerId, Peer};
    }
}

pub mod transaction {
    //! This module contains [`Transaction`] structures and related implementations
    //! and traits implementations.

    use std::{
        cmp::Ordering, collections::BTreeSet, iter::FromIterator, time::SystemTime,
        vec::IntoIter as VecIter,
    };

    use eyre::{eyre, Result};
    use iroha_crypto::prelude::*;
    use iroha_derive::Io;
    use iroha_schema::prelude::*;
    use iroha_version::{
        declare_versioned, declare_versioned_with_scale, version, version_with_scale,
    };
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};
    #[cfg(feature = "warp")]
    use warp::{reply::Response, Reply};

    use crate::{
        account::Account, isi::Instruction, metadata::UnlimitedMetadata,
        prelude::TransactionRejectionReason, Identifiable,
    };

    /// Maximum number of instructions and expressions per transaction
    pub const MAX_INSTRUCTION_NUMBER: usize = 2_usize.pow(12);

    declare_versioned!(
        VersionedTransaction 1..2,
        Debug,
        Clone,
        iroha_derive::FromVariant,
        IntoSchema,
    );

    /// This structure represents transaction in non-trusted form.
    ///
    /// `Iroha` and its' clients use [`Transaction`] to send transactions via network.
    /// Direct usage in business logic is strongly prohibited. Before any interactions
    /// `accept`.
    #[version(
        n = 1,
        versioned = "VersionedTransaction",
        derive = "Clone, Debug, Io, Eq, PartialEq, iroha_schema::IntoSchema"
    )]
    #[derive(
        Clone, Debug, Io, Encode, Decode, Serialize, Deserialize, Eq, PartialEq, IntoSchema,
    )]
    pub struct Transaction {
        /// [`Transaction`] payload.
        pub payload: Payload,
        /// [`Transaction`]'s [`Signature`]s.
        pub signatures: BTreeSet<Signature>,
    }

    /// Iroha [`Transaction`] payload.
    #[derive(
        Clone, Debug, Io, Encode, Decode, Serialize, Deserialize, Eq, PartialEq, IntoSchema,
    )]
    pub struct Payload {
        /// Account ID of transaction creator.
        pub account_id: <Account as Identifiable>::Id,
        /// An ordered set of instructions.
        pub instructions: Vec<Instruction>,
        /// Time of creation (unix time, in milliseconds).
        pub creation_time: u64,
        /// The transaction will be dropped after this time if it is still in a `Queue`.
        pub time_to_live_ms: u64,
        /// Metadata.
        pub metadata: UnlimitedMetadata,
    }

    impl VersionedTransaction {
        /// Same as [`as_v1`](`VersionedTransaction::as_v1()`) but also does conversion
        pub const fn as_inner_v1(&self) -> &Transaction {
            match self {
                Self::V1(v1) => &v1.0,
            }
        }

        /// Same as [`as_inner_v1`](`VersionedTransaction::as_inner_v1()`) but returns mutable reference
        pub fn as_mut_inner_v1(&mut self) -> &mut Transaction {
            match self {
                Self::V1(v1) => &mut v1.0,
            }
        }

        /// Same as [`into_v1`](`VersionedTransaction::into_v1()`) but also does conversion
        pub fn into_inner_v1(self) -> Transaction {
            match self {
                Self::V1(v1) => v1.0,
            }
        }

        /// Default [`Transaction`] constructor.
        pub fn new(
            instructions: Vec<Instruction>,
            account_id: <Account as Identifiable>::Id,
            proposed_ttl_ms: u64,
        ) -> VersionedTransaction {
            Transaction::new(instructions, account_id, proposed_ttl_ms).into()
        }

        /// Calculate transaction [`Hash`](`iroha_crypto::Hash`).
        pub fn hash(&self) -> Hash {
            self.as_inner_v1().hash()
        }

        /// Checks if number of instructions in payload exceeds maximum
        ///
        /// # Errors
        /// Fails if instruction length exceeds maximum instruction number
        pub fn check_instruction_len(&self, max_instruction_number: u64) -> Result<()> {
            self.as_inner_v1()
                .check_instruction_len(max_instruction_number)
        }

        /// Sign transaction with the provided key pair.
        ///
        /// # Errors
        /// Fails if signature creation fails
        pub fn sign(self, key_pair: &KeyPair) -> Result<VersionedTransaction> {
            self.into_inner_v1().sign(key_pair).map(Into::into)
        }

        /// Returns payload of transaction
        pub const fn payload(&self) -> &Payload {
            match self {
                Self::V1(v1) => &v1.0.payload,
            }
        }
    }

    impl Transaction {
        /// Default [`Transaction`] constructor.
        pub fn new(
            instructions: Vec<Instruction>,
            account_id: <Account as Identifiable>::Id,
            proposed_ttl_ms: u64,
        ) -> Transaction {
            Transaction::with_metadata(
                instructions,
                account_id,
                proposed_ttl_ms,
                UnlimitedMetadata::new(),
            )
        }

        /// [`Transaction`] constructor with metadata.
        pub fn with_metadata(
            instructions: Vec<Instruction>,
            account_id: <Account as Identifiable>::Id,
            proposed_ttl_ms: u64,
            metadata: UnlimitedMetadata,
        ) -> Transaction {
            #[allow(clippy::cast_possible_truncation, clippy::expect_used)]
            Transaction {
                payload: Payload {
                    instructions,
                    account_id,
                    creation_time: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .expect("Failed to get System Time.")
                        .as_millis() as u64,
                    time_to_live_ms: proposed_ttl_ms,
                    metadata,
                },
                signatures: BTreeSet::new(),
            }
        }

        /// Calculate transaction [`Hash`](`iroha_crypto::Hash`).
        pub fn hash(&self) -> Hash {
            let bytes: Vec<u8> = self.payload.clone().into();
            Hash::new(&bytes)
        }

        /// Checks if number of instructions in payload exceeds maximum
        ///
        /// # Errors
        /// Fails if instruction length exceeds maximum instruction number
        pub fn check_instruction_len(&self, max_instruction_number: u64) -> Result<()> {
            self.payload.check_instruction_len(max_instruction_number)
        }

        /// Sign transaction with the provided key pair.
        ///
        /// # Errors
        /// Fails if signature creation fails
        pub fn sign(self, key_pair: &KeyPair) -> Result<Transaction> {
            let mut signatures = self.signatures.clone();
            signatures.insert(Signature::new(key_pair.clone(), self.hash().as_ref())?);
            Ok(Transaction {
                payload: self.payload,
                signatures,
            })
        }
    }

    impl Payload {
        /// Used to compare the contents of the transaction independent of when it was created.
        pub fn equals_excluding_creation_time(&self, other: &Payload) -> bool {
            self.account_id == other.account_id
                && self.instructions == other.instructions
                && self.time_to_live_ms == other.time_to_live_ms
                && self.metadata == other.metadata
        }

        /// # Errors
        /// Asserts specific instruction number of instruction constraint
        pub fn check_instruction_len(&self, max_instruction_number: u64) -> Result<()> {
            if self
                .instructions
                .iter()
                .map(Instruction::len)
                .sum::<usize>() as u64
                > max_instruction_number
            {
                return Err(eyre!("Too many instructions in payload"));
            }
            Ok(())
        }
    }

    declare_versioned_with_scale!(VersionedPendingTransactions 1..2, iroha_derive::FromVariant, Clone, Debug);

    impl FromIterator<Transaction> for VersionedPendingTransactions {
        fn from_iter<T: IntoIterator<Item = Transaction>>(iter: T) -> Self {
            PendingTransactions(iter.into_iter().collect()).into()
        }
    }

    #[cfg(feature = "warp")]
    impl Reply for VersionedPendingTransactions {
        fn into_response(self) -> Response {
            use iroha_version::scale::EncodeVersioned;

            match self.encode_versioned() {
                Ok(bytes) => Response::new(bytes.into()),
                Err(e) => e.into_response(),
            }
        }
    }

    impl VersionedPendingTransactions {
        /// Same as [`as_v1`](`VersionedPendingTransactions::as_v1()`) but also does conversion
        pub const fn as_inner_v1(&self) -> &PendingTransactions {
            match self {
                Self::V1(v1) => &v1.0,
            }
        }

        /// Same as [`as_inner_v1`](`VersionedPendingTransactions::as_inner_v1()`) but returns mutable reference
        pub fn as_mut_inner_v1(&mut self) -> &mut PendingTransactions {
            match self {
                Self::V1(v1) => &mut v1.0,
            }
        }

        /// Same as [`into_v1`](`VersionedPendingTransactions::into_v1()`) but also does conversion
        pub fn into_inner_v1(self) -> PendingTransactions {
            match self {
                Self::V1(v1) => v1.0,
            }
        }
    }

    /// Represents a collection of transactions that the peer sends to describe its pending transactions in a queue.
    #[version_with_scale(
        n = 1,
        versioned = "VersionedPendingTransactions",
        derive = "Debug, Clone"
    )]
    #[derive(Debug, Clone, Encode, Decode, Deserialize, Serialize, Io, IntoSchema)]
    pub struct PendingTransactions(pub Vec<Transaction>);

    impl FromIterator<Transaction> for PendingTransactions {
        fn from_iter<T: IntoIterator<Item = Transaction>>(iter: T) -> Self {
            PendingTransactions(iter.into_iter().collect())
        }
    }

    impl IntoIterator for PendingTransactions {
        type Item = Transaction;

        type IntoIter = VecIter<Self::Item>;

        fn into_iter(self) -> Self::IntoIter {
            let PendingTransactions(transactions) = self;
            transactions.into_iter()
        }
    }

    /// Transaction Value used in Instructions and Queries
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, IntoSchema)]
    pub enum TransactionValue {
        /// Committed transaction
        Transaction(VersionedTransaction),
        /// Rejected transaction with reason of rejection
        RejectedTransaction(VersionedRejectedTransaction),
    }

    impl TransactionValue {
        /// Used to return payload of the transaction
        pub const fn payload(&self) -> &Payload {
            match self {
                TransactionValue::Transaction(tx) => tx.payload(),
                TransactionValue::RejectedTransaction(tx) => tx.payload(),
            }
        }
    }

    impl Ord for TransactionValue {
        fn cmp(&self, other: &Self) -> Ordering {
            self.payload()
                .creation_time
                .cmp(&other.payload().creation_time)
        }
    }

    impl PartialOrd for TransactionValue {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(
                self.payload()
                    .creation_time
                    .cmp(&other.payload().creation_time),
            )
        }
    }

    declare_versioned!(VersionedRejectedTransaction 1..2, iroha_derive::FromVariant, Clone, Debug, IntoSchema);

    impl VersionedRejectedTransaction {
        /// The same as [`as_v1`](`VersionedRejectedTransaction::as_v1()`) but also runs into on it
        pub const fn as_inner_v1(&self) -> &RejectedTransaction {
            match self {
                Self::V1(v1) => &v1.0,
            }
        }

        /// The same as [`as_v1`](`VersionedRejectedTransaction::as_v1()`) but also runs into on it
        pub fn as_mut_inner_v1(&mut self) -> &mut RejectedTransaction {
            match self {
                Self::V1(v1) => &mut v1.0,
            }
        }

        /// The same as [`as_v1`](`VersionedRejectedTransaction::as_v1()`) but also runs into on it
        pub fn into_inner_v1(self) -> RejectedTransaction {
            match self {
                Self::V1(v1) => v1.into(),
            }
        }

        /// Calculate transaction [`Hash`](`iroha_crypto::Hash`).
        pub fn hash(&self) -> Hash {
            self.as_inner_v1().hash()
        }

        /// Returns payload of transaction
        pub const fn payload(&self) -> &Payload {
            match self {
                Self::V1(v1) => &v1.0.payload,
            }
        }

        /// # Errors
        /// Asserts specific instruction number of instruction in transaction constraint
        pub fn check_instruction_len(&self, max_instruction_len: u64) -> Result<()> {
            self.as_inner_v1()
                .check_instruction_len(max_instruction_len)
        }
    }

    impl Eq for VersionedRejectedTransaction {}

    impl PartialEq for VersionedRejectedTransaction {
        fn eq(&self, other: &Self) -> bool {
            use VersionedRejectedTransaction::*;

            match (self, other) {
                (V1(first), V1(second)) => first.0.eq(&second.0),
            }
        }
    }

    impl Eq for VersionedTransaction {}

    impl PartialEq for VersionedTransaction {
        fn eq(&self, other: &Self) -> bool {
            use VersionedTransaction::*;

            match (self, other) {
                (V1(first), V1(second)) => first.0.eq(&second.0),
            }
        }
    }

    /// [`RejectedTransaction`] represents transaction rejected by some validator at some stage of the pipeline.
    #[version(
        n = 1,
        versioned = "VersionedRejectedTransaction",
        derive = "Debug, Clone, IntoSchema"
    )]
    #[derive(
        Clone, Debug, Io, Encode, Decode, Serialize, Deserialize, Eq, PartialEq, IntoSchema,
    )]
    pub struct RejectedTransaction {
        /// [`Transaction`] payload.
        pub payload: Payload,
        /// [`Transaction`]'s [`Signature`]s.
        pub signatures: BTreeSet<Signature>,
        /// The reason for rejecting this transaction during the validation pipeline.
        pub rejection_reason: TransactionRejectionReason,
    }

    impl RejectedTransaction {
        /// # Errors
        /// Asserts specific instruction number of instruction in transaction constraint
        pub fn check_instruction_len(&self, max_instruction_len: u64) -> Result<()> {
            self.payload.check_instruction_len(max_instruction_len)
        }

        /// Calculate transaction [`Hash`](`iroha_crypto::Hash`).
        pub fn hash(&self) -> Hash {
            let bytes: Vec<u8> = self.payload.clone().into();
            Hash::new(&bytes)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{
            Payload, PendingTransactions, RejectedTransaction, Transaction, TransactionValue,
            VersionedPendingTransactions, VersionedRejectedTransaction, VersionedTransaction,
        };
    }
}

/// Structures and traits related to pagination.
pub mod pagination {
    use std::{collections::BTreeMap, fmt};

    use serde::{Deserialize, Serialize};
    #[cfg(feature = "warp")]
    use warp::{
        http::StatusCode,
        reply::{self, Response},
        Filter, Rejection, Reply,
    };

    /// Describes a collection to which pagination can be applied.
    /// Implemented for the [`Iterator`] implementors.
    pub trait Paginate: Iterator + Sized {
        /// Returns a paginated [`Iterator`].
        fn paginate(self, pagination: Pagination) -> Paginated<Self>;
    }

    impl<I: Iterator + Sized> Paginate for I {
        fn paginate(self, pagination: Pagination) -> Paginated<Self> {
            Paginated {
                pagination,
                iter: self,
            }
        }
    }

    /// Paginated [`Iterator`].
    /// Not recommended to use directly, only use in iterator chains.
    #[derive(Debug)]
    pub struct Paginated<I: Iterator> {
        pagination: Pagination,
        iter: I,
    }

    impl<I: Iterator> Iterator for Paginated<I> {
        type Item = I::Item;

        fn next(&mut self) -> Option<Self::Item> {
            if let Some(limit) = self.pagination.limit.as_mut() {
                if *limit == 0 {
                    return None;
                }
                *limit -= 1
            }

            #[allow(clippy::option_if_let_else)]
            // Required because of E0524. 2 closures with unique refs to self
            if let Some(start) = self.pagination.start.take() {
                self.iter.nth(start)
            } else {
                self.iter.next()
            }
        }
    }

    /// Structure for pagination requests
    #[derive(Clone, Eq, PartialEq, Debug, Default, Copy, Deserialize, Serialize)]
    pub struct Pagination {
        /// start of indexing
        pub start: Option<usize>,
        /// limit of indexing
        pub limit: Option<usize>,
    }

    impl Pagination {
        /// Constructs [`Pagination`].
        pub const fn new(start: Option<usize>, limit: Option<usize>) -> Pagination {
            Pagination { start, limit }
        }
    }

    const PAGINATION_START: &str = "start";
    const PAGINATION_LIMIT: &str = "limit";

    /// Error for pagination
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct PaginateError(pub std::num::ParseIntError);

    impl fmt::Display for PaginateError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Failed to decode pagination. Error occurred in one of numbers: {}",
                self.0
            )
        }
    }
    impl std::error::Error for PaginateError {}

    #[cfg(feature = "warp")]
    impl Reply for PaginateError {
        fn into_response(self) -> Response {
            reply::with_status(self.to_string(), StatusCode::BAD_REQUEST).into_response()
        }
    }

    #[cfg(feature = "warp")]
    /// Filter for warp which extracts pagination
    pub fn paginate() -> impl Filter<Extract = (Pagination,), Error = Rejection> + Copy {
        warp::query()
    }

    impl From<Pagination> for BTreeMap<String, String> {
        fn from(pagination: Pagination) -> Self {
            let mut query_params = Self::new();
            if let Some(start) = pagination.start {
                query_params.insert(PAGINATION_START.to_owned(), start.to_string());
            }
            if let Some(limit) = pagination.limit {
                query_params.insert(PAGINATION_LIMIT.to_owned(), limit.to_string());
            }
            query_params
        }
    }

    impl From<Pagination> for Vec<(&'static str, usize)> {
        fn from(pagination: Pagination) -> Self {
            match (pagination.start, pagination.limit) {
                (Some(start), Some(limit)) => {
                    vec![(PAGINATION_START, start), (PAGINATION_LIMIT, limit)]
                }
                (Some(start), None) => vec![(PAGINATION_START, start)],
                (None, Some(limit)) => vec![(PAGINATION_LIMIT, limit)],
                (None, None) => Vec::new(),
            }
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::*;
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn empty() {
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(None, None))
                    .collect::<Vec<_>>(),
                vec![1_i32, 2_i32, 3_i32]
            )
        }

        #[test]
        fn start() {
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(Some(0), None))
                    .collect::<Vec<_>>(),
                vec![1_i32, 2_i32, 3_i32]
            );
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(Some(1), None))
                    .collect::<Vec<_>>(),
                vec![2_i32, 3_i32]
            );
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(Some(3), None))
                    .collect::<Vec<_>>(),
                Vec::<i32>::new()
            );
        }

        #[test]
        fn limit() {
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(None, Some(0)))
                    .collect::<Vec<_>>(),
                Vec::<i32>::new()
            );
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(None, Some(2)))
                    .collect::<Vec<_>>(),
                vec![1_i32, 2_i32]
            );
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(None, Some(4)))
                    .collect::<Vec<_>>(),
                vec![1_i32, 2_i32, 3_i32]
            );
        }

        #[test]
        fn start_and_limit() {
            assert_eq!(
                vec![1_i32, 2_i32, 3_i32]
                    .into_iter()
                    .paginate(Pagination::new(Some(1), Some(1)))
                    .collect::<Vec<_>>(),
                vec![2_i32]
            )
        }
    }
}

pub mod metadata {
    //! Module with metadata for accounts

    use std::{borrow::Borrow, collections::BTreeMap};

    use eyre::{eyre, Result};
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use crate::{Name, Value};

    /// Collection of parameters by their names.
    pub type UnlimitedMetadata = BTreeMap<Name, Value>;

    /// Limits for [`Metadata`].
    #[derive(Debug, Clone, Copy, Decode, Encode, Serialize, Deserialize)]
    pub struct Limits {
        /// Maximum number of entries
        pub max_len: u32,
        /// Maximum length of entry
        pub max_entry_byte_size: u32,
    }

    impl Limits {
        /// Constructor.
        pub const fn new(max_len: u32, max_entry_byte_size: u32) -> Limits {
            Limits {
                max_len,
                max_entry_byte_size,
            }
        }
    }

    /// Collection of parameters by their names with checked insertion.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Serialize,
        Deserialize,
        Default,
        PartialOrd,
        Ord,
        IntoSchema,
    )]
    #[serde(transparent)]
    pub struct Metadata {
        map: BTreeMap<Name, Value>,
    }

    impl Metadata {
        /// Constructor.
        pub fn new() -> Self {
            Self {
                map: BTreeMap::new(),
            }
        }

        /// Inserts `key` and `value`.
        /// Returns `Some(value)` if the value was already present, `None` otherwise.
        ///
        /// # Errors
        /// Fails if `max_entry_byte_size` or `max_len` from `limits` are exceeded.
        pub fn insert_with_limits(
            &mut self,
            key: Name,
            value: Value,
            limits: Limits,
        ) -> Result<Option<Value>> {
            if self.map.len() == limits.max_len as usize && !self.map.contains_key(&key) {
                return Err(eyre!(
                    "Metadata length limit is reached: {}",
                    limits.max_len
                ));
            }
            let entry_bytes: Vec<u8> = (key.clone(), value.clone()).encode();
            let byte_size = entry_bytes.len();
            if byte_size > limits.max_entry_byte_size as usize {
                return Err(eyre!("Metadata entry is bigger than allowed. Expected less or equal to {} bytes. Got: {} bytes", limits.max_entry_byte_size, byte_size));
            }
            Ok(self.map.insert(key, value))
        }

        /// Returns a reference to the value corresponding to the key.
        pub fn get<K: Ord + ?Sized>(&self, key: &K) -> Option<&Value>
        where
            Name: Borrow<K>,
        {
            self.map.get(key)
        }

        /// Removes a key from the map, returning the value at the key if the key was previously in the map.
        pub fn remove<K: Ord + ?Sized>(&mut self, key: &K) -> Option<Value>
        where
            Name: Borrow<K>,
        {
            self.map.remove(key)
        }
    }

    /// The prelude re-exports most commonly used traits, structs and macros from this module.
    pub mod prelude {
        pub use super::{Limits as MetadataLimits, Metadata, UnlimitedMetadata};
    }

    #[cfg(test)]
    mod tests {
        use super::{Limits, Metadata};

        #[test]
        fn insert_exceeds_entry_size() {
            let mut metadata = Metadata::new();
            let limits = Limits::new(10, 5);
            assert!(metadata
                .insert_with_limits("1".to_owned(), "2".to_owned().into(), limits)
                .is_ok());
            assert!(metadata
                .insert_with_limits("1".to_owned(), "23456".to_owned().into(), limits)
                .is_err());
        }

        #[test]
        fn insert_exceeds_len() {
            let mut metadata = Metadata::new();
            let limits = Limits::new(2, 5);
            assert!(metadata
                .insert_with_limits("1".to_owned(), "0".to_owned().into(), limits)
                .is_ok());
            assert!(metadata
                .insert_with_limits("2".to_owned(), "0".to_owned().into(), limits)
                .is_ok());
            assert!(metadata
                .insert_with_limits("2".to_owned(), "1".to_owned().into(), limits)
                .is_ok());
            assert!(metadata
                .insert_with_limits("3".to_owned(), "0".to_owned().into(), limits)
                .is_err());
        }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    #[cfg(feature = "roles")]
    pub use super::role::prelude::*;
    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, fixed::prelude::*,
        pagination::prelude::*, peer::prelude::*, transaction::prelude::*, world::prelude::*,
        Bytes, IdBox, Identifiable, IdentifiableBox, Name, Parameter, TryAsMut, TryAsRef, Value,
    };
    pub use crate::{
        events::prelude::*, expression::prelude::*, isi::prelude::*, metadata::prelude::*,
        permissions::prelude::*, query::prelude::*,
    };
}
