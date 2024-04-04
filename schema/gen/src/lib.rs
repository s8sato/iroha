//! Iroha schema generation support library. Contains the
//! `build_schemas` `fn`, which is the function which decides which
//! types are included in the schema.
use iroha_crypto::MerkleTree;
use iroha_data_model::{
    block::stream::{BlockMessage, BlockSubscriptionRequest},
    query::QueryOutputBox,
    BatchedResponse,
};
use iroha_schema::prelude::*;

macro_rules! types {
    ($($t:ty),+ $(,)?) => {
        /// Apply `callback` to all types in the schema.
        #[macro_export]
        macro_rules! map_all_schema_types {
            ($callback:ident) => {{
                $( $callback!($t); )+
            }}
        }
    }
}

/// Builds the schema for the current state of Iroha.
///
/// You should only include the top-level types, because other types
/// shall be included recursively.
pub fn build_schemas() -> MetaMap {
    use iroha_data_model::prelude::*;

    macro_rules! schemas {
        ($($t:ty),* $(,)?) => {{
            let mut out = MetaMap::new(); $(
            <$t as IntoSchema>::update_schema_map(&mut out); )*
            out
        }};
    }

    schemas! {
        // Transaction
        SignedTransaction,

        // Query + response
        SignedQuery,
        BatchedResponse<QueryOutputBox>,

        // Event stream
        EventMessage,
        EventSubscriptionRequest,

        // Block stream
        BlockMessage,
        BlockSubscriptionRequest,

        // Never referenced, but present in type signature. Like `PhantomData<X>`
        MerkleTree<SignedTransaction>,
    }
}

types!(
    Account,
    AccountEvent,
    AccountEventFilter,
    AccountEventSet,
    AccountId,
    AccountPermissionChanged,
    AccountRoleChanged,
    Action,
    Algorithm,
    Asset,
    AssetChanged,
    AssetDefinition,
    AssetDefinitionEvent,
    AssetDefinitionEventFilter,
    AssetDefinitionEventSet,
    AssetDefinitionId,
    AssetDefinitionOwnerChanged,
    AssetDefinitionTotalQuantityChanged,
    AssetEvent,
    AssetEventFilter,
    AssetEventSet,
    AssetId,
    AssetTransferBox,
    AssetValue,
    AssetValueType,
    AtIndex,
    BTreeMap<AccountId, Account>,
    BTreeMap<AssetDefinitionId, AssetDefinition>,
    BTreeMap<AssetDefinitionId, Numeric>,
    BTreeMap<AssetId, Asset>,
    BTreeMap<Name, MetadataValueBox>,
    BTreeSet<PermissionToken>,
    BTreeSet<SignatureWrapperOf<BlockPayload>>,
    BatchedResponse<QueryOutputBox>,
    BatchedResponseV1<QueryOutputBox>,
    BlockHeader,
    BlockMessage,
    BlockPayload,
    BlockRejectionReason,
    BlockSubscriptionRequest,
    Box<GenericPredicateBox<QueryOutputPredicate>>,
    Box<QueryOutputPredicate>,
    Burn<u32, Trigger>,
    Burn<Numeric, Asset>,
    BurnBox,
    ChainId,
    ConfigurationEvent,
    ConfigurationEventFilter,
    ConfigurationEventSet,
    ConstString,
    ConstVec<u8>,
    Container,
    DataEvent,
    DataEventFilter,
    Domain,
    DomainEvent,
    DomainEventFilter,
    DomainEventSet,
    DomainId,
    DomainOwnerChanged,
    Duration,
    Event,
    EventMessage,
    EventSubscriptionRequest,
    Executable,
    ExecuteTrigger,
    ExecuteTriggerEvent,
    ExecuteTriggerEventFilter,
    ExecutionTime,
    Executor,
    ExecutorEvent,
    ExecutorEventFilter,
    ExecutorEventSet,
    Fail,
    EventFilterBox,
    FindAccountById,
    FindAccountKeyValueByIdAndKey,
    FindAccountsByDomainId,
    FindAccountsWithAsset,
    FindAllAccounts,
    FindAllActiveTriggerIds,
    FindAllAssets,
    FindAllAssetsDefinitions,
    FindAllBlockHeaders,
    FindAllBlocks,
    FindAllDomains,
    FindAllParameters,
    FindAllPeers,
    FindAllRoleIds,
    FindAllRoles,
    FindAllTransactions,
    FindAssetById,
    FindAssetDefinitionById,
    FindAssetDefinitionKeyValueByIdAndKey,
    FindAssetKeyValueByIdAndKey,
    FindAssetQuantityById,
    FindAssetsByAccountId,
    FindAssetsByAssetDefinitionId,
    FindAssetsByDomainId,
    FindAssetsByDomainIdAndAssetDefinitionId,
    FindAssetsByName,
    FindBlockHeaderByHash,
    FindDomainById,
    FindDomainKeyValueByIdAndKey,
    FindError,
    FindPermissionTokenSchema,
    FindPermissionTokensByAccountId,
    FindRoleByRoleId,
    FindRolesByAccountId,
    FindTotalAssetQuantityByAssetDefinitionId,
    FindTransactionByHash,
    FindTransactionsByAccountId,
    FindTriggerById,
    FindTriggerKeyValueByIdAndKey,
    FindTriggersByDomainId,
    ForwardCursor,
    Grant<PermissionToken, Account>,
    Grant<PermissionToken, Role>,
    Grant<RoleId, Account>,
    GrantBox,
    Hash,
    HashOf<MerkleTree<SignedTransaction>>,
    HashOf<SignedBlock>,
    HashOf<SignedTransaction>,
    IdBox,
    IdentifiableBox,
    InstructionBox,
    InstructionEvaluationError,
    InstructionExecutionError,
    InstructionExecutionFail,
    InstructionType,
    InvalidParameterError,
    IpfsPath,
    Ipv4Addr,
    Ipv6Addr,
    LengthLimits,
    Level,
    Log,
    MathError,
    MerkleTree<SignedTransaction>,
    Metadata,
    MetadataChanged<AccountId>,
    MetadataChanged<AssetDefinitionId>,
    MetadataChanged<AssetId>,
    MetadataChanged<DomainId>,
    MetadataError,
    MetadataLimits,
    MetadataValueBox,
    Mint<u32, Trigger>,
    Mint<Numeric, Asset>,
    MintBox,
    MintabilityError,
    Mintable,
    Mismatch<AssetValueType>,
    Name,
    NewAccount,
    NewAssetDefinition,
    NewDomain,
    NewParameter,
    NewRole,
    NonTrivial<PredicateBox>,
    NonZeroU32,
    NonZeroU64,
    Numeric,
    NumericSpec,
    Option<u32>,
    Option<AccountId>,
    Option<AssetDefinitionId>,
    Option<AssetId>,
    Option<DomainId>,
    Option<Duration>,
    Option<Hash>,
    Option<HashOf<MerkleTree<SignedTransaction>>>,
    Option<HashOf<SignedBlock>>,
    Option<IpfsPath>,
    Option<NonZeroU32>,
    Option<NonZeroU64>,
    Option<ParameterId>,
    Option<PeerId>,
    Option<PipelineEntityKind>,
    Option<PipelineStatusKind>,
    Option<RoleId>,
    Option<String>,
    Option<TimeInterval>,
    Option<TransactionRejectionReason>,
    Option<TriggerCompletedOutcomeType>,
    Option<TriggerId>,
    Parameter,
    ParameterId,
    ParameterValueBox,
    Peer,
    PeerEvent,
    PeerEventFilter,
    PeerEventSet,
    PeerId,
    RolePermissionChanged,
    PermissionToken,
    PermissionTokenSchema,
    PermissionTokenSchemaUpdateEvent,
    PipelineEntityKind,
    PipelineEvent,
    PipelineEventFilter,
    PipelineRejectionReason,
    PipelineStatus,
    PipelineStatusKind,
    PredicateBox,
    PublicKey,
    QueryBox,
    QueryExecutionFail,
    QueryOutputBox,
    QueryOutputPredicate,
    QueryPayload,
    Register<Account>,
    Register<Asset>,
    Register<AssetDefinition>,
    Register<Domain>,
    Register<Peer>,
    Register<Role>,
    Register<Trigger>,
    RegisterBox,
    RemoveKeyValue<Account>,
    RemoveKeyValue<Asset>,
    RemoveKeyValue<AssetDefinition>,
    RemoveKeyValue<Domain>,
    RemoveKeyValueBox,
    Repeats,
    RepetitionError,
    Revoke<PermissionToken, Account>,
    Revoke<PermissionToken, Role>,
    Revoke<RoleId, Account>,
    RevokeBox,
    Role,
    RoleEvent,
    RoleEventFilter,
    RoleEventSet,
    RoleId,
    SemiInterval<Numeric>,
    SemiInterval<u128>,
    SemiRange,
    SetKeyValue<Account>,
    SetKeyValue<Asset>,
    SetKeyValue<AssetDefinition>,
    SetKeyValue<Domain>,
    SetKeyValueBox,
    SetParameter,
    Signature,
    SignatureOf<BlockPayload>,
    SignatureOf<QueryPayload>,
    SignatureOf<TransactionPayload>,
    SignatureWrapperOf<BlockPayload>,
    SignaturesOf<BlockPayload>,
    SignedBlock,
    SignedBlockV1,
    SignedQuery,
    SignedQueryV1,
    SignedTransaction,
    SignedTransactionV1,
    SizeError,
    SocketAddr,
    SocketAddrHost,
    SocketAddrV4,
    SocketAddrV6,
    String,
    StringPredicate,
    JsonString,
    TimeEvent,
    TimeEventFilter,
    TimeInterval,
    TimeSchedule,
    TransactionLimitError,
    TransactionLimits,
    TransactionPayload,
    TransactionQueryOutput,
    TransactionRejectionReason,
    TransactionValue,
    Transfer<Account, AssetDefinitionId, Account>,
    Transfer<Account, DomainId, Account>,
    Transfer<Asset, Metadata, Account>,
    Transfer<Asset, Numeric, Account>,
    TransferBox,
    Trigger,
    TriggerCompletedEvent,
    TriggerCompletedEventFilter,
    TriggerCompletedOutcome,
    TriggerCompletedOutcomeType,
    TriggerEvent,
    TriggerEventFilter,
    TriggerEventSet,
    TriggerId,
    TriggerNumberOfExecutionsChanged,
    TriggeringEventFilterBox,
    TypeError,
    UniqueVec<PeerId>,
    Unregister<Account>,
    Unregister<Asset>,
    Unregister<AssetDefinition>,
    Unregister<Domain>,
    Unregister<Peer>,
    Unregister<Role>,
    Unregister<Trigger>,
    UnregisterBox,
    Upgrade,
    ValidationFail,
    Vec<Event>,
    Vec<InstructionBox>,
    Vec<MetadataValueBox>,
    Vec<Name>,
    Vec<PeerId>,
    Vec<PredicateBox>,
    Vec<QueryOutputBox>,
    Vec<TransactionValue>,
    Vec<u8>,
    WasmExecutionFail,
    WasmSmartContract,
    [u16; 8],
    [u8; 32],
    [u8; 4],
    bool,
    u128,
    u16,
    u32,
    u64,
    u8,
);

#[cfg(test)]
mod tests {
    use core::num::{NonZeroU32, NonZeroU64};
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap, HashSet},
        time::Duration,
    };

    use iroha_crypto::*;
    use iroha_data_model::{
        account::NewAccount,
        asset::NewAssetDefinition,
        block::{
            error::BlockRejectionReason,
            stream::{BlockMessage, BlockSubscriptionRequest},
            BlockHeader, BlockPayload, SignedBlock, SignedBlockV1,
        },
        domain::NewDomain,
        executor::Executor,
        ipfs::IpfsPath,
        isi::{
            error::{
                InstructionEvaluationError, InstructionExecutionError, InvalidParameterError,
                MathError, MintabilityError, Mismatch, RepetitionError, TypeError,
            },
            InstructionType,
        },
        metadata::{MetadataError, MetadataValueBox, SizeError},
        parameter::ParameterValueBox,
        permission::JsonString,
        prelude::*,
        query::{
            error::{FindError, QueryExecutionFail},
            predicate::{
                numerical::{SemiInterval, SemiRange},
                string::StringPredicate,
                value::{AtIndex, Container, QueryOutputPredicate},
                GenericPredicateBox, NonTrivial, PredicateBox,
            },
            ForwardCursor, QueryOutputBox,
        },
        transaction::{error::TransactionLimitError, SignedTransactionV1, TransactionLimits},
        BatchedResponse, BatchedResponseV1, Level,
    };
    use iroha_primitives::{
        addr::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrHost, SocketAddrV4, SocketAddrV6},
        const_vec::ConstVec,
        conststr::ConstString,
        unique_vec::UniqueVec,
    };
    use iroha_schema::Compact;

    use super::IntoSchema;

    fn is_const_generic(generic: &str) -> bool {
        generic.parse::<usize>().is_ok()
    }

    fn generate_test_map() -> BTreeMap<core::any::TypeId, String> {
        let mut map = BTreeMap::new();

        macro_rules! insert_into_test_map {
            ($t:ty) => {{
                let type_id = <$t as iroha_schema::TypeId>::id();

                if let Some(type_id) = map.insert(core::any::TypeId::of::<$t>(), type_id) {
                    panic!(
                        "{}: Duplicate type id. Make sure that type ids are unique",
                        type_id
                    );
                }
            }};
        }

        map_all_schema_types!(insert_into_test_map);

        insert_into_test_map!(Compact<u128>);
        insert_into_test_map!(Compact<u32>);

        map
    }

    // For `PhantomData` wrapped types schemas aren't expanded recursively.
    // This test ensures that schemas for those types are present as well.
    fn find_missing_type_params(type_names: &HashSet<String>) -> HashMap<&str, Vec<&str>> {
        let mut missing_schemas = HashMap::<&str, _>::new();

        for type_name in type_names {
            let (Some(start), Some(end)) = (type_name.find('<'), type_name.rfind('>')) else {
                continue;
            };

            assert!(start < end, "Invalid type name: {type_name}");

            for generic in type_name.split(", ") {
                if !is_const_generic(generic) {
                    continue;
                }

                if !type_names.contains(generic) {
                    missing_schemas
                        .entry(type_name)
                        .or_insert_with(Vec::new)
                        .push(generic);
                }
            }
        }

        missing_schemas
    }

    #[test]
    fn no_extra_or_missing_schemas() {
        // NOTE: Skipping Box<str> until [this PR](https://github.com/paritytech/parity-scale-codec/pull/565) is merged
        let exceptions: [core::any::TypeId; 1] = [core::any::TypeId::of::<Box<str>>()];

        let schemas_types = super::build_schemas()
            .into_iter()
            .collect::<HashMap<_, _>>();
        let map_types = generate_test_map();

        let mut extra_types = HashSet::new();
        for (type_id, schema) in &map_types {
            if !schemas_types.contains_key(type_id) {
                extra_types.insert(schema);
            }
        }
        assert!(extra_types.is_empty(), "Extra types: {extra_types:#?}");

        let mut missing_types = HashSet::new();
        for (type_id, schema) in &schemas_types {
            if !map_types.contains_key(type_id) && !exceptions.contains(type_id) {
                missing_types.insert(schema);
            }
        }
        assert!(
            missing_types.is_empty(),
            "Missing types: {missing_types:#?}",
        );
    }

    #[test]
    fn no_missing_referenced_types() {
        let type_names = super::build_schemas()
            .into_iter()
            .map(|(_, (name, _))| name)
            .collect();
        let missing_schemas = find_missing_type_params(&type_names);

        assert!(
            missing_schemas.is_empty(),
            "Missing schemas: \n{missing_schemas:#?}"
        );
    }

    #[test]
    // NOTE: This test guards from incorrect implementation where
    // `SortedVec<T>` and `Vec<T>` start stepping over each other
    fn no_schema_type_overlap() {
        let mut schemas = super::build_schemas();
        <Vec<PublicKey>>::update_schema_map(&mut schemas);
        <BTreeSet<SignedTransactionV1>>::update_schema_map(&mut schemas);
    }
}
