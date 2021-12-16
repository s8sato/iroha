#![allow(clippy::module_name_repetitions)]

//! This module contains permissions related Iroha functionality.

use std::iter;

use eyre::Result;
use iroha_data_model::prelude::*;

use super::prelude::WorldTrait;
#[cfg(feature = "roles")]
use super::Evaluate;
use crate::prelude::*;

/// Operation for which the permission should be checked.
pub trait NeedsPermission {}

impl NeedsPermission for Instruction {}

impl NeedsPermission for QueryBox {}

// Expression might contain a query, therefore needs to be checked.
impl NeedsPermission for Expression {}

/// Reason for prohibiting the execution of the particular instruction.
pub type DenialReason = String;

/// Implement this to provide custom permission checks for the Iroha based blockchain.
pub trait IsAllowed<W: WorldTrait, O: NeedsPermission> {
    /// Checks if the `authority` is allowed to perform `instruction` given the current state of `wsv`.
    ///
    /// # Errors
    /// In the case when the execution of `instruction` under given `authority` with the current state of `wsv`
    /// is unallowed.
    fn check(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason>;
}

/// Box with permissions validator.
pub type IsAllowedBoxed<W, O> = Box<dyn IsAllowed<W, O> + Send + Sync>;

/// Box with permissions validator for `Instruction`.
pub type IsInstructionAllowedBoxed<W> = IsAllowedBoxed<W, Instruction>;

/// Box with permissions validator for `Query`.
pub type IsQueryAllowedBoxed<W> = IsAllowedBoxed<W, QueryBox>;

/// Trait for joining validators with `or` method, auto-implemented
/// for all types which convert to [`IsAllowedBoxed`].
pub trait ValidatorApplyOr<W: WorldTrait, O: NeedsPermission> {
    /// Combines two validators into [`Or`].
    fn or(self, another: impl Into<IsAllowedBoxed<W, O>>) -> Or<W, O>;
}

impl<W: WorldTrait, O: NeedsPermission, V: Into<IsAllowedBoxed<W, O>>> ValidatorApplyOr<W, O>
    for V
{
    fn or(self, another: impl Into<IsAllowedBoxed<W, O>>) -> Or<W, O> {
        Or {
            first: self.into(),
            second: another.into(),
        }
    }
}

/// `check` will succeed if either `first` or `second` validator succeeds.
pub struct Or<W: WorldTrait, O: NeedsPermission> {
    first: IsAllowedBoxed<W, O>,
    second: IsAllowedBoxed<W, O>,
}

impl<W: WorldTrait, O: NeedsPermission> IsAllowed<W, O> for Or<W, O> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        self.first
            .check(authority, operation, wsv)
            .or_else(|first_error| {
                self.second
                    .check(authority, operation, wsv)
                    .map_err(|second_error| {
                        format!(
                            "Failed to pass first check with {} and second check with {}.",
                            first_error, second_error
                        )
                    })
            })
    }
}

impl<W: WorldTrait, O: NeedsPermission + 'static> From<Or<W, O>> for IsAllowedBoxed<W, O> {
    fn from(validator: Or<W, O>) -> Self {
        Box::new(validator)
    }
}

/// Wraps validator to check nested permissions.
/// Pay attention to wrap only validators that do not check nested intructions by themselves.
pub struct CheckNested<W: WorldTrait, O: NeedsPermission> {
    validator: IsAllowedBoxed<W, O>,
}

impl<W: WorldTrait, O: NeedsPermission> CheckNested<W, O> {
    /// Wraps `validator` to check nested permissions.
    pub fn new(validator: IsAllowedBoxed<W, O>) -> Self {
        CheckNested { validator }
    }
}

impl<W: WorldTrait> IsAllowed<W, Instruction> for CheckNested<W, Instruction> {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        match instruction {
            Instruction::Register(_)
            | Instruction::Unregister(_)
            | Instruction::Mint(_)
            | Instruction::Burn(_)
            | Instruction::SetKeyValue(_)
            | Instruction::RemoveKeyValue(_)
            | Instruction::Transfer(_)
            | Instruction::Grant(_)
            | Instruction::Fail(_) => self.validator.check(authority, instruction, wsv),
            Instruction::If(if_box) => {
                self.check(authority, &if_box.then, wsv)
                    .and_then(|_| match &if_box.otherwise {
                        Some(this_instruction) => self.check(authority, this_instruction, wsv),
                        None => Ok(()),
                    })
            }
            Instruction::Pair(pair_box) => self
                .check(authority, &pair_box.left_instruction, wsv)
                .and(self.check(authority, &pair_box.right_instruction, wsv)),
            Instruction::Sequence(sequence_box) => sequence_box
                .instructions
                .iter()
                .try_for_each(|this_instruction| self.check(authority, this_instruction, wsv)),
        }
    }
}

/// Checks an expression recursively to evaluate if there is a query inside of it and if
/// the user has permission to execute this query.
///
/// As the function is recursive, caution should be exercised to have a limit of nestedness, that would not cause stack overflow.
/// Up to 2^13 calls were tested and are ok. This is within default instruction limit.
///
/// # Errors
/// Returns an error if a user is not allowed to execute one of the inner queries, given the current `validator`.
pub fn check_query_in_expression<W: WorldTrait>(
    authority: &AccountId,
    expression: &Expression,
    wsv: &WorldStateView<W>,
    validator: &IsQueryAllowedBoxed<W>,
) -> Result<(), DenialReason> {
    macro_rules! check_binary_expression {
        ($e:ident) => {
            check_query_in_expression(authority, &($e).left.expression, wsv, validator).and(
                check_query_in_expression(authority, &($e).right.expression, wsv, validator),
            )
        };
    }

    match expression {
        Expression::Add(expression) => check_binary_expression!(expression),
        Expression::Subtract(expression) => check_binary_expression!(expression),
        Expression::Multiply(expression) => check_binary_expression!(expression),
        Expression::Divide(expression) => check_binary_expression!(expression),
        Expression::Mod(expression) => check_binary_expression!(expression),
        Expression::RaiseTo(expression) => check_binary_expression!(expression),
        Expression::Greater(expression) => check_binary_expression!(expression),
        Expression::Less(expression) => check_binary_expression!(expression),
        Expression::Equal(expression) => check_binary_expression!(expression),
        Expression::Not(expression) => {
            check_query_in_expression(authority, &expression.expression.expression, wsv, validator)
        }
        Expression::And(expression) => check_binary_expression!(expression),
        Expression::Or(expression) => check_binary_expression!(expression),
        Expression::If(expression) => {
            check_query_in_expression(authority, &expression.condition.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &expression.then_expression.expression,
                    wsv,
                    validator,
                ))
                .and(check_query_in_expression(
                    authority,
                    &expression.else_expression.expression,
                    wsv,
                    validator,
                ))
        }
        Expression::Query(query) => validator.check(authority, query, wsv),
        Expression::Contains(expression) => {
            check_query_in_expression(authority, &expression.collection.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &expression.element.expression,
                    wsv,
                    validator,
                ))
        }
        Expression::ContainsAll(expression) => {
            check_query_in_expression(authority, &expression.collection.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &expression.elements.expression,
                    wsv,
                    validator,
                ))
        }
        Expression::ContainsAny(expression) => {
            check_query_in_expression(authority, &expression.collection.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &expression.elements.expression,
                    wsv,
                    validator,
                ))
        }
        Expression::Where(expression) => {
            check_query_in_expression(authority, &expression.expression.expression, wsv, validator)
        }
        Expression::ContextValue(_) | Expression::Raw(_) => Ok(()),
    }
}

/// Checks an instruction recursively to evaluate if there is a query inside of it and if
/// the user has permission to execute this query.
///
/// As the function is recursive, caution should be exercised to have a limit of nestedness, that would not cause stack overflow.
/// Up to 2^13 calls were tested and are ok. This is within default instruction limit.
///
/// # Errors
/// Returns an error if a user is not allowed to execute one of the inner queries, given the current `validator`.
pub fn check_query_in_instruction<W: WorldTrait>(
    authority: &AccountId,
    instruction: &Instruction,
    wsv: &WorldStateView<W>,
    validator: &IsQueryAllowedBoxed<W>,
) -> Result<(), DenialReason> {
    match instruction {
        Instruction::Register(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
        }
        Instruction::Unregister(instruction) => {
            check_query_in_expression(authority, &instruction.object_id.expression, wsv, validator)
        }
        Instruction::Mint(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::Burn(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::Transfer(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
                .and(check_query_in_expression(
                    authority,
                    &instruction.source_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::Fail(_) => Ok(()),
        Instruction::SetKeyValue(instruction) => {
            check_query_in_expression(authority, &instruction.object_id.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.key.expression,
                    wsv,
                    validator,
                ))
                .and(check_query_in_expression(
                    authority,
                    &instruction.value.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::RemoveKeyValue(instruction) => {
            check_query_in_expression(authority, &instruction.object_id.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.key.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::Grant(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::If(if_box) => {
            check_query_in_instruction(authority, &if_box.then, wsv, validator).and_then(|_| {
                match &if_box.otherwise {
                    Some(this_instruction) => {
                        check_query_in_instruction(authority, this_instruction, wsv, validator)
                    }
                    None => Ok(()),
                }
            })
        }
        Instruction::Pair(pair_box) => {
            check_query_in_instruction(authority, &pair_box.left_instruction, wsv, validator).and(
                check_query_in_instruction(authority, &pair_box.right_instruction, wsv, validator),
            )
        }
        Instruction::Sequence(sequence_box) => {
            sequence_box
                .instructions
                .iter()
                .try_for_each(|this_instruction| {
                    check_query_in_instruction(authority, this_instruction, wsv, validator)
                })
        }
    }
}

impl<W: WorldTrait> From<CheckNested<W, Instruction>> for IsAllowedBoxed<W, Instruction> {
    fn from(validator: CheckNested<W, Instruction>) -> Self {
        Box::new(validator)
    }
}

/// A container for multiple permissions validators. It will succeed if all validators succeed.
pub struct AllShouldSucceed<W: WorldTrait, O: NeedsPermission> {
    validators: Vec<IsAllowedBoxed<W, O>>,
}

impl<W: WorldTrait, O: NeedsPermission> IsAllowed<W, O> for AllShouldSucceed<W, O> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        for validator in &self.validators {
            validator.check(authority, operation, wsv)?
        }
        Ok(())
    }
}

impl<W: WorldTrait, O: NeedsPermission + 'static> From<AllShouldSucceed<W, O>>
    for IsAllowedBoxed<W, O>
{
    fn from(validator: AllShouldSucceed<W, O>) -> Self {
        Box::new(validator)
    }
}

/// A container for multiple permissions validators. It will succeed if any validator succeeds.
pub struct AnyShouldSucceed<W: WorldTrait, O: NeedsPermission> {
    name: String,
    validators: Vec<IsAllowedBoxed<W, O>>,
}

impl<W: WorldTrait, O: NeedsPermission> IsAllowed<W, O> for AnyShouldSucceed<W, O> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        for validator in &self.validators {
            if validator.check(authority, operation, wsv).is_ok() {
                return Ok(());
            }
        }
        Err(format!(
            "None of the instructions succeeded in Any permission check block with name: {}",
            self.name
        ))
    }
}

impl<W: WorldTrait, O: NeedsPermission + 'static> From<AnyShouldSucceed<W, O>>
    for IsAllowedBoxed<W, O>
{
    fn from(validator: AnyShouldSucceed<W, O>) -> Self {
        Box::new(validator)
    }
}

/// Builder to combine multiple validation checks into one.
#[derive(Default)]
pub struct ValidatorBuilder<W: WorldTrait, O: NeedsPermission> {
    validators: Vec<IsAllowedBoxed<W, O>>,
}

impl<W: WorldTrait, O: NeedsPermission + 'static> ValidatorBuilder<W, O> {
    /// Returns new `ValidatorBuilder`, with empty set of validator checks.
    pub fn new() -> Self {
        ValidatorBuilder {
            validators: Vec::new(),
        }
    }

    /// Adds a validator to the list.
    pub fn with_validator(self, validator: impl Into<IsAllowedBoxed<W, O>>) -> Self {
        ValidatorBuilder {
            validators: self
                .validators
                .into_iter()
                .chain(iter::once(validator.into()))
                .collect(),
        }
    }

    /// Returns [`AllShouldSucceed`] that will check all the checks of previously supplied validators.
    pub fn all_should_succeed(self) -> IsAllowedBoxed<W, O> {
        AllShouldSucceed {
            validators: self.validators,
        }
        .into()
    }

    /// Returns [`AnyShouldSucceed`] that will succeed if any of the checks of previously supplied validators succeds.
    pub fn any_should_succeed(self, check_name: impl Into<String>) -> IsAllowedBoxed<W, O> {
        AnyShouldSucceed {
            name: check_name.into(),
            validators: self.validators,
        }
        .into()
    }
}

impl<W: WorldTrait> ValidatorBuilder<W, Instruction> {
    /// Adds a validator to the list and wraps it with `CheckNested` to check nested permissions.
    pub fn with_recursive_validator(
        self,
        validator: impl Into<IsInstructionAllowedBoxed<W>>,
    ) -> Self {
        self.with_validator(CheckNested::new(validator.into()))
    }
}

/// Allows all operations to be executed for all possible values. Mostly for tests and simple cases.
#[derive(Debug, Clone, Copy)]
pub struct AllowAll;

/// Disallows all operations to be executed for all possible values. Mostly for tests and simple cases.
#[derive(Debug, Clone, Copy)]
pub struct DenyAll;

impl<W: WorldTrait, O: NeedsPermission> IsAllowed<W, O> for AllowAll {
    fn check(
        &self,
        _authority: &AccountId,
        _instruction: &O,
        _wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        Ok(())
    }
}

impl<W: WorldTrait, O: NeedsPermission> IsAllowed<W, O> for DenyAll {
    fn check(
        &self,
        _authority: &AccountId,
        _instruction: &O,
        _wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        Err("All operations are denied.".to_owned())
    }
}

impl<W: WorldTrait, O: NeedsPermission> From<AllowAll> for IsAllowedBoxed<W, O> {
    fn from(AllowAll: AllowAll) -> Self {
        Box::new(AllowAll)
    }
}

impl<W: WorldTrait, O: NeedsPermission> From<DenyAll> for IsAllowedBoxed<W, O> {
    fn from(DenyAll: DenyAll) -> Self {
        Box::new(DenyAll)
    }
}

/// Boxed validator implementing [`HasToken`] validator trait.
pub type HasTokenBoxed<W> = Box<dyn HasToken<W> + Send + Sync>;

/// Trait that should be implemented by validator that checks the need to have permission token for a certain action.
pub trait HasToken<W: WorldTrait> {
    /// This function should return the token that `authority` should possess, given the `instruction`
    /// they are planning to execute on the current state of `wsv`
    ///
    /// # Errors
    /// In the case when it is impossible to deduce the required token given current data
    /// (e.g. unexistent account or unaplicable instruction).
    fn token(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String>;
}

impl<W: WorldTrait> IsAllowed<W, Instruction> for HasTokenBoxed<W> {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let permission_token = self
            .token(authority, instruction, wsv)
            .map_err(|err| format!("Unable to identify corresponding permission token: {}", err))?;
        let contain = wsv
            .map_account(authority, |account| {
                account.permission_tokens.contains(&permission_token)
            })
            .map_err(|e| e.to_string())?;
        if contain {
            Ok(())
        } else {
            Err(format!(
                "Account does not have the needed permission token: {:?}.",
                permission_token
            ))
        }
    }
}

// TODO: rewrite when specialization reaches stable
// Currently we simply can't do the following:
// impl <T: IsGrantAllowed> PermissionsValidator for T {}
// when we have
// impl <T: HasToken> PermissionsValidator for T {}
/// Boxed validator implementing [`IsGrantAllowed`] trait.
pub type IsGrantAllowedBoxed<W> = Box<dyn IsGrantAllowed<W> + Send + Sync>;

/// Checks the [`GrantBox`] instruction.
pub trait IsGrantAllowed<W: WorldTrait> {
    /// Checks the [`GrantBox`] instruction.
    ///
    /// # Errors
    /// Should return error if this particular validator does not approve this Grant instruction.
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason>;
}

impl<W: WorldTrait> IsAllowed<W, Instruction> for IsGrantAllowedBoxed<W> {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        if let Instruction::Grant(isi) = instruction {
            self.check_grant(authority, isi, wsv)
        } else {
            Ok(())
        }
    }
}

impl<W: WorldTrait> From<IsGrantAllowedBoxed<W>> for IsInstructionAllowedBoxed<W> {
    fn from(validator: IsGrantAllowedBoxed<W>) -> Self {
        Box::new(validator)
    }
}

/// Unpacks instruction if it is Grant of a Role into several Grants fo Permission Token.
/// If instruction is not Grant of Role, returns it as inly instruction inside the vec.
/// Should be called before permission checks by validators.
///
/// Semantically means that user can grant a role only if they can grant each of the permission tokens
/// that the role consists of.
///
/// # Errors
/// Evaluation failure of instruction fields.
#[cfg(feature = "roles")]
pub fn unpack_if_role_grant<W: WorldTrait>(
    instruction: Instruction,
    wsv: &WorldStateView<W>,
) -> Result<Vec<Instruction>> {
    let grant = if let Instruction::Grant(grant) = &instruction {
        grant
    } else {
        return Ok(vec![instruction]);
    };
    let id = if let Value::Id(IdBox::RoleId(id)) = grant.object.evaluate(wsv, &Context::new())? {
        id
    } else {
        return Ok(vec![instruction]);
    };

    let instructions = if let Some(role) = wsv.world.roles.get(&id) {
        let destination_id = grant.destination_id.evaluate(wsv, &Context::new())?;
        role.permissions
            .iter()
            .cloned()
            .map(|permission_token| GrantBox::new(permission_token, destination_id.clone()).into())
            .collect()
    } else {
        Vec::new()
    };
    Ok(instructions)
}

pub mod prelude {
    //! Exports common types for permissions.

    pub use super::{
        AllowAll, DenialReason, HasTokenBoxed, IsAllowedBoxed, IsGrantAllowed, IsGrantAllowedBoxed,
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::collections::{BTreeMap, BTreeSet};

    use eyre::Result;
    use iroha_data_model::{expression::prelude::*, isi::*};

    use super::*;
    use crate::wsv::World;

    struct DenyBurn;

    impl<W: WorldTrait> From<DenyBurn> for IsInstructionAllowedBoxed<W> {
        fn from(permissions: DenyBurn) -> Self {
            Box::new(permissions)
        }
    }

    impl<W: WorldTrait> IsAllowed<W, Instruction> for DenyBurn {
        fn check(
            &self,
            _authority: &AccountId,
            instruction: &Instruction,
            _wsv: &WorldStateView<W>,
        ) -> Result<(), super::DenialReason> {
            match instruction {
                Instruction::Burn(_) => Err("Denying sequence isi.".to_owned()),
                _ => Ok(()),
            }
        }
    }

    struct DenyAlice;

    impl<W: WorldTrait> From<DenyAlice> for IsInstructionAllowedBoxed<W> {
        fn from(permissions: DenyAlice) -> Self {
            Box::new(permissions)
        }
    }

    impl<W: WorldTrait> IsAllowed<W, Instruction> for DenyAlice {
        fn check(
            &self,
            authority: &AccountId,
            _instruction: &Instruction,
            _wsv: &WorldStateView<W>,
        ) -> Result<(), super::DenialReason> {
            if authority.name == "alice" {
                Err("Alice account is denied.".to_owned())
            } else {
                Ok(())
            }
        }
    }

    struct GrantedToken;

    impl<W: WorldTrait> HasToken<W> for GrantedToken {
        fn token(
            &self,
            _authority: &AccountId,
            _instruction: &Instruction,
            _wsv: &WorldStateView<W>,
        ) -> Result<PermissionToken, String> {
            Ok(PermissionToken::new("token", BTreeMap::new()))
        }
    }

    #[test]
    pub fn multiple_validators_combined() {
        let permissions_validator = ValidatorBuilder::new()
            .with_validator(DenyBurn)
            .with_validator(DenyAlice)
            .all_should_succeed();
        let instruction_burn: Instruction = BurnBox::new(
            Value::U32(10),
            IdBox::AssetId(AssetId::from_names("xor", "test", "alice", "test")),
        )
        .into();
        let instruction_fail = Instruction::Fail(FailBox {
            message: "fail message".to_owned(),
        });
        let account_bob = <Account as Identifiable>::Id::new("bob", "test");
        let account_alice = <Account as Identifiable>::Id::new("alice", "test");
        let wsv = WorldStateView::new(World::new());
        assert!(permissions_validator
            .check(&account_bob, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check(&account_alice, &instruction_fail, &wsv)
            .is_err());
        assert!(permissions_validator
            .check(&account_alice, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check(&account_bob, &instruction_fail, &wsv)
            .is_ok());
    }

    #[test]
    pub fn recursive_validator() {
        let permissions_validator = ValidatorBuilder::new()
            .with_recursive_validator(DenyBurn)
            .all_should_succeed();
        let instruction_burn: Instruction = BurnBox::new(
            Value::U32(10),
            IdBox::AssetId(AssetId::from_names("xor", "test", "alice", "test")),
        )
        .into();
        let instruction_fail = Instruction::Fail(FailBox {
            message: "fail message".to_owned(),
        });
        let nested_instruction_sequence =
            Instruction::If(If::new(true, instruction_burn.clone()).into());
        let account_alice = <Account as Identifiable>::Id::new("alice", "test");
        let wsv = WorldStateView::new(World::new());
        assert!(permissions_validator
            .check(&account_alice, &instruction_fail, &wsv)
            .is_ok());
        assert!(permissions_validator
            .check(&account_alice, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check(&account_alice, &nested_instruction_sequence, &wsv)
            .is_err());
    }

    #[test]
    pub fn granted_permission() {
        let alice_id = <Account as Identifiable>::Id::new("alice", "test");
        let bob_id = <Account as Identifiable>::Id::new("bob", "test");
        let alice_xor_id = <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
        let instruction_burn: Instruction = BurnBox::new(Value::U32(10), alice_xor_id).into();
        let mut domain = Domain::new("test");
        let mut bob_account = Account::new(bob_id.clone());
        let _ = bob_account
            .permission_tokens
            .insert(PermissionToken::new("token", BTreeMap::default()));
        domain.accounts.insert(bob_id.clone(), bob_account);
        let domains = vec![("test".to_string(), domain)];
        let wsv = WorldStateView::new(World::with(domains, BTreeSet::new()));
        let validator: HasTokenBoxed<_> = Box::new(GrantedToken);
        assert!(validator.check(&alice_id, &instruction_burn, &wsv).is_err());
        assert!(validator.check(&bob_id, &instruction_burn, &wsv).is_ok());
    }

    #[test]
    pub fn check_query_permissions_nested() {
        let instruction: Instruction = Pair::new(
            TransferBox::new(
                IdBox::AssetId(AssetId::from_names("btc", "crypto", "seller", "company")),
                Expression::Add(Add::new(
                    Expression::Query(
                        FindAssetQuantityById::new(AssetId::from_names(
                            "btc2eth_rate",
                            "exchange",
                            "dex",
                            "exchange",
                        ))
                        .into(),
                    ),
                    10_u32,
                )),
                IdBox::AssetId(AssetId::from_names("btc", "crypto", "buyer", "company")),
            ),
            TransferBox::new(
                IdBox::AssetId(AssetId::from_names("eth", "crypto", "buyer", "company")),
                15_u32,
                IdBox::AssetId(AssetId::from_names("eth", "crypto", "seller", "company")),
            ),
        )
        .into();
        let wsv = WorldStateView::new(World::new());
        let alice_id = <Account as Identifiable>::Id::new("alice", "test");
        assert!(check_query_in_instruction(&alice_id, &instruction, &wsv, &DenyAll.into()).is_err())
    }
}
