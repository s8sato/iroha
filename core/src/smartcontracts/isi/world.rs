//! `World`-related ISI implementations.

use iroha_telemetry::metrics;

use super::prelude::*;
use crate::prelude::*;

impl Registrable for NewRole {
    type Target = Role;

    #[must_use]
    #[inline]
    fn build(self, _authority: &AccountId) -> Self::Target {
        self.inner
    }
}

/// Iroha Special Instructions that have `World` as their target.
pub mod isi {
    use eyre::Result;
    use iroha_data_model::{
        isi::error::{InstructionExecutionError, InvalidParameterError, RepetitionError},
        prelude::*,
        query::error::FindError,
        Level,
    };

    use super::*;

    impl Execute for Register<Peer> {
        #[metrics(+"register_peer")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let peer_id = self.object.id;

            let world = &mut state_transaction.world;
            if !world.trusted_peers_ids.push(peer_id.clone()) {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: IdBox::PeerId(peer_id),
                }
                .into());
            }

            world.emit_events(Some(PeerEvent::Added(peer_id)));

            Ok(())
        }
    }

    impl Execute for Unregister<Peer> {
        #[metrics(+"unregister_peer")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let peer_id = self.object_id;
            let world = &mut state_transaction.world;
            let Some(index) = world.trusted_peers_ids.iter().position(|id| id == &peer_id) else {
                return Err(FindError::Peer(peer_id).into());
            };

            world.trusted_peers_ids.remove(index);

            world.emit_events(Some(PeerEvent::Removed(peer_id)));

            Ok(())
        }
    }

    impl Execute for Register<Domain> {
        #[metrics("register_domain")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let domain: Domain = self.object.build(authority);
            let domain_id = domain.id().clone();

            domain_id
                .name
                .validate_len(state_transaction.config.ident_length_limits)
                .map_err(Error::from)?;

            if domain_id == *iroha_genesis::GENESIS_DOMAIN_ID {
                return Err(InstructionExecutionError::InvariantViolation(
                    "Not allowed to register genesis domain".to_owned(),
                ));
            }

            let world = &mut state_transaction.world;
            if world.domains.get(&domain_id).is_some() {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: IdBox::DomainId(domain_id),
                }
                .into());
            }

            world.domains.insert(domain_id, domain.clone());

            world.emit_events(Some(DomainEvent::Created(domain)));

            Ok(())
        }
    }

    impl Execute for Unregister<Domain> {
        #[metrics("unregister_domain")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let domain_id = self.object_id;

            let triggers_in_domain = state_transaction
                .world()
                .triggers()
                .inspect_by_domain_id(&domain_id, |trigger_id, _| trigger_id.clone())
                .collect::<Vec<_>>();

            let world = &mut state_transaction.world;
            for trigger_id in &triggers_in_domain {
                assert!(world.triggers.remove(trigger_id));
            }
            if world.domains.remove(domain_id.clone()).is_none() {
                return Err(FindError::Domain(domain_id).into());
            }

            world.emit_events(Some(DomainEvent::Deleted(domain_id)));

            Ok(())
        }
    }

    impl Execute for Register<Role> {
        #[metrics(+"register_role")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let role = self.object.build(authority);

            if state_transaction.world.roles.get(role.id()).is_some() {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: IdBox::RoleId(role.id),
                }
                .into());
            }

            for permission in &role.permissions {
                if !state_transaction
                    .world
                    .permission_token_schema
                    .token_ids
                    .contains(&permission.definition_id)
                {
                    return Err(FindError::PermissionToken(permission.definition_id.clone()).into());
                }
            }

            let world = &mut state_transaction.world;
            let role_id = role.id().clone();
            world.roles.insert(role_id, role.clone());

            world.emit_events(Some(RoleEvent::Created(role)));

            Ok(())
        }
    }

    impl Execute for Unregister<Role> {
        #[metrics("unregister_role")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let role_id = self.object_id;

            let accounts_with_role = state_transaction
                .world
                .account_roles
                .iter()
                .map(|(role, ())| role)
                .filter(|role| role.role_id.eq(&role_id))
                .map(|role| &role.account_id)
                .cloned()
                .collect::<Vec<_>>();

            for account_id in accounts_with_role {
                let revoke = Revoke {
                    object: role_id.clone(),
                    destination_id: account_id,
                };
                revoke.execute(authority, state_transaction)?
            }

            let world = &mut state_transaction.world;
            if world.roles.remove(role_id.clone()).is_none() {
                return Err(FindError::Role(role_id).into());
            }

            world.emit_events(Some(RoleEvent::Deleted(role_id)));

            Ok(())
        }
    }

    impl Execute for Grant<PermissionToken, Role> {
        #[metrics(+"grant_role_permission")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let role_id = self.destination_id;
            let permission_token = self.object;
            let permission_token_id = permission_token.definition_id.clone();

            if !state_transaction
                .world
                .permission_token_schema
                .token_ids
                .contains(&permission_token_id)
            {
                return Err(FindError::PermissionToken(permission_token_id).into());
            }

            let Some(role) = state_transaction.world.roles.get_mut(&role_id) else {
                return Err(FindError::Role(role_id).into());
            };

            if !role.permissions.insert(permission_token.clone()) {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Grant,
                    id: permission_token.definition_id.into(),
                }
                .into());
            }

            state_transaction
                .world
                .emit_events(Some(RoleEvent::PermissionAdded(RolePermissionChanged {
                    role_id,
                    permission_token_id,
                })));

            Ok(())
        }
    }

    impl Execute for Revoke<PermissionToken, Role> {
        #[metrics(+"grant_role_permission")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let role_id = self.destination_id;
            let permission_token = self.object;
            let permission_token_id = permission_token.definition_id.clone();

            let Some(role) = state_transaction.world.roles.get_mut(&role_id) else {
                return Err(FindError::Role(role_id).into());
            };

            if !role.permissions.remove(&permission_token) {
                return Err(FindError::PermissionToken(permission_token_id).into());
            }

            state_transaction
                .world
                .emit_events(Some(RoleEvent::PermissionRemoved(RolePermissionChanged {
                    role_id,
                    permission_token_id,
                })));

            Ok(())
        }
    }

    impl Execute for SetParameter {
        #[metrics(+"set_parameter")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let parameter = self.parameter;
            let parameter_id = parameter.id.clone();

            let world = &mut state_transaction.world;
            if !world.parameters.remove(&parameter) {
                return Err(FindError::Parameter(parameter_id).into());
            }

            world.parameters.insert(parameter);

            world.emit_events(Some(ConfigurationEvent::Changed(parameter_id)));

            Ok(())
        }
    }

    impl Execute for NewParameter {
        #[metrics(+"new_parameter")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let parameter = self.parameter;
            let parameter_id = parameter.id.clone();

            let world = &mut state_transaction.world;
            if !world.parameters.insert(parameter) {
                return Err(RepetitionError {
                    instruction_type: InstructionType::NewParameter,
                    id: IdBox::ParameterId(parameter_id),
                }
                .into());
            }

            world.emit_events(Some(ConfigurationEvent::Created(parameter_id)));

            Ok(())
        }
    }

    impl Execute for Upgrade {
        #[metrics(+"upgrade_executor")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let raw_executor = self.executor;

            // Cloning executor to avoid multiple mutable borrows of `state_transaction`.
            // Also it's a cheap operation.
            let mut upgraded_executor = state_transaction.world.executor.clone();
            upgraded_executor
                .migrate(raw_executor, state_transaction, authority)
                .map_err(|migration_error| {
                    InvalidParameterError::Wasm(format!(
                        "{:?}",
                        eyre::eyre!(migration_error).wrap_err("Migration failed"),
                    ))
                })?;

            *state_transaction.world.executor.get_mut() = upgraded_executor;

            state_transaction
                .world
                .emit_events(std::iter::once(ExecutorEvent::Upgraded));

            Ok(())
        }
    }

    impl Execute for Log {
        fn execute(
            self,
            _authority: &AccountId,
            _state_transaction: &mut StateTransaction<'_, '_>,
        ) -> std::result::Result<(), Error> {
            const TARGET: &str = "log_isi";
            let Self { level, msg } = self;

            match level {
                Level::TRACE => iroha_logger::trace!(target: TARGET, "{}", msg),
                Level::DEBUG => iroha_logger::debug!(target: TARGET, "{}", msg),
                Level::INFO => iroha_logger::info!(target: TARGET, "{}", msg),
                Level::WARN => iroha_logger::warn!(target: TARGET, "{}", msg),
                Level::ERROR => iroha_logger::error!(target: TARGET, "{}", msg),
            }

            Ok(())
        }
    }
}
/// Query module provides `IrohaQuery` Peer related implementations.
pub mod query {
    use eyre::Result;
    use iroha_data_model::{
        parameter::Parameter,
        peer::Peer,
        permission::PermissionTokenSchema,
        prelude::*,
        query::error::{FindError, QueryExecutionFail as Error},
        role::{Role, RoleId},
    };

    use super::*;
    use crate::state::StateReadOnly;

    impl ValidQuery for FindAllRoles {
        #[metrics(+"find_all_roles")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = Role> + 'state>, Error> {
            Ok(Box::new(
                state_ro
                    .world()
                    .roles()
                    .iter()
                    .map(|(_, role)| role)
                    .cloned(),
            ))
        }
    }

    impl ValidQuery for FindAllRoleIds {
        #[metrics(+"find_all_role_ids")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = RoleId> + 'state>, Error> {
            Ok(Box::new(
                state_ro
               .world()
               .roles()
               .iter()
               .map(|(_, role)| role)
               // To me, this should probably be a method, not a field.
               .map(Role::id)
               .cloned(),
            ))
        }
    }

    impl ValidQuery for FindRoleByRoleId {
        #[metrics(+"find_role_by_role_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Role, Error> {
            let role_id = &self.id;
            iroha_logger::trace!(%role_id);

            state_ro.world().roles().get(role_id).map_or_else(
                || Err(Error::Find(FindError::Role(role_id.clone()))),
                |role_ref| Ok(role_ref.clone()),
            )
        }
    }

    impl ValidQuery for FindAllPeers {
        #[metrics("find_all_peers")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = Peer> + 'state>, Error> {
            Ok(Box::new(state_ro.world().peers().cloned().map(Peer::new)))
        }
    }

    impl ValidQuery for FindPermissionTokenSchema {
        #[metrics("find_permission_token_schema")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<PermissionTokenSchema, Error> {
            Ok(state_ro.world().permission_token_schema().clone())
        }
    }

    impl ValidQuery for FindAllParameters {
        #[metrics("find_all_parameters")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = Parameter> + 'state>, Error> {
            Ok(Box::new(state_ro.world().parameters_iter().cloned()))
        }
    }
}
