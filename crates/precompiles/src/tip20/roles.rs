use alloy::primitives::{Address, B256};
use tempo_precompiles_macros::solidity;

use crate::{error::Result, storage::Handler, tip20::TIP20Token};

#[solidity]
pub mod roles_auth {
    use super::*;

    pub enum Error {
        Unauthorized,
    }

    pub enum Event {
        RoleMembershipUpdated {
            #[indexed]
            role: B256,
            #[indexed]
            account: Address,
            #[indexed]
            sender: Address,
            has_role: bool,
        },
        RoleAdminUpdated {
            #[indexed]
            role: B256,
            #[indexed]
            new_admin_role: B256,
            #[indexed]
            sender: Address,
        },
    }

    pub trait Interface {
        fn has_role(&self, account: Address, role: B256) -> Result<bool>;
        fn get_role_admin(&self, role: B256) -> Result<B256>;
        fn grant_role(&mut self, role: B256, account: Address) -> Result<()>;
        fn revoke_role(&mut self, role: B256, account: Address) -> Result<()>;
        fn renounce_role(&mut self, role: B256) -> Result<()>;
        fn set_role_admin(&mut self, role: B256, admin_role: B256) -> Result<()>;
    }
}

pub use roles_auth::{
    Error as RolesAuthError, Event as RolesAuthEvent, RoleAdminUpdated, RoleMembershipUpdated,
    Unauthorized,
};

#[allow(non_snake_case)]
pub mod IRolesAuth {
    pub use super::roles_auth::{
        Calls, Interface, getRoleAdminCall, getRoleAdminReturn, grantRoleCall, grantRoleReturn,
        hasRoleCall, hasRoleReturn, new, renounceRoleCall, renounceRoleReturn,
        roles_authInstance as IRolesAuthInstance, revokeRoleCall, revokeRoleReturn,
        setRoleAdminCall, setRoleAdminReturn,
    };
}

pub const DEFAULT_ADMIN_ROLE: B256 = B256::ZERO;
pub const UNGRANTABLE_ROLE: B256 = B256::new([0xff; 32]);

impl roles_auth::Interface for TIP20Token {
    fn has_role(&self, account: Address, role: B256) -> Result<bool> {
        self.has_role_internal(account, role)
    }

    fn get_role_admin(&self, role: B256) -> Result<B256> {
        self.get_role_admin_internal(role)
    }

    fn grant_role(&mut self, msg_sender: Address, role: B256, account: Address) -> Result<()> {
        let admin_role = self.get_role_admin_internal(role)?;
        self.check_role_internal(msg_sender, admin_role)?;
        self.grant_role_internal(account, role)?;

        self.emit_event(RolesAuthEvent::role_membership_updated(
            role, account, msg_sender, true,
        ))
    }

    fn revoke_role(&mut self, msg_sender: Address, role: B256, account: Address) -> Result<()> {
        let admin_role = self.get_role_admin_internal(role)?;
        self.check_role_internal(msg_sender, admin_role)?;
        self.revoke_role_internal(account, role)?;

        self.emit_event(RolesAuthEvent::role_membership_updated(
            role, account, msg_sender, false,
        ))
    }

    fn renounce_role(&mut self, msg_sender: Address, role: B256) -> Result<()> {
        self.check_role_internal(msg_sender, role)?;
        self.revoke_role_internal(msg_sender, role)?;

        self.emit_event(RolesAuthEvent::role_membership_updated(
            role, msg_sender, msg_sender, false,
        ))
    }

    fn set_role_admin(&mut self, msg_sender: Address, role: B256, admin_role: B256) -> Result<()> {
        let current_admin_role = self.get_role_admin_internal(role)?;
        self.check_role_internal(msg_sender, current_admin_role)?;
        self.set_role_admin_internal(role, admin_role)?;

        self.emit_event(RolesAuthEvent::role_admin_updated(
            role, admin_role, msg_sender,
        ))
    }
}

impl TIP20Token {
    /// Initialize the UNGRANTABLE_ROLE to be self-administered
    pub fn initialize_roles(&mut self) -> Result<()> {
        self.set_role_admin_internal(UNGRANTABLE_ROLE, UNGRANTABLE_ROLE)
    }

    /// Grant the default admin role to an account
    pub fn grant_default_admin(&mut self, msg_sender: Address, admin: Address) -> Result<()> {
        self.grant_role_internal(admin, DEFAULT_ADMIN_ROLE)?;

        self.emit_event(RolesAuthEvent::role_membership_updated(
            DEFAULT_ADMIN_ROLE,
            admin,
            msg_sender,
            true,
        ))
    }

    // Utility functions for checking roles without calldata
    pub fn check_role(&self, account: Address, role: B256) -> Result<()> {
        self.check_role_internal(account, role)
    }

    // Internal implementation functions
    pub fn has_role_internal(&self, account: Address, role: B256) -> Result<bool> {
        self.roles[account][role].read()
    }

    pub fn grant_role_internal(&mut self, account: Address, role: B256) -> Result<()> {
        self.roles[account][role].write(true)
    }

    fn revoke_role_internal(&mut self, account: Address, role: B256) -> Result<()> {
        self.roles[account][role].write(false)
    }

    /// If sloads 0, will be equal to DEFAULT_ADMIN_ROLE
    fn get_role_admin_internal(&self, role: B256) -> Result<B256> {
        self.role_admins[role].read()
    }

    fn set_role_admin_internal(&mut self, role: B256, admin_role: B256) -> Result<()> {
        self.role_admins[role].write(admin_role)
    }

    fn check_role_internal(&self, account: Address, role: B256) -> Result<()> {
        if !self.has_role_internal(account, role)? {
            return Err(RolesAuthError::unauthorized().into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::keccak256;

    use super::*;
    use crate::{error::TempoPrecompileError, storage::StorageCtx, test_util::TIP20Setup};
    use roles_auth::Interface;

    #[test]
    fn test_role_contract_grant_and_check() -> eyre::Result<()> {
        let mut storage = crate::storage::hashmap::HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let custom_role = keccak256(b"CUSTOM_ROLE");

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            // Test hasRole
            let has_admin = token.has_role(admin, DEFAULT_ADMIN_ROLE)?;
            assert!(has_admin);

            // Grant custom role
            token.grant_role(admin, custom_role, user)?;

            // Check custom role
            let has_custom = token.has_role(user, custom_role)?;
            assert!(has_custom);

            // Verify events were emitted
            token.assert_emitted_events(vec![
                // Event from grant_default_admin during token initialization
                RolesAuthEvent::RoleMembershipUpdated(RoleMembershipUpdated {
                    role: DEFAULT_ADMIN_ROLE,
                    account: admin,
                    sender: admin,
                    has_role: true,
                }),
                // Event from grant_role call above
                RolesAuthEvent::RoleMembershipUpdated(RoleMembershipUpdated {
                    role: custom_role,
                    account: user,
                    sender: admin,
                    has_role: true,
                }),
            ]);

            Ok(())
        })
    }

    #[test]
    fn test_role_admin_functions() -> eyre::Result<()> {
        let mut storage = crate::storage::hashmap::HashMapStorageProvider::new(1);
        let admin = Address::random();
        let custom_role = keccak256(b"CUSTOM_ROLE");
        let admin_role = keccak256(b"ADMIN_ROLE");

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            // Set custom admin for role
            token.set_role_admin(admin, custom_role, admin_role)?;

            // Check role admin
            let retrieved_admin = token.get_role_admin(custom_role)?;
            assert_eq!(retrieved_admin, admin_role);

            Ok(())
        })
    }

    #[test]
    fn test_renounce_role() -> eyre::Result<()> {
        let mut storage = crate::storage::hashmap::HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let custom_role = keccak256(b"CUSTOM_ROLE");

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;
            token.grant_role_internal(user, custom_role).unwrap();

            // Renounce role
            token.renounce_role(user, custom_role)?;

            // Check role is removed
            assert!(!token.has_role_internal(user, custom_role)?);

            Ok(())
        })
    }

    #[test]
    fn test_unauthorized_access() -> eyre::Result<()> {
        let mut storage = crate::storage::hashmap::HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let other = Address::random();
        let custom_role = keccak256(b"CUSTOM_ROLE");

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            // Try to grant role without permission
            let result = token.grant_role(user, custom_role, other);

            assert!(matches!(
                result,
                Err(TempoPrecompileError::RolesAuthError(
                    RolesAuthError::Unauthorized(Unauthorized)
                ))
            ));

            Ok(())
        })
    }
}
