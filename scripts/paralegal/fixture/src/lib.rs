//! Isolated control-dependence fixtures. These exercise policy sensitivity;
//! they neither implement token operations nor change Tempo's runtime code.

type Result<T> = std::result::Result<T, ()>;

pub fn check_role_internal(allowed: bool) -> Result<()> {
    allowed.then_some(()).ok_or(())
}
pub fn check_not_paused(allowed: bool) -> Result<()> {
    allowed.then_some(()).ok_or(())
}
pub fn ensure_transfer_authorized(allowed: bool) -> Result<()> {
    allowed.then_some(()).ok_or(())
}
pub fn grant_role_internal(value: u64) -> Result<u64> {
    Ok(value)
}
pub fn revoke_role_internal(value: u64) -> Result<u64> {
    Ok(value)
}
pub fn set_role_admin_internal(value: u64) -> Result<u64> {
    Ok(value)
}
pub fn _transfer(value: u64) -> Result<u64> {
    Ok(value)
}

macro_rules! role_entry {
    ($name:ident, $sink:ident) => {
        pub fn $name(allowed: bool, value: u64) -> Result<u64> {
            let checked = check_role_internal(allowed);
            #[cfg(not(feature = "ignore-role"))]
            checked?;
            #[cfg(feature = "ignore-role")]
            let _ = checked;
            $sink(value)
        }
    };
}

role_entry!(grant_role, grant_role_internal);
role_entry!(revoke_role, revoke_role_internal);
role_entry!(renounce_role, revoke_role_internal);
role_entry!(set_role_admin, set_role_admin_internal);

fn transfer_checks(unpaused: bool, authorized: bool, value: u64) -> Result<u64> {
    let pause = check_not_paused(unpaused);
    #[cfg(not(feature = "ignore-pause"))]
    pause?;
    #[cfg(feature = "ignore-pause")]
    let _ = pause;
    let policy = ensure_transfer_authorized(authorized);
    #[cfg(not(feature = "ignore-policy"))]
    policy?;
    #[cfg(feature = "ignore-policy")]
    let _ = policy;
    _transfer(value)
}

macro_rules! transfer_entry {
    ($name:ident) => {
        pub fn $name(unpaused: bool, authorized: bool, value: u64) -> Result<u64> {
            transfer_checks(unpaused, authorized, value)
        }
    };
}

transfer_entry!(transfer);
transfer_entry!(transfer_from);
transfer_entry!(transfer_with_memo);
transfer_entry!(transfer_from_with_memo);
