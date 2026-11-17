//! `ZoneIdentity` — Zone L2 predeploy (0x1c00...0003): orgs, their members, and the TIP-20s each
//! org may send to each other org on a shared zone.

pub use IZoneIdentity::IZoneIdentityErrors as ZoneIdentityError;

crate::sol! {
    /// Org membership and per-token edges between orgs.
    ///
    /// An address belongs to at most one org; an address in no org is in org 0, which the
    /// registrar administers. Org A may send token T to org B only when A's admin allows it
    /// outbound and B's admin allows it inbound. The pair is stored precomputed, so a check reads a
    /// fixed number of slots whatever the number of orgs, tokens or edges.
    ///
    /// The registrar and the enforcement flag are set on Tempo with
    /// `ZonePortal.setIdentityConfig`. A token's bit is its position in the portal's enabled-token
    /// list.
    #[sol(abi)]
    #[derive(Debug, PartialEq, Eq)]
    interface IZoneIdentity {
        // Registrar.
        function createOrg(address admin) external returns (uint64 orgId);
        function setOrgAdmin(uint64 orgId, address admin) external;

        // Org admin.
        function addMember(uint64 orgId, address account) external;
        function removeMember(address account) external;
        function setFrozen(address account, bool frozen) external;
        function setOutbound(uint64 fromOrg, uint64 toOrg, uint256 tokenMask) external;
        function setInbound(uint64 toOrg, uint64 fromOrg, uint256 tokenMask) external;

        // Views. Membership is visible to the account, its org admin and the registrar.
        function orgAdmin(uint64 orgId) external view returns (address);
        function tokenBit(address token) external view returns (uint16 bit, bool hasBit);
        function orgOf(address account) external view returns (uint64 orgId, bool frozen);
        function edge(uint64 fromOrg, uint64 toOrg) external view returns (uint256 tokenMask);

        error Unauthorized();
        error UnknownOrg(uint64 orgId);
        error InvalidAddress();
        error AlreadyMember(address account);
        error NotMember(address account);
        error OrgPolicyForbids(address token, address from, address to);
    }
}
