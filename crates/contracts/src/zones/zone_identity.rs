//! `ZoneIdentity` — Zone L2 predeploy (0x1c00...0003): orgs, their members, and the TIP-20s each
//! org may send to each other org on a shared zone.

pub use IZoneIdentity::IZoneIdentityErrors as ZoneIdentityError;

crate::sol! {
    /// Org membership and per-token edges between orgs.
    ///
    /// An address belongs to at most one org; an address in no org is in org 0, which the
    /// registrar administers. An edge joins two sides, each an org ID with the top bit set for the
    /// org's addresses on Tempo instead of its accounts on the Zone. Token T may move along an edge
    /// only when the sending side's admin allows it outbound and the receiving side's admin allows
    /// it inbound. Both halves share one slot.
    ///
    /// The registrar and the enforcement flag are set on Tempo with
    /// `ZonePortal.setIdentityConfig`.
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
        function setOutbound(uint64 fromOrg, uint64 toOrg, address[] calldata tokens, bool allowed) external;
        function setInbound(uint64 toOrg, uint64 fromOrg, address[] calldata tokens, bool allowed) external;

        // Views. Membership is visible to the account, its org admin and the registrar.
        function orgAdmin(uint64 orgId) external view returns (address);
        function orgOf(address account) external view returns (uint64 orgId, bool frozen);
        function edge(uint64 fromOrg, uint64 toOrg, address token) external view returns (bool allowed);

        event OrgCreated(uint64 indexed orgId, address admin);
        event OrgAdminUpdated(uint64 indexed orgId, address admin);
        event MemberUpdated(address indexed account, uint64 indexed orgId, bool frozen);
        event OutboundUpdated(uint64 indexed fromOrg, uint64 indexed toOrg, address indexed token, bool allowed);
        event InboundUpdated(uint64 indexed toOrg, uint64 indexed fromOrg, address indexed token, bool allowed);

        error Unauthorized();
        error UnknownOrg(uint64 orgId);
        error InvalidAddress();
        error AlreadyMember(address account);
        error NotMember(address account);
        error OrgPolicyForbids(address token, address from, address to);
    }
}
