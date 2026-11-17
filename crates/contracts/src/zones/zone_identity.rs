//! `ZoneIdentity` — Zone L2 predeploy (0x1c00...0003): orgs, their members, and the TIP-20s each
//! org may send to each other org on a shared zone.

pub use IZoneIdentity::IZoneIdentityErrors as ZoneIdentityError;

crate::sol! {
    /// Org membership and per-token edges between orgs.
    ///
    /// An address belongs to at most one org; an address in no org is in org 0, which the
    /// registrar administers. An edge joins two sides; an [`OrgKey`] names an org's accounts on the
    /// Zone, or with `l1` set its addresses on Tempo. Token T may move along an edge only when the
    /// sending side's admin allows it outbound and the receiving side's admin allows it inbound.
    ///
    /// The registrar and the enforcement flag are set on Tempo with
    /// `ZonePortal.setIdentityConfig`.
    #[sol(abi)]
    #[derive(Debug, PartialEq, Eq)]
    interface IZoneIdentity {
        /// One side of an edge: an org's accounts on the Zone, or with `l1` its addresses on Tempo.
        struct OrgKey {
            uint64 orgId;
            bool l1;
        }

        // Registrar.
        function createOrg(address admin) external returns (uint64 orgId);
        function setOrgAdmin(uint64 orgId, address admin) external;

        // Org admin.
        function addMembers(uint64 orgId, address[] calldata accounts) external;
        function removeMember(address account) external;
        function setFrozen(address account, bool frozen) external;
        function setEdge(OrgKey from, OrgKey to, address[] calldata tokens, bool allowed) external;
        function setReader(uint64 orgId, address reader, bool allowed) external;

        // Views. Membership is visible to whoever may read the account, and to the registrar.
        function orgAdmin(uint64 orgId) external view returns (address);
        function orgOf(address account) external view returns (uint64 orgId, bool frozen);
        function edge(OrgKey from, OrgKey to, address token) external view returns (bool allowed);
        function canRead(address account) external view returns (bool);

        event OrgCreated(uint64 indexed orgId, address admin);
        event OrgAdminUpdated(uint64 indexed orgId, address admin);
        event MemberUpdated(address indexed account, uint64 indexed orgId, bool frozen);
        event EdgeUpdated(uint64 indexed fromOrg, bool fromL1, uint64 indexed toOrg, bool toL1, address indexed token, bool fromOk, bool toOk);
        event ReaderUpdated(uint64 indexed orgId, address indexed reader, bool allowed);

        error Unauthorized();
        error UnknownOrg(uint64 orgId);
        error InvalidAddress();
        /// An edge from Tempo to Tempo, which no move uses.
        error InvalidEdge();
        error AlreadyMember(address account);
        error OrgPolicyForbids(address token, address from, address to);
    }
}

impl IZoneIdentity::OrgKey {
    /// The Zone accounts of `org`.
    pub const fn zone(org: u64) -> Self {
        Self {
            orgId: org,
            l1: false,
        }
    }

    /// The Tempo addresses of `org`.
    pub const fn l1(org: u64) -> Self {
        Self {
            orgId: org,
            l1: true,
        }
    }
}
