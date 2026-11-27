//! `ZoneIdentity` — Zone L2 predeploy (0x1c00...0003): orgs, their members, the TIP-20s each
//! org may send to each other org on a shared zone, and the Tempo addresses each org's members may
//! deposit from and withdraw to.

pub use IZoneIdentity::IZoneIdentityErrors as ZoneIdentityError;

crate::sol! {
    /// Org membership, per-token edges between orgs, and each org's per-token Tempo targets.
    ///
    /// An address on the Zone belongs to at most one org; an address in no org is in org 0. Token T
    /// may move on the Zone from org A to org B only when A's admin allows it outbound and B's admin
    /// allows it inbound. Org 0 has no admin and no edges: nothing moves on the Zone to, from or
    /// within org 0, and `setEdge` rejects any edge that names it. Tempo addresses are never members:
    /// each org's admin alone decides, per token, which Tempo addresses its members accept deposits
    /// from and may withdraw to, through its targets and its [`L1Policy`]. Addresses in org 0 may
    /// always withdraw to any Tempo address and never accept deposits.
    ///
    /// The registrar and the enforcement flag are set on Tempo with
    /// `ZonePortal.setIdentityConfig`.
    #[sol(abi)]
    #[derive(Debug, PartialEq, Eq)]
    interface IZoneIdentity {
        /// The Tempo addresses an org allows for one token without listing them as targets.
        struct L1Policy {
            /// Members accept deposits from any Tempo address.
            bool openDeposit;
            /// Members may withdraw to any Tempo address.
            bool openWithdrawal;
        }

        // Registrar.
        function createOrg(address admin) external returns (uint64 orgId);
        function setOrgAdmin(uint64 orgId, address admin) external;

        // Org admin.
        function addMembers(uint64 orgId, address[] calldata accounts) external;
        function removeMember(address account) external;
        function setEdge(uint64 fromOrg, uint64 toOrg, address[] calldata tokens, bool allowed) external;
        function setL1Target(uint64 orgId, address target, address[] calldata tokens, bool depositFrom, bool withdrawTo) external;
        function setL1Policy(uint64 orgId, address[] calldata tokens, L1Policy policy) external;
        function setReader(uint64 orgId, address reader, bool allowed) external;

        // Views. Membership is visible to whoever may read the account and to the registrar; an org's
        // edges, targets and policy to its admin and the registrar.
        function orgAdmin(uint64 orgId) external view returns (address);
        function orgOf(address account) external view returns (uint64 orgId);
        function edge(uint64 fromOrg, uint64 toOrg, address token) external view returns (bool allowed);
        function l1Target(uint64 orgId, address target, address token) external view returns (bool depositFrom, bool withdrawTo);
        function l1Policy(uint64 orgId, address token) external view returns (L1Policy policy);
        function canRead(address account) external view returns (bool);

        event OrgCreated(uint64 indexed orgId, address admin);
        event OrgAdminUpdated(uint64 indexed orgId, address admin);
        event MemberAdded(address indexed account, uint64 indexed orgId);
        event MemberRemoved(address indexed account, uint64 indexed orgId);
        event EdgeUpdated(uint64 indexed fromOrg, uint64 indexed toOrg, address indexed token, bool fromOk, bool toOk);
        event L1TargetUpdated(uint64 indexed orgId, address indexed target, address indexed token, bool depositFrom, bool withdrawTo);
        event L1PolicyUpdated(uint64 indexed orgId, address indexed token, L1Policy policy);
        event ReaderUpdated(uint64 indexed orgId, address indexed reader, bool allowed);

        error Unauthorized();
        error UnknownOrg(uint64 orgId);
        error InvalidAddress();
        error AlreadyMember(address account);
        error OrgPolicyForbids(address token, address from, address to);
    }
}
