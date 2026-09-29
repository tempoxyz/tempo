pub use IRolesAuth::{IRolesAuthErrors as RolesAuthError, IRolesAuthEvents as RolesAuthEvent};
pub use ITIP20::{ITIP20Errors as TIP20Error, ITIP20Events as TIP20Event};
use alloy_primitives::Address;
use alloy_sol_types::{SolCall, SolType};

/// Decimal precision for all TIP-20 tokens.
pub const DECIMALS: u8 = 6;

/// USD currency string constant.
pub const USD_CURRENCY: &str = "USD";

/// Full list of ISO 4217 currency codes.
pub const ISO4217_CODES: &[&str] = &[
    "AED", "AFN", "ALL", "AMD", "ANG", "AOA", "ARS", "AUD", "AWG", "AZN", "BAM", "BBD", "BDT",
    "BGN", "BHD", "BIF", "BMD", "BND", "BOB", "BOV", "BRL", "BSD", "BTN", "BWP", "BYN", "BZD",
    "CAD", "CDF", "CHE", "CHF", "CHW", "CLP", "CLF", "CNY", "COP", "COU", "CRC", "CUP", "CVE",
    "CZK", "DJF", "DKK", "DOP", "DZD", "EGP", "ERN", "ETB", "EUR", "FJD", "FKP", "GBP", "GEL",
    "GHS", "GIP", "GMD", "GNF", "GTQ", "GYD", "HKD", "HNL", "HRK", "HTG", "HUF", "IDR", "ILS",
    "INR", "IQD", "IRR", "ISK", "JMD", "JOD", "JPY", "KES", "KGS", "KHR", "KMF", "KPW", "KRW",
    "KWD", "KYD", "KZT", "LAK", "LBP", "LKR", "LRD", "LSL", "LYD", "MAD", "MDL", "MGA", "MKD",
    "MMK", "MNT", "MOP", "MRU", "MUR", "MVR", "MWK", "MXN", "MXV", "MYR", "MZN", "NAD", "NGN",
    "NIO", "NOK", "NPR", "NZD", "OMR", "PAB", "PEN", "PGK", "PHP", "PKR", "PLN", "PYG", "QAR",
    "RON", "RSD", "RUB", "RWF", "SAR", "SBD", "SCR", "SDG", "SEK", "SGD", "SHP", "SLE", "SOS",
    "SRD", "SSP", "STN", "SVC", "SYP", "SZL", "THB", "TJS", "TMT", "TND", "TOP", "TRY", "TTD",
    "TWD", "TZS", "UAH", "UGX", "USD", "USN", "UYI", "UYU", "UYW", "UZS", "VED", "VES", "VND",
    "VUV", "WST", "XAF", "XAG", "XAU", "XBA", "XBB", "XBC", "XBD", "XCD", "XDR", "XOF", "XPD",
    "XPF", "XPT", "XSU", "XTS", "XUA", "XXX", "YER", "ZAR", "ZMW", "ZWL",
];

/// Returns `true` if the given code is a recognized ISO 4217 currency code.
pub fn is_iso4217_currency(code: &str) -> bool {
    ISO4217_CODES.binary_search(&code).is_ok()
}

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IRolesAuth {
        function hasRole(address account, bytes32 role) external view returns (bool);
        function getRoleAdmin(bytes32 role) external view returns (bytes32);
        function grantRole(bytes32 role, address account) external;
        function revokeRole(bytes32 role, address account) external;
        function renounceRole(bytes32 role) external;
        function setRoleAdmin(bytes32 role, bytes32 adminRole) external;

        event RoleMembershipUpdated(bytes32 indexed role, address indexed account, address indexed sender, bool hasRole);
        event RoleAdminUpdated(bytes32 indexed role, bytes32 indexed newAdminRole, address indexed sender);

        error Unauthorized();
    }
}

crate::sol! {
    /// TIP20 token interface providing standard ERC20 functionality with Tempo-specific extensions.
    ///
    /// TIP20 tokens extend the ERC20 standard with:
    /// - Currency denomination support for real-world asset backing
    /// - Transfer policy enforcement for compliance
    /// - Supply caps for controlled token issuance
    /// - Pause/unpause functionality for emergency controls
    /// - Memo support for transaction context
    /// The interface supports both standard token operations and administrative functions
    /// for managing token behavior and compliance requirements.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    #[allow(clippy::too_many_arguments)]
    interface ITIP20 {
        // Standard token functions
        function name() external view returns (string memory);
        function symbol() external view returns (string memory);
        function decimals() external pure returns (uint8);
        function totalSupply() external view returns (uint256);
        function quoteToken() external view returns (address);
        function nextQuoteToken() external view returns (address);
        function balanceOf(address account) external view returns (uint256);
        function transfer(address to, uint256 amount) external returns (bool);
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
        function mint(address to, uint256 amount) external;
        function burn(uint256 amount) external;

        // TIP20 Extension
        function currency() external view returns (string memory);
        function supplyCap() external view returns (uint256);
        function paused() external view returns (bool);
        function transferPolicyId() external view returns (uint64);
        function logoURI() external view returns (string memory);
        function setLogoURI(string calldata newLogoURI) external;
        function burnBlocked(address from, uint256 amount) external;
        /// @notice Burns from any unprotected account (requires BURN_AT_ROLE, T12+).
        function burnAt(address from, uint256 amount) external;
        function mintWithMemo(address to, uint256 amount, bytes32 memo) external;
        function burnWithMemo(uint256 amount, bytes32 memo) external;
        function transferWithMemo(address to, uint256 amount, bytes32 memo) external;
        function transferFromWithMemo(address from, address to, uint256 amount, bytes32 memo) external returns (bool);

        // Admin Functions
        function changeTransferPolicyId(uint64 newPolicyId) external;
        function setSupplyCap(uint256 newSupplyCap) external;
        function pause() external;
        function unpause() external;
        function setNextQuoteToken(address newQuoteToken) external;
        function completeQuoteTokenUpdate() external;

        /// @notice Returns the role identifier for pausing the contract
        /// @return The pause role identifier
        function PAUSE_ROLE() external view returns (bytes32);

        /// @notice Returns the role identifier for unpausing the contract
        /// @return The unpause role identifier
        function UNPAUSE_ROLE() external view returns (bytes32);

        /// @notice Returns the role identifier for issuing tokens
        /// @return The issuer role identifier
        function ISSUER_ROLE() external view returns (bytes32);

        /// @notice Returns the role identifier for burning tokens from blocked accounts
        /// @return The burn blocked role identifier
        function BURN_BLOCKED_ROLE() external view returns (bytes32);

        /// @notice Returns the role identifier for burning from any unprotected account (T12+).
        function BURN_AT_ROLE() external view returns (bytes32);

        // EIP-2612 Permit Functions
        function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
        function nonces(address owner) external view returns (uint256);
        function DOMAIN_SEPARATOR() external view returns (bytes32);

        struct UserRewardInfo {
            address rewardRecipient;
            uint256 rewardPerToken;
            uint256 rewardBalance;
        }

        // Reward Functions
        function distributeReward(uint256 amount) external;
        function setRewardRecipient(address recipient) external;
        function claimRewards() external returns (uint256);
        function optedInSupply() external view returns (uint128);
        function globalRewardPerToken() external view returns (uint256);
        function userRewardInfo(address account) external view returns (UserRewardInfo memory);
        function getPendingRewards(address account) external view returns (uint128);

        // Events
        event Transfer(address indexed from, address indexed to, uint256 amount);
        event Approval(address indexed owner, address indexed spender, uint256 amount);
        event Mint(address indexed to, uint256 amount);
        event Burn(address indexed from, uint256 amount);
        event BurnBlocked(address indexed from, uint256 amount);
        event BurnAt(address indexed burner, address indexed from, uint256 indexed amount);
        event TransferWithMemo(address indexed from, address indexed to, uint256 amount, bytes32 indexed memo);
        event TransferPolicyUpdate(address indexed updater, uint64 indexed newPolicyId);
        event SupplyCapUpdate(address indexed updater, uint256 indexed newSupplyCap);
        event PauseStateUpdate(address indexed updater, bool isPaused);
        event NextQuoteTokenSet(address indexed updater, address indexed nextQuoteToken);
        event QuoteTokenUpdate(address indexed updater, address indexed newQuoteToken);
        event RewardDistributed(address indexed funder, uint256 amount);
        event RewardRecipientSet(address indexed holder, address indexed recipient);
        event LogoURIUpdated(address indexed updater, string newLogoURI);

        // Errors
        error InsufficientBalance(uint256 available, uint256 required, address token);
        error InsufficientAllowance();
        error SupplyCapExceeded();
        error InvalidSupplyCap();
        error InvalidPayload();
        error PolicyForbids();
        error InvalidRecipient();
        error ContractPaused();
        error InvalidCurrency();
        error InvalidQuoteToken();
        error InvalidAmount();
        error NoOptedInSupply();
        error Unauthorized();
        error ProtectedAddress();
        error InvalidToken();
        error Uninitialized();
        error InvalidTransferPolicyId();
        error PermitExpired();
        error InvalidSignature();
        error LogoURITooLong();
        error InvalidLogoURI();
    }
}

impl ITIP20::ITIP20Calls {
    /// Returns the recipient address for the TIP-20 call, if one exists.
    pub fn to(&self) -> Option<Address> {
        Some(match self {
            Self::transfer(c) => c.to,
            Self::transferWithMemo(c) => c.to,
            Self::transferFrom(c) => c.to,
            Self::transferFromWithMemo(c) => c.to,
            Self::mint(c) => c.to,
            Self::mintWithMemo(c) => c.to,
            _ => return None,
        })
    }

    /// Returns `true` if `input` matches one of the recognized [TIP-20 payment] selectors:
    /// - `transfer` / `transferWithMemo`
    /// - `transferFrom` / `transferFromWithMemo`
    /// - `approve`
    /// - `mint` / `mintWithMemo`
    /// - `burn` / `burnWithMemo`
    ///
    /// # NOTES
    /// - Only validates calldata; the caller must check the TIP-20 address prefix on `to`.
    /// - Only selector and ABI-encoded length match, no decoding (better performance).
    /// - At most `max_trailing_bytes` may follow the ABI-encoded arguments: `0` before T13 and
    ///   [`MAX_PAYMENT_TRAILING_BYTES`] from T13.
    /// - Use [`PaymentSlots::classify`] when the call's addresses are needed as well.
    ///
    /// [TIP-20 payment]: <https://docs.tempo.xyz/protocol/tip20/overview#get-predictable-payment-fees>
    pub fn is_payment(input: &[u8], max_trailing_bytes: usize) -> bool {
        PaymentSlotsKind::from_calldata(input, max_trailing_bytes).is_some()
    }
}

/// [TIP-1045] Maximum number of bytes that may follow the ABI-encoded arguments of a static-only
/// payment call from T13.
///
/// Integrators commonly append a fixed-size tag, such as an attribution ID, after otherwise
/// canonical calldata.
///
/// [TIP-1045]: <https://docs.tempo.xyz/protocol/tips/tip-1045>
pub const MAX_PAYMENT_TRAILING_BYTES: usize = 32;

const WORD: usize = 32;
const ADDRESS_PADDING: usize = WORD - Address::len_bytes();

/// Returns `true` if `input` starts with the selector of `C`, followed by its static ABI-encoded
/// arguments and at most `max_trailing_bytes` trailing bytes.
pub(crate) fn is_static_call<C: SolCall>(input: &[u8], max_trailing_bytes: usize) -> bool {
    input.first_chunk::<4>() == Some(&C::SELECTOR)
        && <C::Parameters<'_> as SolType>::ENCODED_SIZE.is_some_and(|size| {
            input
                .len()
                .checked_sub(4 + size)
                .is_some_and(|trailing| trailing <= max_trailing_bytes)
        })
}

/// Shape of the addresses needed to derive a payment call's storage slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaymentSlotsKind {
    /// No addresses (`approve`, `burn`, `burnWithMemo`).
    Empty,
    /// Recipient only (`transfer`, `transferWithMemo`, `mint`, `mintWithMemo`).
    Direct,
    /// Token owner followed by recipient (`transferFrom`, `transferFromWithMemo`).
    Delegated,
}

impl PaymentSlotsKind {
    fn from_calldata(input: &[u8], max_trailing_bytes: usize) -> Option<Self> {
        if is_static_call::<ITIP20::transferCall>(input, max_trailing_bytes)
            || is_static_call::<ITIP20::transferWithMemoCall>(input, max_trailing_bytes)
            || is_static_call::<ITIP20::mintCall>(input, max_trailing_bytes)
            || is_static_call::<ITIP20::mintWithMemoCall>(input, max_trailing_bytes)
        {
            Some(Self::Direct)
        } else if is_static_call::<ITIP20::transferFromCall>(input, max_trailing_bytes)
            || is_static_call::<ITIP20::transferFromWithMemoCall>(input, max_trailing_bytes)
        {
            Some(Self::Delegated)
        } else if is_static_call::<ITIP20::approveCall>(input, max_trailing_bytes)
            || is_static_call::<ITIP20::burnCall>(input, max_trailing_bytes)
            || is_static_call::<ITIP20::burnWithMemoCall>(input, max_trailing_bytes)
        {
            Some(Self::Empty)
        } else {
            None
        }
    }
}

/// A [TIP-20 payment] call classified straight from calldata, without ABI decoding.
///
/// Carries only the addresses needed to derive the storage slots a payment touches, read
/// in place from the static ABI head. Its private array stores only a meaningful zero-to-two-
/// address prefix. Amounts and memos are never materialized, which is why this is cheaper than
/// decoding into [`ITIP20Calls`] just to read one or two addresses.
///
/// [TIP-20 payment]: <https://docs.tempo.xyz/protocol/tip20/overview#get-predictable-payment-fees>
/// [`ITIP20Calls`]: ITIP20::ITIP20Calls
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentSlots {
    kind: PaymentSlotsKind,
    addresses: [Address; 2],
}

impl PaymentSlots {
    /// Classifies payment calldata by selector and length, reading only its addresses.
    ///
    /// Accepts up to [`MAX_PAYMENT_TRAILING_BYTES`] trailing bytes, the most permissive
    /// classification of any hardfork, since the result only drives cache warming.
    pub fn classify(input: &[u8]) -> Option<Self> {
        fn address(input: &[u8], index: usize) -> Address {
            let start = 4 + WORD * index + ADDRESS_PADDING;
            Address::from_slice(&input[start..start + Address::len_bytes()])
        }

        let kind = PaymentSlotsKind::from_calldata(input, MAX_PAYMENT_TRAILING_BYTES)?;
        let addresses = match kind {
            PaymentSlotsKind::Empty => [Address::ZERO; 2],
            PaymentSlotsKind::Direct => [address(input, 0), Address::ZERO],
            PaymentSlotsKind::Delegated => [address(input, 0), address(input, 1)],
        };
        Some(Self { kind, addresses })
    }

    /// Returns the transfer or mint recipient, including memo variants, if any.
    pub const fn to(&self) -> Option<Address> {
        match self.kind {
            PaymentSlotsKind::Empty => None,
            PaymentSlotsKind::Direct => Some(self.addresses[0]),
            PaymentSlotsKind::Delegated => Some(self.addresses[1]),
        }
    }

    /// Returns the token owner for `transferFrom` and `transferFromWithMemo`, if any.
    pub const fn from(&self) -> Option<Address> {
        match self.kind {
            PaymentSlotsKind::Delegated => Some(self.addresses[0]),
            _ => None,
        }
    }

    /// Returns `[to]`, `[from, to]`, or an empty slice according to the payment shape.
    pub fn addresses(&self) -> &[Address] {
        let len = match self.kind {
            PaymentSlotsKind::Empty => 0,
            PaymentSlotsKind::Direct => 1,
            PaymentSlotsKind::Delegated => 2,
        };
        &self.addresses[..len]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{vec, vec::Vec};
    use alloy_primitives::{Address, B256, U256};
    use alloy_sol_types::SolInterface;

    #[rustfmt::skip]
    /// Returns valid ABI-encoded calldata for every recognized TIP-20 payment selector.
    fn payment_calldatas() -> [Vec<u8>; 9] {
        let (to, from, amount, memo) = (Address::random(), Address::random(), U256::random(), B256::random());

        [
            ITIP20::transferCall { to, amount }.abi_encode(),
            ITIP20::transferWithMemoCall { to, amount, memo }.abi_encode(),
            ITIP20::transferFromCall { from, to, amount }.abi_encode(),
            ITIP20::transferFromWithMemoCall { from, to, amount, memo }.abi_encode(),
            ITIP20::approveCall { spender: to, amount }.abi_encode(),
            ITIP20::mintCall { to, amount }.abi_encode(),
            ITIP20::mintWithMemoCall { to, amount, memo }.abi_encode(),
            ITIP20::burnCall { amount }.abi_encode(),
            ITIP20::burnWithMemoCall { amount, memo }.abi_encode(),
        ]
    }

    #[rustfmt::skip]
    /// Returns ABI-encoded calldata for TIP-20 selectors NOT recognized as payments.
    fn non_payment_calldatas() -> [Vec<u8>; 3] {
        let mut data = ITIP20::transferCall { to: Address::random(), amount: U256::random() }.abi_encode();
        data[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        [
            // non-payment TIP20 calls with known selectors
            ITIP20::claimRewardsCall {}.abi_encode(),
            ITIP20::permitCall {
                owner: Address::random(), spender: Address::random(), value: U256::random(), deadline: U256::random(),
                v: u8::MAX, r: B256::random(), s: B256::random() }.abi_encode(),
            // non-payment TIP20 calls with unknown selectors
            data,
        ]
    }

    #[test]
    fn test_is_payment() {
        for calldata in payment_calldatas() {
            assert!(ITIP20::ITIP20Calls::is_payment(&calldata, 0));
            assert!(ITIP20::ITIP20Calls::is_payment(
                &calldata,
                MAX_PAYMENT_TRAILING_BYTES
            ));
        }

        for calldata in non_payment_calldatas() {
            assert!(!ITIP20::ITIP20Calls::is_payment(&calldata, 0));
            assert!(!ITIP20::ITIP20Calls::is_payment(
                &calldata,
                MAX_PAYMENT_TRAILING_BYTES
            ));
        }
    }

    #[test]
    fn test_is_payment_trailing_bytes() {
        for calldata in payment_calldatas() {
            for trailing in 1..=MAX_PAYMENT_TRAILING_BYTES {
                let mut input = calldata.clone();
                input.extend(core::iter::repeat_n(0xab, trailing));
                assert!(!ITIP20::ITIP20Calls::is_payment(&input, 0));
                assert!(ITIP20::ITIP20Calls::is_payment(
                    &input,
                    MAX_PAYMENT_TRAILING_BYTES
                ));
            }

            let mut input = calldata;
            input.extend([0xab; MAX_PAYMENT_TRAILING_BYTES + 1]);
            assert!(!ITIP20::ITIP20Calls::is_payment(
                &input,
                MAX_PAYMENT_TRAILING_BYTES
            ));
        }
    }

    /// The `from` argument the decode-based path derives for the `transferFrom` variants.
    fn decoded_from(call: &ITIP20::ITIP20Calls) -> Option<Address> {
        match call {
            ITIP20::ITIP20Calls::transferFrom(c) => Some(c.from),
            ITIP20::ITIP20Calls::transferFromWithMemo(c) => Some(c.from),
            _ => None,
        }
    }

    #[test]
    fn test_classify_matches_decoded_call() {
        for calldata in payment_calldatas() {
            let decoded = ITIP20::ITIP20Calls::abi_decode(&calldata).expect("decodes");
            let classified = PaymentSlots::classify(&calldata).expect("classifies");

            assert_eq!(classified.to(), decoded.to());
            assert_eq!(classified.from(), decoded_from(&decoded));
            let expected = match (decoded_from(&decoded), decoded.to()) {
                (Some(from), Some(to)) => vec![from, to],
                (None, Some(to)) => vec![to],
                (None, None) => vec![],
                (Some(_), None) => unreachable!("payment owner without recipient"),
            };
            assert_eq!(classified.addresses(), expected);
        }
    }

    #[test]
    fn test_classify_rejects_non_payment_and_malformed_calldata() {
        for calldata in non_payment_calldatas() {
            assert!(PaymentSlots::classify(&calldata).is_none());
        }

        for calldata in payment_calldatas() {
            // every truncation of valid payment calldata is rejected, and none panics
            for len in 0..calldata.len() {
                assert!(
                    PaymentSlots::classify(&calldata[..len]).is_none(),
                    "truncated to {len} bytes must not classify"
                );
            }

            // up to `MAX_PAYMENT_TRAILING_BYTES` trailing bytes classify, more do not
            let mut trailing = calldata.clone();
            trailing.extend([0xab; MAX_PAYMENT_TRAILING_BYTES]);
            assert_eq!(
                PaymentSlots::classify(&trailing),
                PaymentSlots::classify(&calldata)
            );
            trailing.push(0);
            assert!(PaymentSlots::classify(&trailing).is_none());
        }
    }
}
