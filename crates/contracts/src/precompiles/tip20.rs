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
    /// - Only selector and exact ABI-encoded length match, no decoding (better performance).
    /// - Shares its selector table with [`PaymentCallKind::from_calldata`]; use
    ///   [`PaymentCall::classify`] when the call's addresses are needed as well.
    ///
    /// [TIP-20 payment]: <https://docs.tempo.xyz/protocol/tip20/overview#get-predictable-payment-fees>
    pub fn is_payment(input: &[u8]) -> bool {
        PaymentCallKind::from_calldata(input).is_some()
    }

    /// Returns addresses whose balance slots are accessed by this call.
    ///
    /// For transfers: `[to]` or `[from, to]`. For mints: `[to]`.
    /// For burns, approves, and view calls: empty.
    pub fn balance_addresses(&self) -> [Option<Address>; 2] {
        match self {
            Self::transfer(c) => [Some(c.to), None],
            Self::transferWithMemo(c) => [Some(c.to), None],
            Self::transferFrom(c) => [Some(c.from), Some(c.to)],
            Self::transferFromWithMemo(c) => [Some(c.from), Some(c.to)],
            Self::mint(c) => [Some(c.to), None],
            Self::mintWithMemo(c) => [Some(c.to), None],
            _ => [None, None],
        }
    }

    /// Returns addresses whose rewards slots are accessed by this call.
    pub fn reward_addresses(&self, sender: Address) -> [Option<Address>; 2] {
        match self {
            Self::transfer(c) => [Some(sender), Some(c.to)],
            Self::transferWithMemo(c) => [Some(sender), Some(c.to)],
            Self::transferFrom(c) => [Some(c.from), Some(c.to)],
            Self::transferFromWithMemo(c) => [Some(c.from), Some(c.to)],
            Self::mint(c) => [Some(c.to), None],
            Self::mintWithMemo(c) => [Some(c.to), None],
            Self::burn(_) | Self::burnWithMemo(_) => [Some(sender), Some(Address::ZERO)],
            _ => [None, None],
        }
    }
}

/// Size of an ABI head word.
const WORD: usize = 32;

/// Left padding of an `address` inside its 32-byte ABI head word.
const ADDRESS_PADDING: usize = WORD - Address::len_bytes();

/// One of the nine [TIP-20 payment] calls recognized by [`ITIP20Calls::is_payment`].
///
/// All nine take fully static parameters, so their calldata is the 4-byte selector followed
/// by one 32-byte head word per argument.
///
/// [TIP-20 payment]: <https://docs.tempo.xyz/protocol/tip20/overview#get-predictable-payment-fees>
/// [`ITIP20Calls::is_payment`]: ITIP20::ITIP20Calls::is_payment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaymentCallKind {
    /// `transfer(address to, uint256 amount)`
    Transfer,
    /// `transferWithMemo(address to, uint256 amount, bytes32 memo)`
    TransferWithMemo,
    /// `transferFrom(address from, address to, uint256 amount)`
    TransferFrom,
    /// `transferFromWithMemo(address from, address to, uint256 amount, bytes32 memo)`
    TransferFromWithMemo,
    /// `approve(address spender, uint256 amount)`
    Approve,
    /// `mint(address to, uint256 amount)`
    Mint,
    /// `mintWithMemo(address to, uint256 amount, bytes32 memo)`
    MintWithMemo,
    /// `burn(uint256 amount)`
    Burn,
    /// `burnWithMemo(uint256 amount, bytes32 memo)`
    BurnWithMemo,
}

impl PaymentCallKind {
    /// Classifies raw `input` by its 4-byte selector and exact ABI-encoded length.
    ///
    /// Returns `None` for any other calldata, including truncated, over-long, or empty input.
    ///
    /// # NOTE
    /// Only validates calldata; the caller must check the TIP-20 address prefix on `to`.
    pub fn from_calldata(input: &[u8]) -> Option<Self> {
        /// Returns `true` if `input` is `C`'s selector followed by exactly `C`'s statically
        /// sized parameter encoding.
        fn is_call<C: SolCall>(input: &[u8]) -> bool {
            let Some(encoded_size) = <C::Parameters<'_> as SolType>::ENCODED_SIZE else {
                return false;
            };

            input.first_chunk::<4>() == Some(&C::SELECTOR) && input.len() == 4 + encoded_size
        }

        if is_call::<ITIP20::transferCall>(input) {
            Some(Self::Transfer)
        } else if is_call::<ITIP20::transferWithMemoCall>(input) {
            Some(Self::TransferWithMemo)
        } else if is_call::<ITIP20::transferFromCall>(input) {
            Some(Self::TransferFrom)
        } else if is_call::<ITIP20::transferFromWithMemoCall>(input) {
            Some(Self::TransferFromWithMemo)
        } else if is_call::<ITIP20::approveCall>(input) {
            Some(Self::Approve)
        } else if is_call::<ITIP20::mintCall>(input) {
            Some(Self::Mint)
        } else if is_call::<ITIP20::mintWithMemoCall>(input) {
            Some(Self::MintWithMemo)
        } else if is_call::<ITIP20::burnCall>(input) {
            Some(Self::Burn)
        } else if is_call::<ITIP20::burnWithMemoCall>(input) {
            Some(Self::BurnWithMemo)
        } else {
            None
        }
    }
}

/// A [TIP-20 payment] call classified straight from calldata, without ABI decoding.
///
/// Carries only the addresses needed to derive the storage slots a payment touches, read
/// in place from the static ABI head. Amounts and memos are never materialized, which is
/// why this is cheaper than decoding into [`ITIP20Calls`] just to read one or two addresses.
///
/// [TIP-20 payment]: <https://docs.tempo.xyz/protocol/tip20/overview#get-predictable-payment-fees>
/// [`ITIP20Calls`]: ITIP20::ITIP20Calls
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaymentCall {
    /// Which of the nine payment calls this is.
    kind: PaymentCallKind,
    /// The `to` argument of the transfer and mint variants.
    to: Option<Address>,
    /// The `from` argument of the `transferFrom` variants.
    from: Option<Address>,
}

impl PaymentCall {
    /// Classifies raw `input` as one of the nine TIP-20 payment calls and reads its address
    /// arguments, or returns `None` if `input` is not a payment call.
    ///
    /// # NOTES
    /// - Selector and exact ABI-encoded length match only, no decoding (better performance).
    /// - Only validates calldata; the caller must check the TIP-20 address prefix on `to`.
    /// - Addresses are read from the low 20 bytes of their head word. Like the non-validating
    ///   [`SolCall::abi_decode`], the upper 12 padding bytes are not checked.
    pub fn classify(input: &[u8]) -> Option<Self> {
        /// Reads the address in ABI head word `index`, counting the selector as word `-1`.
        fn head_address(input: &[u8], index: usize) -> Option<Address> {
            let start = 4 + WORD * index + ADDRESS_PADDING;
            input
                .get(start..start + Address::len_bytes())
                .map(Address::from_slice)
        }

        let kind = PaymentCallKind::from_calldata(input)?;
        let (from, to) = match kind {
            // `to` is the first argument.
            PaymentCallKind::Transfer
            | PaymentCallKind::TransferWithMemo
            | PaymentCallKind::Mint
            | PaymentCallKind::MintWithMemo => (None, Some(head_address(input, 0)?)),
            // `from` is the first argument, `to` the second.
            PaymentCallKind::TransferFrom | PaymentCallKind::TransferFromWithMemo => {
                (Some(head_address(input, 0)?), Some(head_address(input, 1)?))
            }
            // `approve`'s spender and the burn amounts are not used for slot derivation.
            PaymentCallKind::Approve | PaymentCallKind::Burn | PaymentCallKind::BurnWithMemo => {
                (None, None)
            }
        };

        Some(Self { kind, to, from })
    }

    /// Returns which of the nine payment calls this is.
    pub const fn kind(&self) -> PaymentCallKind {
        self.kind
    }

    /// Returns the recipient address for the TIP-20 call, if one exists.
    ///
    /// Equivalent to [`ITIP20Calls::to`](ITIP20::ITIP20Calls::to).
    pub const fn to(&self) -> Option<Address> {
        self.to
    }

    /// Returns the token owner debited by the `transferFrom` variants, if any.
    ///
    /// This is the address whose `allowances[from][spender]` slot the call reads.
    pub const fn from(&self) -> Option<Address> {
        self.from
    }

    /// Returns addresses whose balance slots are accessed by this call.
    ///
    /// Equivalent to [`ITIP20Calls::balance_addresses`](ITIP20::ITIP20Calls::balance_addresses).
    pub const fn balance_addresses(&self) -> [Option<Address>; 2] {
        match self.kind {
            PaymentCallKind::TransferFrom | PaymentCallKind::TransferFromWithMemo => {
                [self.from, self.to]
            }
            PaymentCallKind::Transfer
            | PaymentCallKind::TransferWithMemo
            | PaymentCallKind::Mint
            | PaymentCallKind::MintWithMemo => [self.to, None],
            PaymentCallKind::Approve | PaymentCallKind::Burn | PaymentCallKind::BurnWithMemo => {
                [None, None]
            }
        }
    }

    /// Returns addresses whose rewards slots are accessed by this call.
    ///
    /// Equivalent to [`ITIP20Calls::reward_addresses`](ITIP20::ITIP20Calls::reward_addresses).
    pub const fn reward_addresses(&self, sender: Address) -> [Option<Address>; 2] {
        match self.kind {
            PaymentCallKind::Transfer | PaymentCallKind::TransferWithMemo => {
                [Some(sender), self.to]
            }
            PaymentCallKind::TransferFrom | PaymentCallKind::TransferFromWithMemo => {
                [self.from, self.to]
            }
            PaymentCallKind::Mint | PaymentCallKind::MintWithMemo => [self.to, None],
            PaymentCallKind::Burn | PaymentCallKind::BurnWithMemo => {
                [Some(sender), Some(Address::ZERO)]
            }
            PaymentCallKind::Approve => [None, None],
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec::Vec;
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
            assert!(ITIP20::ITIP20Calls::is_payment(&calldata))
        }

        for calldata in non_payment_calldatas() {
            assert!(!ITIP20::ITIP20Calls::is_payment(&calldata))
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
        // distinct senders, including the zero address used by the burn reward slots
        let senders = [Address::random(), Address::random(), Address::ZERO];

        for calldata in payment_calldatas() {
            let decoded = ITIP20::ITIP20Calls::abi_decode(&calldata).expect("decodes");
            let classified = PaymentCall::classify(&calldata).expect("classifies");

            assert_eq!(classified.to(), decoded.to());
            assert_eq!(classified.from(), decoded_from(&decoded));
            assert_eq!(classified.balance_addresses(), decoded.balance_addresses());

            for sender in senders {
                assert_eq!(
                    classified.reward_addresses(sender),
                    decoded.reward_addresses(sender),
                );
            }
        }
    }

    #[test]
    fn test_classify_rejects_non_payment_and_malformed_calldata() {
        for calldata in non_payment_calldatas() {
            assert!(PaymentCallKind::from_calldata(&calldata).is_none());
            assert!(PaymentCall::classify(&calldata).is_none());
        }

        for calldata in payment_calldatas() {
            // every truncation of valid payment calldata is rejected, and none panics
            for len in 0..calldata.len() {
                assert!(
                    PaymentCall::classify(&calldata[..len]).is_none(),
                    "truncated to {len} bytes must not classify"
                );
            }

            // trailing bytes break the exact length match, unlike a non-validating decode
            let mut trailing = calldata.clone();
            trailing.push(0);
            assert!(PaymentCall::classify(&trailing).is_none());
        }
    }
}
