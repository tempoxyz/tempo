# Solidity Macro Redesign Specification

## Overview

This document specifies enhancements to the `#[solidity]` and `#[contract]` proc-macros to:
1. Eliminate manual re-export boilerplate
2. Auto-generate unified dispatch enums for contracts composed of multiple solidity modules
3. Maintain clean separation between ABI definition (`#[solidity]`) and contract composition (`#[contract]`)

## Current Pain Points

- **Manual re-exports**: `types.rs` has large `pub use` blocks to re-export generated types
- **Manual dispatch enum**: `dispatch.rs` manually defines `TIP20Call` wrapping 3 `Calls` enums
- **Split definitions**: Related functionality split across modules (e.g., rewards errors in types.rs)

## Design Principles

- `#[solidity]` = ABI definition (single module, single responsibility)
- `#[contract]` = Composition point (aggregates multiple solidity modules)
- No new macros - extend existing infrastructure

---

## 1. `#[solidity]` Macro Changes

### 1.1 Always Generate Core Types

The macro must always generate `Error`, `Event`, and `Calls` types, even when the user doesn't define them. This ensures consistent composition in `#[contract]`.

**Example - Module with only Interface:**

```rust
#[solidity]
pub mod rewards {
    pub trait Interface {
        fn claim_rewards(&mut self) -> Result<U256>;
    }
}
```

**Generates:**

```rust
pub mod rewards {
    // User's interface generates Calls as today
    pub enum Calls { claimRewards(claimRewardsCall) }
    
    // Dummy Error - no variants, but implements required API
    pub enum Error {}
    impl Error {
        pub const SELECTORS: &'static [[u8; 4]] = &[];
        pub fn valid_selector(_: [u8; 4]) -> bool { false }
    }
    
    // Dummy Event - no variants
    pub enum Event {}
    impl Event {
        pub const SELECTORS: &'static [B256] = &[];
    }
}
```

### 1.2 Required API for Generated Types

| Type | Required API |
|------|-------------|
| `Calls` | `SELECTORS: &[[u8; 4]]`, `valid_selector([u8;4]) -> bool`, `abi_decode(&[u8]) -> Result<Self>` |
| `Error` | `SELECTORS: &[[u8; 4]]`, `valid_selector([u8;4]) -> bool`, `selector(&self) -> [u8;4]` |
| `Event` | `SELECTORS: &[B256]` (topic0 hashes) |

### 1.3 Auto Re-exports

After generating the module, emit sibling re-export items:

```rust
#[solidity]
pub mod tip20 { ... }

// Auto-generated after module:
pub use self::tip20::*;

#[allow(non_snake_case)]
pub mod ITIP20 {
    #![allow(ambiguous_glob_reexports)]
    pub use super::tip20::*;
}
```

**Naming convention**: Module `tip20` → re-export module `ITIP20` (capitalize, prefix with `I`)

**Optional attribute to customize:**
```rust
#[solidity(interface_alias = "MyCustomName")]
pub mod tip20 { ... }
```

---

## 2. `#[contract]` Macro Extension

### 2.1 New Attribute Syntax

```rust
#[contract(types(tip20, roles_auth, rewards))]
pub struct TIP20Token {
    // existing fields...
}
```

Paths are relative to the current module. Absolute paths also supported:

```rust
#[contract(types(
    crate::tip20::types::tip20,
    crate::tip20::types::roles_auth,
    crate::tip20::types::rewards,
))]
pub struct TIP20Token { ... }
```

### 2.2 Generated Unified Types

Given `#[contract(types(tip20, roles_auth, rewards))]` on `TIP20Token`:

#### 2.2.1 Unified Calls Enum

```rust
pub enum TIP20TokenCalls {
    Tip20(tip20::Calls),
    RolesAuth(roles_auth::Calls),
    Rewards(rewards::Calls),
}

impl TIP20TokenCalls {
    /// All function selectors from all composed modules
    pub const SELECTORS: &'static [[u8; 4]] = &[
        // Flattened from all modules
    ];
    
    /// Decode calldata into the appropriate variant
    pub fn decode(calldata: &[u8]) -> Result<Self, alloy::sol_types::Error> {
        let selector: [u8; 4] = calldata
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| alloy::sol_types::Error::Other("calldata too short".into()))?;
        
        // Order matches attribute order - first match wins
        if tip20::Calls::valid_selector(selector) {
            tip20::Calls::abi_decode(calldata).map(Self::Tip20)
        } else if roles_auth::Calls::valid_selector(selector) {
            roles_auth::Calls::abi_decode(calldata).map(Self::RolesAuth)
        } else if rewards::Calls::valid_selector(selector) {
            rewards::Calls::abi_decode(calldata).map(Self::Rewards)
        } else {
            // Fallback to first module for unknown selectors
            tip20::Calls::abi_decode(calldata).map(Self::Tip20)
        }
    }
}
```

#### 2.2.2 Unified Error Enum

```rust
pub enum TIP20TokenError {
    Tip20(tip20::Error),
    RolesAuth(roles_auth::Error),
    Rewards(rewards::Error),
}

impl TIP20TokenError {
    pub fn selector(&self) -> [u8; 4] {
        match self {
            Self::Tip20(e) => e.selector(),
            Self::RolesAuth(e) => e.selector(),
            Self::Rewards(e) => e.selector(),
        }
    }
}

// From implementations for ergonomic error conversion
impl From<tip20::Error> for TIP20TokenError {
    fn from(e: tip20::Error) -> Self { Self::Tip20(e) }
}

impl From<roles_auth::Error> for TIP20TokenError {
    fn from(e: roles_auth::Error) -> Self { Self::RolesAuth(e) }
}

impl From<rewards::Error> for TIP20TokenError {
    fn from(e: rewards::Error) -> Self { Self::Rewards(e) }
}
```

#### 2.2.3 Unified Event Enum

```rust
pub enum TIP20TokenEvent {
    Tip20(tip20::Event),
    RolesAuth(roles_auth::Event),
    Rewards(rewards::Event),
}

// From implementations
impl From<tip20::Event> for TIP20TokenEvent {
    fn from(e: tip20::Event) -> Self { Self::Tip20(e) }
}

impl From<roles_auth::Event> for TIP20TokenEvent {
    fn from(e: roles_auth::Event) -> Self { Self::RolesAuth(e) }
}

impl From<rewards::Event> for TIP20TokenEvent {
    fn from(e: rewards::Event) -> Self { Self::Rewards(e) }
}
```

### 2.3 Naming Convention

| Struct Name | Generated Types |
|-------------|-----------------|
| `TIP20Token` | `TIP20TokenCalls`, `TIP20TokenError`, `TIP20TokenEvent` |
| `Foo` | `FooCalls`, `FooError`, `FooEvent` |

Optional override via attribute:

```rust
#[contract(
    types(tip20, roles_auth),
    calls_name = "TIP20Call",
    error_name = "TIP20Error",
    event_name = "TIP20Event",
)]
pub struct TIP20Token { ... }
```

### 2.4 Variant Naming

Module path `tip20` → Variant name `Tip20` (PascalCase)
Module path `roles_auth` → Variant name `RolesAuth` (PascalCase, underscores removed)

---

## 3. Updated Usage Example

### 3.1 types.rs (Before)

```rust
#[solidity]
pub mod tip20 { ... }

#[solidity]
pub mod roles_auth { ... }

#[solidity]
pub mod rewards { ... }

// Manual re-exports (60+ lines)
pub use self::tip20::{
    Approval, Burn, BurnBlocked, Calls as TIP20Calls, ...
};

#[allow(non_snake_case)]
pub mod ITIP20 {
    pub use super::tip20::*;
}
// ... more manual re-exports
```

### 3.2 types.rs (After)

```rust
#[solidity]
pub mod tip20 { ... }
// Auto-generates: pub use self::tip20::*; and pub mod ITIP20 { ... }

#[solidity]
pub mod roles_auth { ... }
// Auto-generates: pub use self::roles_auth::*; and pub mod IRolesAuth { ... }

#[solidity]
pub mod rewards { ... }
// Auto-generates: pub use self::rewards::*; and pub mod IRewards { ... }

// No manual re-exports needed!
```

### 3.3 mod.rs (Before)

```rust
#[contract]
pub struct TIP20Token { ... }

// Manual re-exports from types
pub use types::{
    tip20, ITIP20, TIP20Calls, TIP20Error, TIP20Event,
    roles_auth, IRolesAuth, ...
};
```

### 3.4 mod.rs (After)

```rust
#[contract(types(
    types::tip20,
    types::roles_auth,
    types::rewards,
))]
pub struct TIP20Token { ... }

// Auto-generates: TIP20TokenCalls, TIP20TokenError, TIP20TokenEvent
// Re-exports from types are handled by #[solidity] auto-exports
```

### 3.5 dispatch.rs (Before)

```rust
enum TIP20Call {
    TIP20(ITIP20Calls),
    RolesAuth(roles_auth::Calls),
    Rewards(rewards::Calls),
}

impl TIP20Call {
    fn decode(calldata: &[u8]) -> Result<Self, alloy::sol_types::Error> {
        // 20+ lines of manual selector checking
    }
}

impl Precompile for TIP20Token {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        dispatch_call(calldata, TIP20Call::decode, |call| match call {
            TIP20Call::TIP20(ITIP20Calls::name(_)) => { ... }
            // ...
        })
    }
}
```

### 3.6 dispatch.rs (After)

```rust
// TIP20TokenCalls is auto-generated by #[contract]

impl Precompile for TIP20Token {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        dispatch_call(calldata, TIP20TokenCalls::decode, |call| match call {
            TIP20TokenCalls::Tip20(tip20::Calls::name(_)) => { ... }
            TIP20TokenCalls::IRolesAuth(roles_auth::Calls::hasRole(c)) => { ... }
            TIP20TokenCalls::IRewards(rewards::Calls::claimRewards(c)) => { ... }
            // ...
        })
    }
}
```

---

## 4. Edge Cases & Error Handling

| Case | Behavior |
|------|----------|
| Selector collision across modules | Compile-time error with clear message listing conflicting selectors and their sources |
| Empty module (no Interface/Error/Event) | Uses dummy enums; variant still appears in unified enum |
| Single module | Still generates unified enum with one variant |
| Module not found | Standard Rust path resolution error |
| Module missing required types | Compile-time error: "Module X does not appear to be a #[solidity] module" |

---

## 5. Implementation Plan

### Phase 1: `#[solidity]` Dummy Types
- Modify `#[solidity]` to always emit `Error`, `Event`, `Calls` (dummy if not defined)
- Ensure dummy types implement required API
- Add tests for modules with missing definitions

### Phase 2: `#[solidity]` Auto Re-exports
- Generate `pub use self::module::*` after module
- Generate `pub mod I{ModuleName} { ... }` interface alias module
- Add attribute option to customize/disable

### Phase 3: `#[contract]` Types Composition
- Parse `types(...)` attribute argument
- Generate unified `{StructName}Calls` enum with `decode()` method
- Generate unified `{StructName}Error` enum with `From` impls
- Generate unified `{StructName}Event` enum with `From` impls

### Phase 4: Migration
- Update TIP20 to use new pattern
- Remove manual re-exports from types.rs
- Remove manual TIP20Call enum from dispatch.rs
- Update all match arms to use new variant paths

### Phase 5: Documentation & Cleanup
- Document new macro features
- Add comprehensive tests
- Remove deprecated patterns

---

## 6. Design Decisions

1. **Fallback behavior for unknown selectors**: Return decode error immediately.
   
   When `decode()` receives calldata with a selector that doesn't match any of the composed modules, it should return an `Err` rather than attempting to decode with the first module (which would produce a confusing error message).

   ```rust
   pub fn decode(calldata: &[u8]) -> Result<Self, alloy::sol_types::Error> {
       let selector: [u8; 4] = calldata
           .get(..4)
           .and_then(|s| s.try_into().ok())
           .ok_or_else(|| alloy::sol_types::Error::Other("calldata too short".into()))?;
       
       if tip20::Calls::valid_selector(selector) {
           tip20::Calls::abi_decode(calldata).map(Self::Tip20)
       } else if roles_auth::Calls::valid_selector(selector) {
           roles_auth::Calls::abi_decode(calldata).map(Self::RolesAuth)
       } else if rewards::Calls::valid_selector(selector) {
           rewards::Calls::abi_decode(calldata).map(Self::Rewards)
       } else {
           Err(alloy::sol_types::Error::Other(
               format!("unknown selector: 0x{}", hex::encode(selector)).into()
           ))
       }
   }
   ```

2. **Variant naming**: Use module name only, no custom naming support.
   
   Module path `tip20` → Variant name `Tip20` (PascalCase)
   Module path `roles_auth` → Variant name `RolesAuth` (PascalCase, underscores removed)

3. **Flattened SELECTORS**: Yes, flatten selectors from all modules.
   
   The unified `Calls` enum includes a flattened `SELECTORS` constant that concatenates all selectors from each composed module. This enables:
   - Selector coverage testing across the entire contract
   - Iteration over all valid selectors for documentation/tooling

   ```rust
   impl TIP20TokenCalls {
       /// All function selectors from all composed modules (flattened)
       pub const SELECTORS: &'static [[u8; 4]] = &[
           // tip20::Calls::SELECTORS entries
           [0x06, 0xfd, 0xde, 0x03], // name()
           [0x95, 0xd8, 0x9b, 0x41], // symbol()
           // ... all tip20 selectors
           
           // roles_auth::Calls::SELECTORS entries  
           [0x91, 0xd1, 0x48, 0x54], // hasRole(address,bytes32)
           // ... all roles_auth selectors
           
           // rewards::Calls::SELECTORS entries
           [0x3d, 0x18, 0xb9, 0x12], // claimRewards()
           // ... all rewards selectors
       ];
   }
   ```

4. **Event topic routing**: Not needed for now, `From` impls are sufficient.
   
   Events are emitted by the contract, not decoded from external input like calls. The current use case is:
   - Contract logic creates a specific event (e.g., `tip20::Event::Transfer(...)`)
   - Convert to unified enum via `From` impl for logging/storage
   
   A unified `decode_log(topics, data)` method would be useful if we needed to:
   - Parse logs from transaction receipts
   - Index historical events from multiple interfaces
   
   This can be added later if needed. For now, `From` impls provide the necessary functionality.
