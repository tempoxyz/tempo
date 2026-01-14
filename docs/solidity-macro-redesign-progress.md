# Solidity Macro Redesign - Progress Tracker

> **Spec**: [solidity-macro-redesign.md](./solidity-macro-redesign.md) — refer to spec for requirements and design details.

## Status

| Phase | Status | PR |
|-------|--------|-----|
| 1. `#[solidity]` Dummy Types | ✅ Complete | — |
| 2. `#[solidity]` Auto Re-exports | ✅ Complete | — |
| 3. `#[contract(types(...))]` Composition | ✅ Complete | — |
| 4. TIP20 Migration | ✅ Complete | — |
| 5. Docs & Cleanup | ✅ Complete | — |

---

## Phase 1: Dummy Types

**Files**: `crates/precompiles-macros/src/solidity/{mod.rs, common.rs}`

- [x] Dummy `Error` enum (empty + SELECTORS/valid_selector/selector impls)
- [x] Dummy `Event` enum (empty + SELECTORS + IntoLogData impl)
- [x] Dummy `Calls` enum (empty + SELECTORS/valid_selector/abi_decode impls)
- [x] Tests for modules with missing definitions
- [x] Event::SELECTORS added to real Event containers

**Blockers**: None

---

## Phase 2: Auto Re-exports

**Files**: `crates/precompiles-macros/src/solidity/mod.rs`, `crates/precompiles-macros/src/lib.rs`, `crates/precompiles-macros/src/utils.rs`

- [x] `pub use self::{module}::*` after module
- [x] `pub mod I{ModuleName} { pub use super::{module}::*; }` alias
- [x] `#[solidity(interface_alias = "...")]` attribute
- [x] `#[solidity(no_reexport)]` opt-out

**Blockers**: None (Complete)

---

## Phase 3: Contract Composition

**Files**: `crates/precompiles-macros/src/composition.rs`, `crates/precompiles-macros/src/lib.rs`

- [x] Parse `types(mod1, mod2, ...)` attribute
- [x] Generate `{Struct}Calls` with flattened SELECTORS + decode()
- [x] Generate `{Struct}Error` with From impls
- [x] Generate `{Struct}Event` with From impls
- [ ] Selector collision detection (compile-time error) - deferred to Phase 5

**Blockers**: None (Complete)

---

## Phase 4: TIP20 Migration

**Files**: `crates/precompiles/src/tip20/{types.rs, dispatch.rs, mod.rs}`

- [x] Add `#[contract(solidity(...))]` to TIP20Token
- [x] Remove manual re-exports from types.rs
- [x] Remove manual TIP20Call enum from dispatch.rs  
- [x] Update match arms to new variant paths
- [x] All tests pass (69 TIP20 tests)

**Blockers**: None (Complete)

---

## Phase 5: Docs & Cleanup

- [x] Document new macro features in crate docs (`lib.rs`)
- [x] Integration tests for dummy types and auto re-exports (`tests/macro_tests.rs`)
- [x] Fix composition.rs inner type name bug (was using `TIP20TokenError` instead of `Error`)

**Blockers**: None (Complete)

---

## Implementation Log

### 2026-01-14 — Phase 5 Complete

**Changes**:
- `lib.rs`: Extended `#[contract]` documentation with `abi(...)` composition feature, dispatch pattern example
- `lib.rs`: Extended `#[solidity]` documentation with auto re-exports, dummy types, and interface alias sections
- `tests/macro_tests.rs`: Added 9 integration tests for dummy types and auto re-exports
- `composition.rs`: Fixed bug where `inner_type` was incorrectly set to `TIP20TokenError` instead of `Error`

**New Tests**:
- `test_dummy_error_for_interface_only_module` - Verifies dummy Error for Interface-only modules
- `test_dummy_event_for_interface_only_module` - Verifies dummy Event for Interface-only modules
- `test_real_calls_for_interface_only_module` - Verifies real Calls generation
- `test_dummy_types_for_struct_only_module` - Verifies all dummy types for struct-only modules
- `test_real_error_with_dummy_calls` - Verifies mixed real/dummy types
- `test_auto_reexport_types` - Verifies `pub use self::module::*` works
- `test_interface_alias_module` - Verifies `I{PascalCase}` module alias
- `test_no_reexport_requires_qualified_access` - Verifies `no_reexport` opt-out
- `test_custom_interface_alias` - Verifies `interface_alias = "..."` attribute

**Test Results**: All 46 macro tests pass, all 69 TIP20 tests pass

---

### 2026-01-14 — Phase 4 Complete

**Changes**:
- `mod.rs`: Added `#[contract(types(types::tip20, types::roles_auth, types::rewards))]` to TIP20Token
- `types.rs`: Removed `no_reexport` from all `#[solidity]` modules, removed ~55 lines of manual re-exports
- `types.rs`: Added backward-compatibility aliases (`ITIP20 -> ITip20`, type aliases for `TIP20Error`, etc.)
- `dispatch.rs`: Removed manual `TIP20Call` enum (~25 lines), now uses auto-generated `TIP20TokenCalls`
- `dispatch.rs`: Updated all match arms from `TIP20Call::TIP20(ITIP20Calls::xxx)` to `TIP20TokenCalls::Tip20(tip20::Calls::xxx)`
- `composition.rs`: Fixed fully qualified trait paths for `valid_selector` and `abi_decode` calls

**Generated Types**:
- `TIP20TokenCalls` - Unified calls enum with `Tip20`, `RolesAuth`, `Rewards` variants
- `TIP20TokenError` - Unified error enum with `From` impls for each module's Error
- `TIP20TokenEvent` - Unified event enum with `From` impls for each module's Event

**Backward Compatibility**:
- `ITIP20` module alias preserved (points to auto-generated `ITip20`)
- Individual type re-exports preserved (`TIP20Error`, `TIP20Event`, `RolesAuthError`, etc.)
- External crates (`tempo-revm`, `tempo-evm`) compile without changes

**Test Results**: All 69 TIP20 tests pass

---

### 2026-01-14 — Phase 3 Complete

**Changes**:
- `composition.rs`: New module for generating unified Calls/Error/Event enums from multiple solidity modules
- `lib.rs`: Extended `ContractConfig` to parse `solidity(mod1, mod2, ...)` attribute, updated `gen_contract_output()` to call composition generation
- `tip20/composition_test.rs`: Added 6 tests validating composition with real TIP20 modules

**Implementation Details**:
- `#[contract(types(tip20, roles_auth, rewards))]` generates `{ContractName}Calls`, `{ContractName}Error`, `{ContractName}Event`
- Unified `Calls` enum implements `SolInterface` with flattened `SELECTORS` constant and `abi_decode()` that routes by selector
- Unified `Error` enum implements `SolInterface` with `From<ModuleError>` impls for ergonomic error conversion
- Unified `Event` enum implements `IntoLogData` with `From<ModuleEvent>` impls
- Module path `tip20` → variant name `Tip20` (PascalCase via `to_pascal_case()`)
- Unknown selectors return `Err(Error::unknown_selector(...))`

**API for Generated Types**:
| Type | API |
|------|-----|
| `{Name}Calls` | `SELECTORS`, `valid_selector()`, `abi_decode()`, `SolInterface` impl |
| `{Name}Error` | `SELECTORS`, `valid_selector()`, `selector()`, `SolInterface` impl, `From` impls |
| `{Name}Event` | `SELECTORS`, `IntoLogData` impl, `From` impls |

---

### 2026-01-14 — Phase 2 Complete

**Changes**:
- `utils.rs`: Added `to_pascal_case()` function for module name → interface alias conversion (preserves SCREAMING_SNAKE_CASE)
- `lib.rs`: Added `SolidityConfig` struct with `interface_alias` and `no_reexport` fields, parsing for `#[solidity(...)]` attributes
- `solidity/mod.rs`: Modified `expand()` to accept `SolidityConfig` and generate re-exports after module
- `tests/dummy_types.rs`: Added 5 tests for auto re-export functionality
- `tip20/types.rs`: Added `#[solidity(no_reexport)]` to existing modules to preserve backward compatibility during migration

**Implementation Details**:
- Default behavior: generates `pub use self::{module}::*` and `pub mod I{PascalCase} { pub use super::{module}::*; }`
- `interface_alias = "Name"`: customizes the interface alias module name
- `no_reexport`: disables all auto re-export generation
- Interface alias naming: `tip20` → `ITip20`, `roles_auth` → `IRolesAuth`
- SCREAMING_SNAKE_CASE module names are preserved (for Solidity constants)

**Migration Note**:
- TIP20 modules use `#[solidity(no_reexport)]` to avoid conflicts with existing manual re-exports
- Phase 4 will remove manual re-exports and enable auto re-exports

---

### 2026-01-14 — Phase 1 Complete

**Changes**:
- `common.rs`: Added `generate_dummy_error()`, `generate_dummy_event()`, `generate_dummy_calls()` functions
- `common.rs`: Added `generate_event_selectors()` and `Event::SELECTORS` to real Event containers
- `mod.rs`: Modified `expand()` to always generate Error, Event, and Calls (real or dummy)
- Added test file `tests/dummy_types.rs` with 8 tests covering all dummy type scenarios

**Implementation Details**:
- Dummy types implement full `SolInterface` trait with `abi_decode_raw` and `abi_decode_raw_validate`
- `valid_selector()` returns `false` for dummy types
- `abi_decode()` returns error with unknown selector message
- `SELECTORS` is empty for dummy types
- All existing tests continue to pass

**API for Generated Types**:
| Type | Required API |
|------|-------------|
| `Calls` | `SELECTORS: &[[u8; 4]]`, `valid_selector([u8;4]) -> bool`, `abi_decode(&[u8]) -> Result<Self>` |
| `Error` | `SELECTORS: &[[u8; 4]]`, `valid_selector([u8;4]) -> bool`, `selector(&self) -> [u8;4]` |
| `Event` | `SELECTORS: &[B256]` (topic0 hashes) |

---

### 2026-01-14 — Phase 1 Started

**Analysis complete**:
- `parser.rs` → `SolidityModule` IR with optional `error`, `event`, `interface`
- `enums.rs` → `generate_variant_enum()` for Error/Event
- `interface.rs` → `generate_calls_enum()` for Calls
- `mod.rs` → main expansion, conditionally generates based on `Option<T>`

**Approach**: Generate dummy enums in `mod.rs` when IR fields are `None`

---

<!-- 
Template for new entries:

### YYYY-MM-DD — Phase N: Brief Description

**Changes**:
- file.rs: description of change

**Decisions**:
- Any design decisions made during implementation

**Next**:
- What to do next
-->
