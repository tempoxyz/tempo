//! [TIP-1180] payment call registry precompile. Enabled at `TempoHardfork::T17`.
//!
//! Governance registers templates: a contract's runtime code hash with its immutable byte ranges
//! zeroed, and the selectors whose calls count as payments, each with an exact calldata length
//! and a gas cap. Anyone may register an instance of a template, a deployed contract whose masked
//! code hashes to the template's hash. Block execution, the payload builder and the pool classify
//! calls to active instances as registered payment calls ([`PaymentCallRegistry::classify`]).
//!
//! Every change that affects classification takes effect at a later block: template activation
//! and removal and instance removal at the next block, instance registration one epoch later.
//! Reading the registry anywhere inside a block therefore gives the same answer as reading it at
//! the parent block's state.
//!
//! [TIP-1180]: <https://docs.tempo.xyz/protocol/tips/tip-1180>

pub mod dispatch;

use crate::{
    error::Result,
    storage::{Handler, Mapping},
    validator_config::ValidatorConfig,
    validator_config_v2::ValidatorConfigV2,
};
use alloy::{
    consensus::Transaction,
    primitives::{Address, B256, FixedBytes},
};
pub use tempo_contracts::precompiles::{
    IPaymentCallRegistry, PAYMENT_CALL_REGISTRY_ADDRESS, PaymentCallRegistryError,
    PaymentCallRegistryEvent,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::TempoTxEnvelope;

/// Seconds between a template's proposal and the earliest block that may activate it.
pub const TEMPLATE_TIMELOCK: u64 = 7 * 24 * 60 * 60;

/// Largest template code, in bytes.
pub const MAX_TEMPLATE_CODE_SIZE: usize = 0x10000;

/// Most masked ranges a template may declare.
pub const MAX_CODE_RANGES: usize = 64;

/// Most payment selectors a template may declare.
pub const MAX_PAYMENT_SELECTORS: usize = 32;

/// Most static arguments a payment selector may take.
pub const MAX_STATIC_ARGUMENTS: u32 = 32;

/// Gas charged per 32-byte word of instance code read by [`PaymentCallRegistry::register_instance`],
/// as `EXTCODECOPY` charges.
const CODE_COPY_WORD_GAS: u64 = 3;

/// The opcode a template's code may not contain.
const SELFDESTRUCT: u8 = 0xff;

/// First byte of EOF containers and EIP-7702 delegation designators.
const EF_PREFIX: u8 = 0xef;

/// Registry-wide counters, packed into one slot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
struct RegistryState {
    /// Bumped by every change, so caches keyed by it see each one.
    version: u64,
    /// Number of templates ever proposed. Template ids run from 1 to this count.
    template_count: u64,
}

/// Delay overrides for development and test chains, set only in genesis state. Zero keeps the
/// protocol delay. Nothing writes this slot after genesis.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub struct DelayOverrides {
    /// Replaces [`TEMPLATE_TIMELOCK`] (seconds) when non-zero.
    pub template_timelock: u64,
    /// Replaces the one-epoch instance activation delay (blocks) when non-zero.
    pub instance_activation_delay: u64,
}

/// A template's lifecycle fields, packed into one slot so classification reads it once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
struct TemplateStatus {
    code_length: u32,
    /// Block timestamp of the proposal.
    proposed_at: u64,
    /// First block the template classifies in; zero until activated.
    activation_block: u64,
    /// First block the template no longer classifies in; zero unless removed.
    removed_at_block: u64,
}

/// A masked byte range of a template's code.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
struct CodeRangeRecord {
    offset: u32,
    length: u32,
}

/// What a payment selector of a template requires of a call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
struct SelectorRule {
    /// Exact calldata length, selector included.
    calldata_length: u32,
    /// Zero for a selector the template does not list.
    gas_cap: u64,
}

/// A template, keyed by its id.
#[derive(Debug, Clone, Default, Storable)]
struct TemplateRecord {
    masked_code_hash: B256,
    status: TemplateStatus,
    ranges: Vec<CodeRangeRecord>,
    /// The listed selectors, in proposal order, for views.
    selectors: Vec<FixedBytes<4>>,
    #[allow(dead_code, reason = "read through the generated storage handler")]
    rules: Mapping<FixedBytes<4>, SelectorRule>,
}

/// A registered instance, packed into one slot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
struct InstanceRecord {
    /// Zero for an address that was never registered.
    template_id: u64,
    activation_block: u64,
    removed_at_block: u64,
}

/// [TIP-1180] payment call registry.
///
/// [TIP-1180]: <https://docs.tempo.xyz/protocol/tips/tip-1180>
#[contract(addr = PAYMENT_CALL_REGISTRY_ADDRESS)]
pub struct PaymentCallRegistry {
    state: RegistryState,
    delay_overrides: DelayOverrides,
    templates: Mapping<u64, TemplateRecord>,
    instances: Mapping<Address, InstanceRecord>,
}

/// What the registry says about one call at a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentCallMatch {
    /// The call's gas cap if it is a registered payment call at the block.
    pub gas_cap: Option<u64>,
    /// The first later block at which the answer may change without a registry change (a
    /// pending activation or removal), or [`u64::MAX`].
    pub changes_at: u64,
}

impl PaymentCallMatch {
    const NONE: Self = Self {
        gas_cap: None,
        changes_at: u64::MAX,
    };
}

/// Classification of a transaction against the registry at a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredClassification {
    /// Whether the transaction is a registered payment: it meets TIP-1045's transaction-level
    /// rules, every call is a registered payment call, and its gas limit is at most the sum of
    /// their gas caps.
    pub is_registered_payment: bool,
    /// The first later block at which the answer may change without a registry change, or
    /// [`u64::MAX`].
    pub changes_at: u64,
}

/// Returns whether a lifecycle window `[activation, removed)` covers `block`. A zero activation
/// never covers; a zero removal never ends.
fn covers(activation_block: u64, removed_at_block: u64, block: u64) -> bool {
    activation_block != 0
        && activation_block <= block
        && (removed_at_block == 0 || block < removed_at_block)
}

/// Returns the first boundary of the window after `block`, or [`u64::MAX`].
fn next_boundary(activation_block: u64, removed_at_block: u64, block: u64) -> u64 {
    [activation_block, removed_at_block]
        .into_iter()
        .filter(|&boundary| boundary > block)
        .min()
        .unwrap_or(u64::MAX)
}

/// Scans `code` as EVM bytecode and returns which bytes are PUSH immediate data.
///
/// # Errors
/// - `InvalidCode`: empty, larger than [`MAX_TEMPLATE_CODE_SIZE`], or starting with `0xEF`
/// - `ForbiddenOpcode`: a `SELFDESTRUCT` opcode outside PUSH data
pub fn scan_code(code: &[u8]) -> Result<Vec<bool>> {
    if code.is_empty() || code.len() > MAX_TEMPLATE_CODE_SIZE || code[0] == EF_PREFIX {
        return Err(PaymentCallRegistryError::invalid_code().into());
    }
    let mut push_data = vec![false; code.len()];
    let mut pc = 0;
    while pc < code.len() {
        let opcode = code[pc];
        if opcode == SELFDESTRUCT {
            return Err(PaymentCallRegistryError::forbidden_opcode(pc as u32, opcode).into());
        }
        if (0x60..=0x7f).contains(&opcode) {
            let end = (pc + 1 + usize::from(opcode - 0x5f)).min(code.len());
            push_data[pc + 1..end].fill(true);
            pc = end;
        } else {
            pc += 1;
        }
    }
    Ok(push_data)
}

/// Checks that `ranges` are non-empty, ascending, disjoint, at most [`MAX_CODE_RANGES`], and
/// lie inside PUSH immediate data of the scanned code.
///
/// # Errors
/// - `InvalidCodeRange` naming the first range that fails
pub fn validate_ranges(
    push_data: &[bool],
    ranges: &[IPaymentCallRegistry::CodeRange],
) -> Result<()> {
    let mut previous_end = 0usize;
    for (index, range) in ranges.iter().enumerate() {
        let invalid = || PaymentCallRegistryError::invalid_code_range(range.offset, range.length);
        let start = range.offset as usize;
        let end = start + range.length as usize;
        if index >= MAX_CODE_RANGES
            || range.length == 0
            || (index > 0 && start < previous_end)
            || end > push_data.len()
            || !push_data[start..end].iter().all(|&data| data)
        {
            return Err(invalid().into());
        }
        previous_end = end;
    }
    Ok(())
}

/// Returns `code` with every range zeroed. Ranges must be in bounds.
fn mask(code: &[u8], ranges: impl IntoIterator<Item = (u32, u32)>) -> Vec<u8> {
    let mut masked = code.to_vec();
    for (offset, length) in ranges {
        masked[offset as usize..(offset + length) as usize].fill(0);
    }
    masked
}

impl PaymentCallRegistry {
    /// Initializes the registry by setting its bytecode marker.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    // ────────────────── Governance ──────────────────

    /// Returns the governance address: the ValidatorConfigV2 owner, or the ValidatorConfig owner
    /// while V2 has none.
    pub fn governance(&self) -> Result<Address> {
        let owner = ValidatorConfigV2::new().owner()?;
        if !owner.is_zero() {
            return Ok(owner);
        }
        ValidatorConfig::new().owner()
    }

    fn require_governance(&self, sender: Address) -> Result<()> {
        let governance = self.governance()?;
        if governance.is_zero() || governance != sender {
            return Err(PaymentCallRegistryError::unauthorized().into());
        }
        Ok(())
    }

    /// Proposes a template from its runtime `code`; [`Self::activate_template`] may activate it
    /// [`Self::template_timelock`] seconds later.
    ///
    /// # Errors
    /// - `Unauthorized`: `sender` is not governance
    /// - `InvalidCode`, `ForbiddenOpcode`, `InvalidCodeRange`: see [`scan_code`] and
    ///   [`validate_ranges`]
    /// - `InvalidPaymentSelector`: no selectors, too many, a duplicate, a calldata length other
    ///   than 4 plus 32 per argument (up to [`MAX_STATIC_ARGUMENTS`]), or a gas cap of zero or
    ///   above the transaction gas limit cap
    pub fn propose_template(
        &mut self,
        sender: Address,
        call: IPaymentCallRegistry::proposeTemplateCall,
    ) -> Result<u64> {
        self.require_governance(sender)?;
        let push_data = scan_code(&call.code)?;
        validate_ranges(&push_data, &call.ranges)?;
        self.validate_selectors(&call.selectors)?;

        let masked = mask(
            &call.code,
            call.ranges.iter().map(|range| (range.offset, range.length)),
        );
        let masked_code_hash = self.storage.keccak256(&masked)?;
        let now = self.storage.timestamp().saturating_to::<u64>();

        let mut state = self.state.read()?;
        let template_id = state.template_count + 1;
        let template = &mut self.templates[template_id];
        template.masked_code_hash.write(masked_code_hash)?;
        template.status.write(TemplateStatus {
            code_length: call.code.len() as u32,
            proposed_at: now,
            activation_block: 0,
            removed_at_block: 0,
        })?;
        template.ranges.write(
            call.ranges
                .iter()
                .map(|range| CodeRangeRecord {
                    offset: range.offset,
                    length: range.length,
                })
                .collect(),
        )?;
        template
            .selectors
            .write(call.selectors.iter().map(|s| s.selector).collect())?;
        for selector in &call.selectors {
            template.rules[selector.selector].write(SelectorRule {
                calldata_length: selector.calldataLength,
                gas_cap: selector.gasCap,
            })?;
        }

        state.template_count = template_id;
        state.version += 1;
        self.state.write(state)?;

        let activatable_at = now.saturating_add(self.template_timelock()?);
        self.emit_event(PaymentCallRegistryEvent::template_proposed(
            template_id,
            masked_code_hash,
            activatable_at,
        ))?;
        Ok(template_id)
    }

    fn validate_selectors(
        &self,
        selectors: &[IPaymentCallRegistry::PaymentSelector],
    ) -> Result<()> {
        if selectors.is_empty() {
            return Err(
                PaymentCallRegistryError::invalid_payment_selector(FixedBytes::ZERO).into(),
            );
        }
        let gas_cap_limit = self.storage.spec().tx_gas_limit_cap().unwrap_or(u64::MAX);
        for (index, selector) in selectors.iter().enumerate() {
            let arguments_length = selector.calldataLength.checked_sub(4);
            let invalid = index >= MAX_PAYMENT_SELECTORS
                || selectors[..index]
                    .iter()
                    .any(|earlier| earlier.selector == selector.selector)
                || arguments_length
                    .is_none_or(|length| length % 32 != 0 || length / 32 > MAX_STATIC_ARGUMENTS)
                || selector.gasCap == 0
                || selector.gasCap > gas_cap_limit;
            if invalid {
                return Err(
                    PaymentCallRegistryError::invalid_payment_selector(selector.selector).into(),
                );
            }
        }
        Ok(())
    }

    /// Activates a proposed template from the next block, once its timelock has passed.
    ///
    /// # Errors
    /// - `Unauthorized`, `UnknownTemplate`, `TemplateRemovedAlready`, `TemplateAlreadyActivated`
    /// - `TimelockNotElapsed`: the block timestamp is before the proposal plus the timelock
    pub fn activate_template(&mut self, sender: Address, template_id: u64) -> Result<()> {
        self.require_governance(sender)?;
        let mut status = self.template_status(template_id)?;
        if status.removed_at_block != 0 {
            return Err(PaymentCallRegistryError::template_removed_already(template_id).into());
        }
        if status.activation_block != 0 {
            return Err(PaymentCallRegistryError::template_already_activated(template_id).into());
        }
        let activatable_at = status.proposed_at.saturating_add(self.template_timelock()?);
        if self.storage.timestamp().saturating_to::<u64>() < activatable_at {
            return Err(PaymentCallRegistryError::timelock_not_elapsed(activatable_at).into());
        }
        status.activation_block = self.storage.block_number() + 1;
        self.templates[template_id].status.write(status)?;
        self.bump_version()?;
        self.emit_event(PaymentCallRegistryEvent::template_activated(
            template_id,
            status.activation_block,
        ))
    }

    /// Removes a template from the next block. Its instances stop classifying with it.
    ///
    /// # Errors
    /// - `Unauthorized`, `UnknownTemplate`, `TemplateRemovedAlready`
    pub fn remove_template(&mut self, sender: Address, template_id: u64) -> Result<()> {
        self.require_governance(sender)?;
        let mut status = self.template_status(template_id)?;
        if status.removed_at_block != 0 {
            return Err(PaymentCallRegistryError::template_removed_already(template_id).into());
        }
        status.removed_at_block = self.storage.block_number() + 1;
        self.templates[template_id].status.write(status)?;
        self.bump_version()?;
        self.emit_event(PaymentCallRegistryEvent::template_removed(
            template_id,
            status.removed_at_block,
        ))
    }

    /// Removes an instance from the next block. A removed instance cannot register again.
    ///
    /// # Errors
    /// - `Unauthorized`, `UnknownInstance`, `InstanceRemovedAlready`
    pub fn remove_instance(&mut self, sender: Address, instance: Address) -> Result<()> {
        self.require_governance(sender)?;
        let mut record = self.instances[instance].read()?;
        if record.template_id == 0 {
            return Err(PaymentCallRegistryError::unknown_instance(instance).into());
        }
        if record.removed_at_block != 0 {
            return Err(PaymentCallRegistryError::instance_removed_already(instance).into());
        }
        record.removed_at_block = self.storage.block_number() + 1;
        self.instances[instance].write(record)?;
        self.bump_version()?;
        self.emit_event(PaymentCallRegistryEvent::instance_removed(
            instance,
            record.removed_at_block,
        ))
    }

    // ────────────────── Registration ──────────────────

    /// Registers `instance` under the first template, not removed, whose masked code hash its
    /// masked runtime code matches. It classifies from [`Self::instance_activation_delay`]
    /// blocks after the current one. Anyone may call it.
    ///
    /// # Errors
    /// - `InstanceAlreadyRegistered`, `InstanceRemovedAlready`
    /// - `NoMatchingTemplate`: no template's masked hash matches
    pub fn register_instance(&mut self, instance: Address) -> Result<u64> {
        let record = self.instances[instance].read()?;
        if record.template_id != 0 {
            return Err(if record.removed_at_block != 0 {
                PaymentCallRegistryError::instance_removed_already(instance)
            } else {
                PaymentCallRegistryError::instance_already_registered(instance)
            }
            .into());
        }

        let code = self
            .storage
            .with_account_code(instance, |code| Ok(code.to_vec()))?;
        self.storage
            .deduct_gas(CODE_COPY_WORD_GAS * code.len().div_ceil(32) as u64)?;
        if code.is_empty() || code[0] == EF_PREFIX {
            return Err(PaymentCallRegistryError::no_matching_template(instance).into());
        }

        let template_count = self.state.template_count.read()?;
        let mut matched = None;
        for template_id in 1..=template_count {
            let status = self.templates[template_id].status.read()?;
            if status.removed_at_block != 0 || status.code_length as usize != code.len() {
                continue;
            }
            let ranges = self.templates[template_id].ranges.read()?;
            let masked = mask(
                &code,
                ranges.iter().map(|range| (range.offset, range.length)),
            );
            if self.storage.keccak256(&masked)?
                == self.templates[template_id].masked_code_hash.read()?
            {
                matched = Some(template_id);
                break;
            }
        }
        let template_id =
            matched.ok_or_else(|| PaymentCallRegistryError::no_matching_template(instance))?;

        let activation_block = self
            .storage
            .block_number()
            .saturating_add(self.instance_activation_delay()?);
        self.instances[instance].write(InstanceRecord {
            template_id,
            activation_block,
            removed_at_block: 0,
        })?;
        self.bump_version()?;
        self.emit_event(PaymentCallRegistryEvent::instance_registered(
            instance,
            template_id,
            activation_block,
        ))?;
        Ok(template_id)
    }

    // ────────────────── Views ──────────────────

    /// Returns the registry version, bumped by every change.
    pub fn version(&self) -> Result<u64> {
        self.state.version.read()
    }

    /// Returns the number of templates ever proposed.
    pub fn template_count(&self) -> Result<u64> {
        self.state.template_count.read()
    }

    /// Returns the template timelock in seconds: [`TEMPLATE_TIMELOCK`] unless genesis overrides it.
    pub fn template_timelock(&self) -> Result<u64> {
        let timelock = self.delay_overrides.template_timelock.read()?;
        Ok(if timelock == 0 {
            TEMPLATE_TIMELOCK
        } else {
            timelock
        })
    }

    /// Returns the instance activation delay in blocks: one epoch unless genesis overrides it.
    pub fn instance_activation_delay(&self) -> Result<u64> {
        let delay = self.delay_overrides.instance_activation_delay.read()?;
        Ok(if delay == 0 {
            self.storage
                .with_block_env(|env| env.ext.epoch_length.get())
        } else {
            delay
        })
    }

    /// Returns a template.
    ///
    /// # Errors
    /// - `UnknownTemplate`
    pub fn get_template(&self, template_id: u64) -> Result<IPaymentCallRegistry::Template> {
        let status = self.template_status(template_id)?;
        let template = &self.templates[template_id];
        let selectors = template
            .selectors
            .read()?
            .into_iter()
            .map(|selector| {
                let rule = template.rules[selector].read()?;
                Ok(IPaymentCallRegistry::PaymentSelector {
                    selector,
                    calldataLength: rule.calldata_length,
                    gasCap: rule.gas_cap,
                })
            })
            .collect::<Result<_>>()?;
        Ok(IPaymentCallRegistry::Template {
            maskedCodeHash: template.masked_code_hash.read()?,
            codeLength: status.code_length,
            proposedAt: status.proposed_at,
            activationBlock: status.activation_block,
            removedAtBlock: status.removed_at_block,
            ranges: template
                .ranges
                .read()?
                .into_iter()
                .map(|range| IPaymentCallRegistry::CodeRange {
                    offset: range.offset,
                    length: range.length,
                })
                .collect(),
            selectors,
        })
    }

    /// Returns an instance's record; all zero for an unregistered address.
    pub fn get_instance(&self, instance: Address) -> Result<IPaymentCallRegistry::Instance> {
        let record = self.instances[instance].read()?;
        Ok(IPaymentCallRegistry::Instance {
            templateId: record.template_id,
            activationBlock: record.activation_block,
            removedAtBlock: record.removed_at_block,
        })
    }

    /// Returns the masked code hash of `code` with `ranges` zeroed, after the checks
    /// [`Self::propose_template`] applies to code and ranges.
    pub fn masked_code_hash(
        &self,
        code: &[u8],
        ranges: &[IPaymentCallRegistry::CodeRange],
    ) -> Result<B256> {
        let push_data = scan_code(code)?;
        validate_ranges(&push_data, ranges)?;
        self.storage.keccak256(&mask(
            code,
            ranges.iter().map(|range| (range.offset, range.length)),
        ))
    }

    fn template_status(&self, template_id: u64) -> Result<TemplateStatus> {
        if template_id == 0 || template_id > self.state.template_count.read()? {
            return Err(PaymentCallRegistryError::unknown_template(template_id).into());
        }
        self.templates[template_id].status.read()
    }

    fn bump_version(&mut self) -> Result<()> {
        let mut state = self.state.read()?;
        state.version += 1;
        self.state.write(state)
    }

    // ────────────────── Classification ──────────────────

    /// Looks up a call to `target` with `input` at `block`.
    pub fn lookup_payment_call(
        &self,
        target: Address,
        input: &[u8],
        block: u64,
    ) -> Result<PaymentCallMatch> {
        let Some(selector) = input.first_chunk::<4>() else {
            return Ok(PaymentCallMatch::NONE);
        };
        let instance = self.instances[target].read()?;
        if instance.template_id == 0 {
            return Ok(PaymentCallMatch::NONE);
        }
        let template = &self.templates[instance.template_id];
        let rule = template.rules[FixedBytes(*selector)].read()?;
        if rule.gas_cap == 0 || rule.calldata_length as usize != input.len() {
            return Ok(PaymentCallMatch::NONE);
        }
        let status = template.status.read()?;
        let effective = covers(instance.activation_block, instance.removed_at_block, block)
            && covers(status.activation_block, status.removed_at_block, block);
        Ok(PaymentCallMatch {
            gas_cap: effective.then_some(rule.gas_cap),
            changes_at: next_boundary(instance.activation_block, instance.removed_at_block, block)
                .min(next_boundary(
                    status.activation_block,
                    status.removed_at_block,
                    block,
                )),
        })
    }

    /// Returns the gas cap of a call to `target` with `input` if it is a registered payment call
    /// at the current block, else zero.
    pub fn payment_call_gas_cap(&self, target: Address, input: &[u8]) -> Result<u64> {
        let block = self.storage.block_number();
        Ok(self
            .lookup_payment_call(target, input, block)?
            .gas_cap
            .unwrap_or_default())
    }

    /// Classifies `tx` for `block`: a registered payment meets TIP-1045's transaction-level rules,
    /// every call is a registered payment call, and its gas limit is at most the sum of their gas
    /// caps. A transaction mixing registered calls with TIP-1045 payment calls is not one.
    pub fn classify(&self, tx: &TempoTxEnvelope, block: u64) -> Result<RegisteredClassification> {
        let mut gas_caps = 0u64;
        let mut changes_at = u64::MAX;
        let mut error = None;
        let all_registered = tx.is_payment_with(|target, input| {
            let Some(target) = target else {
                return false;
            };
            match self.lookup_payment_call(*target, input, block) {
                Ok(found) => {
                    changes_at = changes_at.min(found.changes_at);
                    found.gas_cap.is_some_and(|cap| {
                        gas_caps = gas_caps.saturating_add(cap);
                        true
                    })
                }
                Err(err) => {
                    error = Some(err);
                    false
                }
            }
        });
        if let Some(error) = error {
            return Err(error);
        }
        Ok(RegisteredClassification {
            is_registered_payment: all_registered && tx.gas_limit() <= gas_caps,
            changes_at,
        })
    }
}

#[cfg(test)]
mod tests;
