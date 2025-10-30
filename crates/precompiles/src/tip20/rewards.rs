use crate::{
    error::TempoPrecompileError,
    storage::{PrecompileStorageProvider, slots::mapping_slot},
    tip20::TIP20Token,
    tip20_rewards_registry::TIP20RewardsRegistry,
};
use alloy::primitives::{Address, IntoLogData, U256, uint};
use revm::interpreter::instructions::utility::{IntoAddress, IntoU256};
use tempo_contracts::precompiles::{ITIP20, TIP20Error, TIP20Event};

pub const ACC_PRECISION: U256 = uint!(1000000000000000000_U256);

pub mod slots {
    use alloy::primitives::{U256, uint};

    // Rewards related slots
    pub const LAST_UPDATE_TIME: U256 = uint!(16_U256);
    pub const OPTED_IN_SUPPLY: U256 = uint!(17_U256);
    pub const NEXT_STREAM_ID: U256 = uint!(18_U256);
    pub const STREAMS: U256 = uint!(19_U256);
    pub const SCHEDULED_RATE_DECREASE: U256 = uint!(20_U256);
    pub const REWARD_RECIPIENT_OF: U256 = uint!(21_U256);
    pub const USER_REWARD_PER_TOKEN_PAID: U256 = uint!(22_U256);
    pub const DELEGATED_BALANCE: U256 = uint!(23_U256);
    pub const REWARD_PER_TOKEN_STORED: U256 = uint!(24_U256);
    pub const TOTAL_REWARD_PER_SECOND: U256 = uint!(25_U256);
}

impl<'a, S: PrecompileStorageProvider> TIP20Token<'a, S> {
    // TIP20 extension functions
    pub fn start_reward(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::startRewardCall,
    ) -> Result<u64, TempoPrecompileError> {
        self.check_not_paused()?;
        let token_address = self.token_address;
        self.ensure_transfer_authorized(msg_sender, &token_address)?;

        if call.amount == U256::ZERO {
            return Err(TIP20Error::invalid_amount().into());
        }

        let from_balance = self.get_balance(msg_sender)?;
        let new_from_balance = from_balance
            .checked_sub(call.amount)
            // TODO: update this to overflow error
            .ok_or(TIP20Error::insufficient_balance())?;
        self.set_balance(msg_sender, new_from_balance)?;

        let contract_address = self.token_address;
        let to_balance = self.get_balance(&contract_address)?;
        let new_to_balance = to_balance
            .checked_add(call.amount)
            // TODO: update this to overflow error
            .ok_or(TIP20Error::supply_cap_exceeded())?;
        self.set_balance(&contract_address, new_to_balance)?;

        self.accrue()?;

        if call.seconds == 0 {
            let opted_in_supply = self.get_opted_in_supply()?;
            if opted_in_supply.is_zero() {
                return Err(TIP20Error::no_reward_supplied().into());
            }

            let delta_rpt = (call.amount * ACC_PRECISION) / opted_in_supply;
            let current_rpt = self.get_reward_per_token_stored()?;
            self.set_reward_per_token_stored(current_rpt + delta_rpt)?;

            // Emit reward scheduled event for immediate payout
            self.storage.emit_event(
                self.token_address,
                TIP20Event::RewardScheduled(ITIP20::RewardScheduled {
                    funder: *msg_sender,
                    id: 0,
                    amount: call.amount,
                    durationSeconds: 0,
                })
                .into_log_data(),
            )?;

            Ok(0)
        } else {
            let rate = (call.amount * ACC_PRECISION) / U256::from(call.seconds);
            let stream_id = self.get_next_stream_id()?;
            self.set_next_stream_id(stream_id + 1)?;

            let current_total = self.get_total_reward_per_second()?;
            self.set_total_reward_per_second(current_total + rate)?;

            let current_time = self.storage.timestamp().to::<u128>();
            let end_time = current_time + call.seconds;

            RewardStream::new(
                stream_id,
                *msg_sender,
                current_time as u64,
                end_time as u64,
                rate,
                call.amount,
            )
            .store(self.storage, self.token_address)?;

            let current_decrease = self.get_scheduled_rate_decrease_at(end_time);
            self.set_scheduled_rate_decrease_at(end_time, current_decrease + rate)?;

            // Add stream to registry
            let mut registry = TIP20RewardsRegistry::new(self.storage);
            registry.add_stream(&self.token_address, end_time)?;

            // Emit reward scheduled event for streaming reward
            self.storage.emit_event(
                self.token_address,
                TIP20Event::RewardScheduled(ITIP20::RewardScheduled {
                    funder: *msg_sender,
                    id: stream_id,
                    amount: call.amount,
                    durationSeconds: call.seconds as u64,
                })
                .into_log_data(),
            )?;

            Ok(stream_id)
        }
    }

    pub fn handle_sender_rewards(
        &mut self,
        from: &Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        let from_recipient = self.get_reward_recipient_of(from)?;
        if from_recipient != Address::ZERO {
            self.update_rewards(&from_recipient)?;

            let delegated = self
                .get_delegated_balance(&from_recipient)?
                .checked_sub(amount)
                .expect("TODO: handle error");
            self.set_delegated_balance(&from_recipient, delegated)?;

            let opted_in = self
                .get_opted_in_supply()?
                .checked_sub(amount)
                .expect("TODO: handle error");
            self.set_opted_in_supply(opted_in)?;
        }
        Ok(())
    }

    pub fn handle_receiver_rewards(
        &mut self,
        to: &Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        let to_recipient = self.get_reward_recipient_of(to)?;
        if to_recipient != Address::ZERO {
            self.update_rewards(&to_recipient)?;

            let delegated = self
                .get_delegated_balance(&to_recipient)?
                .checked_add(amount)
                .expect("TODO: handle error");
            self.set_delegated_balance(&to_recipient, delegated)?;

            let opted_in = self
                .get_opted_in_supply()?
                .checked_add(amount)
                .expect("TODO: handle error");
            self.set_opted_in_supply(opted_in)?;
        }
        Ok(())
    }

    pub fn accrue(&mut self) -> Result<(), TempoPrecompileError> {
        let current_time = self.storage.timestamp();
        let last_update_time = U256::from(self.get_last_update_time()?);

        let elapsed = if current_time > last_update_time {
            current_time - last_update_time
        } else {
            return Ok(());
        };
        self.set_last_update_time(current_time)?;

        let opted_in_supply = self.get_opted_in_supply()?;
        if opted_in_supply == U256::ZERO {
            return Ok(());
        }

        let total_reward_per_second = self.get_total_reward_per_second()?;
        if total_reward_per_second > U256::ZERO {
            let delta_rpt = (total_reward_per_second * elapsed) / opted_in_supply;
            let current_rpt = self.get_reward_per_token_stored()?;
            self.set_reward_per_token_stored(current_rpt + delta_rpt)?;
        }

        Ok(())
    }

    fn update_rewards(&mut self, recipient: &Address) -> Result<(), TempoPrecompileError> {
        if *recipient == Address::ZERO {
            return Ok(());
        }

        let delegated = self.get_delegated_balance(recipient)?;
        let reward_per_token_stored = self.get_reward_per_token_stored()?;
        let user_reward_per_token_paid = self.get_user_reward_per_token_paid(recipient)?;

        let mut accrued =
            (delegated * (reward_per_token_stored - user_reward_per_token_paid)) / ACC_PRECISION;

        self.set_user_reward_per_token_paid(recipient, reward_per_token_stored)?;

        if accrued > U256::ZERO {
            let token_address = self.token_address;
            let contract_balance = self.get_balance(&token_address)?;

            if accrued > contract_balance {
                accrued = contract_balance;
            }

            let new_contract_balance = contract_balance - accrued;
            self.set_balance(&token_address, new_contract_balance)?;

            let recipient_balance = self.get_balance(recipient)?;
            let new_recipient_balance = recipient_balance + accrued;
            self.set_balance(recipient, new_recipient_balance)?;

            self.storage.emit_event(
                self.token_address,
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: token_address,
                    to: *recipient,
                    amount: accrued,
                })
                .into_log_data(),
            )?;
        }

        Ok(())
    }

    pub fn set_reward_recipient(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::setRewardRecipientCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_not_paused()?;
        if call.recipient != Address::ZERO {
            self.ensure_transfer_authorized(msg_sender, &call.recipient)?;
        }

        self.accrue()?;

        let current_recipient = self.get_reward_recipient_of(msg_sender)?;
        if call.recipient == current_recipient {
            return Ok(());
        }

        let balance = self.get_balance(msg_sender)?;
        if current_recipient != Address::ZERO {
            self.update_rewards(&current_recipient)?;
            let delegated = self
                .get_delegated_balance(&current_recipient)?
                .checked_sub(balance)
                .expect("TODO: handle error");
            self.set_delegated_balance(&current_recipient, delegated)?;
        }

        self.set_reward_recipient_of(msg_sender, call.recipient)?;
        if call.recipient == Address::ZERO {
            let opted_in_supply = self
                .get_opted_in_supply()?
                .checked_sub(balance)
                .expect("TODO: handle error");
            self.set_opted_in_supply(opted_in_supply)?;
        } else {
            let delegated = self.get_delegated_balance(&call.recipient)?;
            if delegated > U256::ZERO {
                self.update_rewards(&call.recipient)?;
            }

            let new_delegated = delegated.checked_add(balance).expect("TODO: handle error");
            self.set_delegated_balance(&call.recipient, new_delegated)?;

            if current_recipient.is_zero() {
                let opted_in = self
                    .get_opted_in_supply()?
                    .checked_add(balance)
                    .expect("TODO: handle error");
                self.set_opted_in_supply(opted_in)?;
            }

            let rpt = self.get_reward_per_token_stored()?;
            self.set_user_reward_per_token_paid(&call.recipient, rpt)?;
        }

        // Emit reward recipient set event
        self.storage.emit_event(
            self.token_address,
            TIP20Event::RewardRecipientSet(ITIP20::RewardRecipientSet {
                holder: *msg_sender,
                recipient: call.recipient,
            })
            .into_log_data(),
        )?;

        Ok(())
    }

    pub fn cancel_reward(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::cancelRewardCall,
    ) -> Result<U256, TempoPrecompileError> {
        let stream_id = call.id.to::<u64>();
        let stream = RewardStream::from_storage(stream_id, self.storage, self.token_address)?;

        let current_time = self.storage.timestamp();

        if stream.funder.is_zero() {
            return Err(TIP20Error::stream_inactive().into());
        }
        if stream.funder != *msg_sender {
            return Err(TIP20Error::not_stream_funder().into());
        }

        if current_time >= stream.end_time {
            return Err(TIP20Error::stream_inactive().into());
        }

        self.accrue()?;

        let elapsed = if current_time > U256::from(stream.start_time) {
            current_time - U256::from(stream.start_time)
        } else {
            U256::ZERO
        };

        let mut distributed = (stream.rate_per_second_scaled * elapsed) / ACC_PRECISION;
        distributed = distributed.min(stream.amount_total);
        let remaining = stream.amount_total - distributed;

        let total_rps = self
            .get_total_reward_per_second()?
            .checked_sub(stream.rate_per_second_scaled)
            .expect("TODO: handle error");
        self.set_total_reward_per_second(total_rps)?;

        // Update the rate decrease and remove the stream
        let end_time = stream.end_time as u128;
        let rate_decrease = self
            .get_scheduled_rate_decrease_at(end_time)
            .checked_sub(stream.rate_per_second_scaled)
            .expect("TODO: handle error");
        self.set_scheduled_rate_decrease_at(end_time, rate_decrease)?;

        stream.delete(self.storage, self.token_address)?;

        // Attempt to transfer remaining funds to funder
        let mut refund = U256::ZERO;
        if remaining > U256::ZERO {
            // Check if transfer is authorized
            if self.is_transfer_authorized(&stream.funder, &stream.funder)? {
                let contract_address = self.token_address;
                let contract_balance = self
                    .get_balance(&contract_address)?
                    .checked_sub(remaining)
                    .expect("TODO: handle error");
                self.set_balance(&contract_address, contract_balance)?;

                let funder_balance = self
                    .get_balance(&stream.funder)?
                    .checked_add(remaining)
                    .expect("TODO: handle error");
                self.set_balance(&stream.funder, funder_balance)?;

                self.storage.emit_event(
                    self.token_address,
                    TIP20Event::Transfer(ITIP20::Transfer {
                        from: self.token_address,
                        to: stream.funder,
                        amount: remaining,
                    })
                    .into_log_data(),
                )?;

                refund = remaining;
            }
        }

        // Emit reward canceled event
        self.storage.emit_event(
            self.token_address,
            TIP20Event::RewardCanceled(ITIP20::RewardCanceled {
                funder: stream.funder,
                id: stream_id,
                refund,
            })
            .into_log_data(),
        )?;

        Ok(refund)
    }

    pub fn finalize_streams(&mut self) -> Result<(), TempoPrecompileError> {
        let end_time = self.storage.timestamp().to::<u128>();
        let rate_decrease = self.get_scheduled_rate_decrease_at(end_time);

        if rate_decrease == U256::ZERO {
            return Ok(());
        }

        self.accrue()?;

        let total_rps = self
            .get_total_reward_per_second()?
            .checked_sub(rate_decrease)
            .expect("TODO: handle error");
        self.set_total_reward_per_second(total_rps)?;

        self.set_scheduled_rate_decrease_at(end_time, U256::ZERO)?;

        Ok(())
    }

    fn get_user_reward_per_token_paid(
        &mut self,
        account: &Address,
    ) -> Result<U256, TempoPrecompileError> {
        let slot = mapping_slot(account, slots::USER_REWARD_PER_TOKEN_PAID);
        self.storage.sload(self.token_address, slot)
    }

    fn set_user_reward_per_token_paid(
        &mut self,
        account: &Address,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        let slot = mapping_slot(account, slots::USER_REWARD_PER_TOKEN_PAID);
        self.storage.sstore(self.token_address, slot, value)
    }

    fn get_next_stream_id(&mut self) -> Result<u64, TempoPrecompileError> {
        let id = self
            .storage
            .sload(self.token_address, slots::NEXT_STREAM_ID)?
            .to::<u64>();

        Ok(id.max(1))
    }

    fn set_next_stream_id(&mut self, value: u64) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.token_address, slots::NEXT_STREAM_ID, U256::from(value))
    }

    fn get_reward_per_token_stored(&mut self) -> Result<U256, TempoPrecompileError> {
        self.storage
            .sload(self.token_address, slots::REWARD_PER_TOKEN_STORED)
    }

    fn set_reward_per_token_stored(&mut self, value: U256) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.token_address, slots::REWARD_PER_TOKEN_STORED, value)
    }

    fn get_last_update_time(&mut self) -> Result<u64, TempoPrecompileError> {
        Ok(self
            .storage
            .sload(self.token_address, slots::LAST_UPDATE_TIME)?
            .to::<u64>())
    }

    fn set_last_update_time(&mut self, value: U256) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.token_address, slots::LAST_UPDATE_TIME, value)
    }

    fn get_opted_in_supply(&mut self) -> Result<U256, TempoPrecompileError> {
        self.storage
            .sload(self.token_address, slots::OPTED_IN_SUPPLY)
    }

    fn set_opted_in_supply(&mut self, value: U256) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.token_address, slots::OPTED_IN_SUPPLY, value)
    }

    fn get_reward_recipient_of(
        &mut self,
        account: &Address,
    ) -> Result<Address, TempoPrecompileError> {
        let slot = mapping_slot(account, slots::REWARD_RECIPIENT_OF);
        Ok(self.storage.sload(self.token_address, slot)?.into_address())
    }

    fn set_reward_recipient_of(
        &mut self,
        account: &Address,
        recipient: Address,
    ) -> Result<(), TempoPrecompileError> {
        let slot = mapping_slot(account, slots::REWARD_RECIPIENT_OF);
        self.storage
            .sstore(self.token_address, slot, recipient.into_u256())
    }

    fn get_delegated_balance(&mut self, account: &Address) -> Result<U256, TempoPrecompileError> {
        let slot = mapping_slot(account, slots::DELEGATED_BALANCE);
        self.storage.sload(self.token_address, slot)
    }

    fn set_delegated_balance(
        &mut self,
        account: &Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        let slot = mapping_slot(account, slots::DELEGATED_BALANCE);
        self.storage.sstore(self.token_address, slot, amount)
    }

    fn get_scheduled_rate_decrease_at(&mut self, end_time: u128) -> U256 {
        let slot = mapping_slot(end_time.to_be_bytes(), slots::SCHEDULED_RATE_DECREASE);
        self.storage
            .sload(self.token_address, slot)
            .unwrap_or(U256::ZERO)
    }

    fn set_scheduled_rate_decrease_at(
        &mut self,
        end_time: u128,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        let slot = mapping_slot(end_time.to_be_bytes(), slots::SCHEDULED_RATE_DECREASE);
        self.storage.sstore(self.token_address, slot, value)
    }

    fn get_total_reward_per_second(&mut self) -> Result<U256, TempoPrecompileError> {
        self.storage
            .sload(self.token_address, slots::TOTAL_REWARD_PER_SECOND)
    }

    fn set_total_reward_per_second(&mut self, value: U256) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.token_address, slots::TOTAL_REWARD_PER_SECOND, value)
    }

    pub fn get_stream(&mut self, stream_id: u64) -> Result<RewardStream, TempoPrecompileError> {
        RewardStream::from_storage(stream_id, self.storage, self.token_address)
    }
}

#[derive(Debug, Clone)]
pub struct RewardStream {
    stream_id: u64,
    pub funder: Address,
    pub start_time: u64,
    pub end_time: u64,
    pub rate_per_second_scaled: U256,
    pub amount_total: U256,
}

impl RewardStream {
    pub const STREAM_FUNDER_OFFSET: U256 = uint!(0_U256);
    pub const STREAM_START_TIME_OFFSET: U256 = uint!(1_U256);
    pub const STREAM_END_TIME_OFFSET: U256 = uint!(2_U256);
    pub const STREAM_RATE_OFFSET: U256 = uint!(3_U256);
    pub const STREAM_AMOUNT_TOTAL_OFFSET: U256 = uint!(4_U256);

    pub fn new(
        stream_id: u64,
        funder: Address,
        start_time: u64,
        end_time: u64,
        rate_per_second_scaled: U256,
        amount_total: U256,
    ) -> Self {
        Self {
            stream_id,
            funder,
            start_time,
            end_time,
            rate_per_second_scaled,
            amount_total,
        }
    }

    pub fn from_storage<S: PrecompileStorageProvider>(
        stream_id: u64,
        storage: &mut S,
        token_address: Address,
    ) -> Result<Self, TempoPrecompileError> {
        let key = stream_id.to_be_bytes();

        let funder = storage
            .sload(
                token_address,
                mapping_slot(key, slots::STREAMS + Self::STREAM_FUNDER_OFFSET),
            )?
            .into_address();

        let start_time = storage
            .sload(
                token_address,
                mapping_slot(key, slots::STREAMS + Self::STREAM_START_TIME_OFFSET),
            )?
            .to::<u64>();

        let end_time = storage
            .sload(
                token_address,
                mapping_slot(key, slots::STREAMS + Self::STREAM_END_TIME_OFFSET),
            )?
            .to::<u64>();

        let rate_per_second_scaled = storage.sload(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_RATE_OFFSET),
        )?;

        let amount_total = storage.sload(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_AMOUNT_TOTAL_OFFSET),
        )?;

        Ok(Self {
            stream_id,
            funder,
            start_time,
            end_time,
            rate_per_second_scaled,
            amount_total,
        })
    }

    pub fn store<S: PrecompileStorageProvider>(
        &self,
        storage: &mut S,
        token_address: Address,
    ) -> Result<(), TempoPrecompileError> {
        let key = self.stream_id.to_be_bytes();

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_FUNDER_OFFSET),
            self.funder.into_u256(),
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_START_TIME_OFFSET),
            U256::from(self.start_time),
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_END_TIME_OFFSET),
            U256::from(self.end_time),
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_RATE_OFFSET),
            self.rate_per_second_scaled,
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_AMOUNT_TOTAL_OFFSET),
            self.amount_total,
        )?;

        Ok(())
    }

    pub fn delete<S: PrecompileStorageProvider>(
        &self,
        storage: &mut S,
        token_address: Address,
    ) -> Result<(), TempoPrecompileError> {
        let key = self.stream_id.to_be_bytes();

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_FUNDER_OFFSET),
            U256::ZERO,
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_START_TIME_OFFSET),
            U256::ZERO,
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_END_TIME_OFFSET),
            U256::ZERO,
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_RATE_OFFSET),
            U256::ZERO,
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_AMOUNT_TOTAL_OFFSET),
            U256::ZERO,
        )?;

        Ok(())
    }
}

impl From<RewardStream> for ITIP20::RewardStream {
    fn from(value: RewardStream) -> Self {
        Self {
            funder: value.funder,
            startTime: value.start_time,
            endTime: value.end_time,
            ratePerSecondScaled: value.rate_per_second_scaled,
            amountTotal: value.amount_total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LINKING_USD_ADDRESS, storage::hashmap::HashMapStorageProvider, tip20::ISSUER_ROLE,
    };
    use alloy::primitives::{Address, U256};

    #[test]
    fn test_start_reward() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let current_time = storage.timestamp().to::<u64>();
        let admin = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: mint_amount,
            },
        )?;

        let reward_amount = U256::from(100e18);
        let stream_id = token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: 10,
            },
        )?;
        assert_eq!(stream_id, 1);

        let token_address = token.token_address;
        let balance = token.get_balance(&token_address)?;
        assert_eq!(balance, reward_amount);

        let stream = token.get_stream(stream_id)?;
        assert_eq!(stream.funder, admin);
        assert_eq!(stream.start_time, current_time);
        assert_eq!(stream.end_time, current_time + 10);

        let total_reward_per_second = token.get_total_reward_per_second()?;
        let expected_rate = (reward_amount * ACC_PRECISION) / U256::from(10);
        assert_eq!(total_reward_per_second, expected_rate);

        let reward_per_token_stored = token.get_reward_per_token_stored()?;
        assert_eq!(reward_per_token_stored, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_set_reward_recipient() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        let amount = U256::from(1000e18);
        token.mint(&admin, ITIP20::mintCall { to: alice, amount })?;

        token.set_reward_recipient(&alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        assert_eq!(token.get_reward_recipient_of(&alice)?, alice);
        assert_eq!(token.get_delegated_balance(&alice)?, amount);
        assert_eq!(token.get_opted_in_supply()?, amount);
        assert_eq!(token.get_user_reward_per_token_paid(&alice)?, U256::ZERO);

        token.set_reward_recipient(
            &alice,
            ITIP20::setRewardRecipientCall {
                recipient: Address::ZERO,
            },
        )?;

        assert_eq!(token.get_reward_recipient_of(&alice)?, Address::ZERO);
        assert_eq!(token.get_delegated_balance(&alice)?, U256::ZERO);
        assert_eq!(token.get_opted_in_supply()?, U256::ZERO);
        assert_eq!(token.get_user_reward_per_token_paid(&alice)?, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_cancel_reward() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: mint_amount,
            },
        )?;

        let reward_amount = U256::from(100e18);
        let stream_id = token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: 10,
            },
        )?;

        let remaining = token.cancel_reward(
            &admin,
            ITIP20::cancelRewardCall {
                id: U256::from(stream_id),
            },
        )?;

        let total_after = token.get_total_reward_per_second()?;
        assert_eq!(total_after, U256::ZERO);
        assert_eq!(remaining, reward_amount);

        let stream = token.get_stream(stream_id)?;
        assert!(stream.funder.is_zero());
        assert_eq!(stream.start_time, 0);
        assert_eq!(stream.end_time, 0);
        assert_eq!(stream.rate_per_second_scaled, U256::ZERO);

        let reward_per_token_stored = token.get_reward_per_token_stored()?;
        assert_eq!(reward_per_token_stored, U256::ZERO);

        let opted_in_supply = token.get_opted_in_supply()?;
        assert_eq!(opted_in_supply, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_update_rewards() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(&alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        let reward_amount = U256::from(100e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        // Distribute the reward immediately
        token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: 0,
            },
        )?;

        let alice_balance_before = token.get_balance(&alice)?;
        let reward_per_token_before = token.get_reward_per_token_stored()?;
        let _user_reward_per_token_paid_before = token.get_user_reward_per_token_paid(&alice)?;

        token.update_rewards(&alice)?;

        let alice_balance_after = token.get_balance(&alice)?;
        let reward_per_token_after = token.get_reward_per_token_stored()?;
        let user_reward_per_token_paid_after = token.get_user_reward_per_token_paid(&alice)?;

        assert!(alice_balance_after > alice_balance_before);
        assert!(reward_per_token_after >= reward_per_token_before);
        assert_eq!(user_reward_per_token_paid_after, reward_per_token_after);
        assert_eq!(token.get_opted_in_supply()?, mint_amount);
        assert_eq!(token.get_delegated_balance(&alice)?, mint_amount);

        Ok(())
    }

    #[test]
    fn test_accrue() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(&alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        let reward_amount = U256::from(100e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: 100,
            },
        )?;

        let rpt_before = token.get_reward_per_token_stored()?;
        let last_update_before = token.get_last_update_time()?;

        token.accrue()?;

        let rpt_after = token.get_reward_per_token_stored()?;
        let last_update_after = token.get_last_update_time()?;

        assert!(rpt_after >= rpt_before);
        assert!(last_update_after >= last_update_before);

        // Check total reward per second remains consistent
        let total_reward_per_second = token.get_total_reward_per_second()?;
        let expected_rate = (reward_amount * ACC_PRECISION) / U256::from(100);
        assert_eq!(total_reward_per_second, expected_rate);

        assert_eq!(token.get_opted_in_supply()?, mint_amount);
        assert_eq!(token.get_delegated_balance(&alice)?, mint_amount);
        assert_eq!(token.get_user_reward_per_token_paid(&alice)?, U256::ZERO);
        Ok(())
    }

    #[test]
    fn test_finalize_streams() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let current_time = storage.timestamp().to::<u128>();
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(&alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        let reward_amount = U256::from(100e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        let stream_duration = 10u128;
        token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: stream_duration,
            },
        )?;

        let end_time = current_time + stream_duration;

        // Advance the timestamp to simulate time passing
        token.storage.set_timestamp(U256::from(end_time));

        let total_before = token.get_total_reward_per_second()?;
        token.finalize_streams()?;
        let total_after = token.get_total_reward_per_second()?;

        assert!(total_after < total_before);

        // Check reward per token stored has been updated
        let reward_per_token_stored = token.get_reward_per_token_stored()?;
        assert!(reward_per_token_stored > U256::ZERO);

        token.update_rewards(&alice)?;
        assert_eq!(token.get_opted_in_supply()?, mint_amount);
        assert_eq!(token.get_delegated_balance(&alice)?, mint_amount);
        assert_eq!(
            token.get_user_reward_per_token_paid(&alice)?,
            reward_per_token_stored
        );

        // TODO: assert balances

        Ok(())
    }

    #[test]
    fn test_start_reward_duration_0() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        // Mint tokens to Alice and have her opt in as reward recipient
        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(&alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        // Mint reward tokens to admin
        let reward_amount = U256::from(100e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        let alice_balance_before = token.get_balance(&alice)?;

        // Start immediate reward
        let id = token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: 0,
            },
        )?;

        assert_eq!(id, 0);

        let bob = Address::random();
        token.transfer(
            &alice,
            ITIP20::transferCall {
                to: bob,
                amount: U256::from(1),
            },
        )?;

        let alice_balance_after = token.get_balance(&alice)?;

        assert_eq!(
            alice_balance_after,
            alice_balance_before + reward_amount - U256::from(1)
        );

        let total_reward_per_second = token.get_total_reward_per_second()?;
        assert_eq!(total_reward_per_second, U256::ZERO);

        let opted_in_supply = token.get_opted_in_supply()?;
        assert_eq!(opted_in_supply, mint_amount - U256::ONE);

        Ok(())
    }

    #[test]
    fn test_reward_distribution_pro_rata() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        // Mint tokens to Alice and have her opt in as reward recipient
        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(&alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        // Mint reward tokens to admin
        let reward_amount = U256::from(100e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        let alice_balance_before = token.get_balance(&alice)?;

        // Start streaming reward for 20 seconds
        let stream_id = token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: 20,
            },
        )?;

        assert_eq!(stream_id, 1);

        // Simulate 10 blocks
        let current_timestamp = token.storage.timestamp();
        token
            .storage
            .set_timestamp(current_timestamp + uint!(10_U256));

        token.finalize_streams()?;
        token.transfer(
            &alice,
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::ONE,
            },
        )?;

        // Assert balances after first half elapsed
        let alice_balance_mid = token.get_balance(&alice)?;
        let expected_balance = alice_balance_before + (reward_amount / uint!(2_U256)) - U256::ONE;
        assert_eq!(alice_balance_mid, expected_balance);

        token
            .storage
            .set_timestamp(current_timestamp + uint!(20_U256));

        token.finalize_streams()?;
        token.transfer(
            &alice,
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::ONE,
            },
        )?;

        // Assert balances
        let alice_balance_after = token.get_balance(&alice)?;

        // NOTE: we are losing 1 wei due to rounding
        let expected_balance = alice_balance_before + reward_amount - U256::from(3);
        assert_eq!(alice_balance_after, expected_balance);

        // Confirm that stream is finished
        let total_reward_per_second = token.get_total_reward_per_second()?;
        assert_eq!(total_reward_per_second, U256::ZERO);

        Ok(())
    }
}
