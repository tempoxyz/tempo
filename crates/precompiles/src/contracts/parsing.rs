use alloy::primitives::{Address, FixedBytes, U256};

use crate::{contracts::types::ERC20Error, erc20_err};

#[derive(Debug)]
pub struct SignedTransferPayload {
    pub to: Address,
    pub amount: U256,
    pub nonce: u32,
    pub rvs: [u8; 64],
}

#[inline]
pub fn unpack_eip2098_rvs(rvs: [u8; 64]) -> (FixedBytes<32>, u8, FixedBytes<32>) {
    let r = FixedBytes::from_slice(&rvs[..32]);

    let vs = U256::from_be_slice(&rvs[32..]);
    // v = add(shr(255, vs), 27)
    let v = ((vs.wrapping_shr(255)) + U256::from(27)).to::<u8>();
    // s = shr(1, shl(1, vs))
    let s = FixedBytes::from((vs.wrapping_shl(1).wrapping_shr(1)).to_be_bytes::<32>());

    (r, v, s)
}

#[inline]
pub fn parse_signed_transfer_payload(
    data: &[u8],
) -> Result<(SignedTransferPayload, usize), ERC20Error> {
    let mut cursor = 0;

    let mut consume_bytes = |len: usize| -> Result<&[u8], ERC20Error> {
        if cursor + len > data.len() {
            return Err(erc20_err!(InvalidPayload));
        }
        let slice = &data[cursor..cursor + len];
        cursor += len;
        Ok(slice)
    };

    // Read to address (20 bytes)
    let to = Address::from_slice(consume_bytes(20)?);

    // Read amount length (1 byte)
    let amount_len_bytes: usize = consume_bytes(1)?[0].into();
    if amount_len_bytes > 32 {
        return Err(erc20_err!(InvalidPayload));
    }

    // Read amount (variable length 0-32 bytes)
    let amount = U256::from_be_slice(consume_bytes(amount_len_bytes)?);
    // Read nonce (4 bytes)
    let nonce = u32::from_be_bytes(consume_bytes(4)?.try_into().unwrap());
    // Read rvs (64 bytes) - compact signature format per EIP-2098
    let rvs = consume_bytes(64)?.try_into().unwrap();

    Ok((
        SignedTransferPayload {
            to,
            amount,
            nonce,
            rvs,
        },
        cursor, // cursor_end_position_relative
    ))
}

pub mod test_utils {
    use alloy::{
        primitives::{Address, U256, keccak256},
        signers::{SignerSync, local::PrivateKeySigner},
    };

    pub fn pack_and_sign_payload(
        to: Address,
        amount: U256,
        nonce: u32,
        signer: &PrivateKeySigner,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(to.as_slice());
        let amount_bytes = amount.to_be_bytes_vec();
        data.push(amount_bytes.len() as u8);
        data.extend_from_slice(&amount_bytes);
        data.extend_from_slice(&nonce.to_be_bytes());

        let signature = signer.sign_hash_sync(&keccak256(&data));

        data.extend_from_slice(&signature.unwrap().as_erc2098()); // rvs

        data
    }
}

#[cfg(test)]
mod tests {

    use alloy::hex;

    use super::*;

    #[test]
    fn test_hardcoded_payloads() {
        {
            // Test case A: len = 0x01, amount = 0xbb
            let payload = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01bb12345678111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222221b").unwrap();
            let result = parse_signed_transfer_payload(&payload);

            let (payload, _) = result.unwrap();

            let (r, v, s) = unpack_eip2098_rvs(payload.rvs);

            assert_eq!(payload.to, Address::from([0xaa; 20]));
            assert_eq!(payload.amount, U256::from(0xbb));
            assert_eq!(payload.nonce, 0x12345678);
            assert_eq!(r, FixedBytes::from([0x11; 32]));
            assert_eq!(s, FixedBytes::from([0x22; 32]));
            assert_eq!(v, 0x1b);
        }

        {
            // Test case B: len = 0x02, amount = 0x0bbb
            let payload = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa020bbb12345678111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222221b").unwrap();
            let result = parse_signed_transfer_payload(&payload);

            let (payload, _) = result.unwrap();

            let (r, v, s) = unpack_eip2098_rvs(payload.rvs);

            assert_eq!(payload.to, Address::from([0xaa; 20]));
            assert_eq!(payload.amount, U256::from(0x0bbb));
            assert_eq!(payload.nonce, 0x12345678);
            assert_eq!(r, FixedBytes::from([0x11; 32]));
            assert_eq!(s, FixedBytes::from([0x22; 32]));
            assert_eq!(v, 0x1b);
        }

        {
            // Test case C: len = 0x04, amount = 0xdeadbeef
            let payload = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa04deadbeef12345678111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222221b").unwrap();
            let result = parse_signed_transfer_payload(&payload);

            let (payload, _) = result.unwrap();

            let (r, v, s) = unpack_eip2098_rvs(payload.rvs);

            assert_eq!(payload.to, Address::from([0xaa; 20]));
            assert_eq!(payload.amount, U256::from(0xdeadbeef_u128));
            assert_eq!(payload.nonce, 0x12345678);
            assert_eq!(r, FixedBytes::from([0x11; 32]));
            assert_eq!(s, FixedBytes::from([0x22; 32]));
            assert_eq!(v, 0x1b);
        }

        {
            // Test case D: len = 0x20 (32 bytes), amount = 0xee...ee (32 bytes of 0xee)
            let payload = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa20eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee12345678111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222221b").unwrap();
            let result = parse_signed_transfer_payload(&payload);

            let (payload, _) = result.unwrap();

            let (r, v, s) = unpack_eip2098_rvs(payload.rvs);

            assert_eq!(payload.to, Address::from([0xaa; 20]));
            assert_eq!(payload.amount, U256::from_be_bytes([0xee; 32]));
            assert_eq!(payload.nonce, 0x12345678);
            assert_eq!(r, FixedBytes::from([0x11; 32]));
            assert_eq!(s, FixedBytes::from([0x22; 32]));
            assert_eq!(v, 0x1b);
        }
    }
}
