//! EIP-712 settlement attestations verified by `ZonePortal.submitBatch`.

use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync as _;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{Eip712Domain, SolStruct as _, eip712_domain, sol};

sol! {
    /// Exact settlement statement verified by ZonePortal.
    #[derive(Debug, PartialEq, Eq)]
    struct SettlementAttestation {
        uint32 zoneId;
        uint64 sequencerSetVersion;
        uint256 zoneHeight;
        uint256 withdrawalBatchIndex;
        address verifier;
        uint64 tempoBlockNumber;
        uint64 anchorBlockNumber;
        bytes32 anchorBlockHash;
        bytes32 blockTransitionHash;
        bytes32 depositQueueTransitionHash;
        bytes32 tokenEnablementTransitionHash;
        bytes32 withdrawalQueueHash;
        bytes32 verifierConfigHash;
    }

    /// Settlement statement with the submitting sequencer's signature.
    #[derive(Debug, PartialEq, Eq)]
    struct SignedSettlementAttestation {
        SettlementAttestation attestation;
        bytes signature;
    }

}

mod legacy {
    alloy_sol_types::sol! {
        /// Settlement statement used by the pre-T13 portal ABI.
        #[derive(Debug, PartialEq, Eq)]
        struct SettlementAttestation {
            uint32 zoneId;
            uint64 sequencerSetVersion;
            uint256 zoneHeight;
            uint256 withdrawalBatchIndex;
            address verifier;
            uint64 tempoBlockNumber;
            uint64 anchorBlockNumber;
            bytes32 anchorBlockHash;
            bytes32 blockTransitionHash;
            bytes32 depositQueueTransitionHash;
            bytes32 withdrawalQueueHash;
            bytes32 verifierConfigHash;
        }
    }
}

use legacy::SettlementAttestation as LegacySettlementAttestation;

/// Immutable values that domain-separate one zone's attestations.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AttestationDomain {
    pub(crate) l1_chain_id: u64,
    pub(crate) portal_address: Address,
}

impl AttestationDomain {
    fn eip712(self) -> Eip712Domain {
        eip712_domain! {
            name: "ZonePortal",
            version: "1",
            chain_id: self.l1_chain_id,
            verifying_contract: self.portal_address,
        }
    }

    pub(crate) fn settlement_digest(self, attestation: &SettlementAttestation) -> B256 {
        if attestation.is_legacy() {
            attestation.as_legacy().eip712_signing_hash(&self.eip712())
        } else {
            attestation.eip712_signing_hash(&self.eip712())
        }
    }
}

impl SettlementAttestation {
    /// Legacy attestations use a zero sentinel for the field absent from their wire format.
    pub fn is_legacy(&self) -> bool {
        self.tokenEnablementTransitionHash.is_zero()
    }

    fn as_legacy(&self) -> LegacySettlementAttestation {
        LegacySettlementAttestation {
            zoneId: self.zoneId,
            sequencerSetVersion: self.sequencerSetVersion,
            zoneHeight: self.zoneHeight,
            withdrawalBatchIndex: self.withdrawalBatchIndex,
            verifier: self.verifier,
            tempoBlockNumber: self.tempoBlockNumber,
            anchorBlockNumber: self.anchorBlockNumber,
            anchorBlockHash: self.anchorBlockHash,
            blockTransitionHash: self.blockTransitionHash,
            depositQueueTransitionHash: self.depositQueueTransitionHash,
            withdrawalQueueHash: self.withdrawalQueueHash,
            verifierConfigHash: self.verifierConfigHash,
        }
    }
}

impl SignedSettlementAttestation {
    pub(crate) fn sign(
        attestation: SettlementAttestation,
        domain: AttestationDomain,
        signer: &PrivateKeySigner,
    ) -> eyre::Result<Self> {
        let signature = signer.sign_hash_sync(&domain.settlement_digest(&attestation))?;
        Ok(Self {
            attestation,
            signature: signature.as_bytes().into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256, Signature, U256, keccak256};
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::SolValue as _;

    use super::*;

    fn domain() -> AttestationDomain {
        AttestationDomain {
            l1_chain_id: 1337,
            portal_address: Address::repeat_byte(0x11),
        }
    }

    #[test]
    fn settlement_type_and_signature_match_zone_portal() {
        const PORTAL_TYPE: &str = "SettlementAttestation(uint32 zoneId,uint64 sequencerSetVersion,uint256 zoneHeight,uint256 withdrawalBatchIndex,address verifier,uint64 tempoBlockNumber,uint64 anchorBlockNumber,bytes32 anchorBlockHash,bytes32 blockTransitionHash,bytes32 depositQueueTransitionHash,bytes32 tokenEnablementTransitionHash,bytes32 withdrawalQueueHash,bytes32 verifierConfigHash)";
        assert_eq!(SettlementAttestation::eip712_encode_type(), PORTAL_TYPE);

        let attestation = SettlementAttestation {
            zoneId: 7,
            sequencerSetVersion: 3,
            zoneHeight: U256::from(120),
            withdrawalBatchIndex: U256::ONE,
            verifier: Address::repeat_byte(2),
            tempoBlockNumber: 100,
            anchorBlockNumber: 100,
            anchorBlockHash: B256::repeat_byte(3),
            blockTransitionHash: B256::repeat_byte(4),
            depositQueueTransitionHash: B256::repeat_byte(5),
            tokenEnablementTransitionHash: B256::repeat_byte(8),
            withdrawalQueueHash: B256::repeat_byte(6),
            verifierConfigHash: B256::repeat_byte(7),
        };
        let struct_hash = keccak256(
            (
                keccak256(PORTAL_TYPE),
                attestation.zoneId,
                attestation.sequencerSetVersion,
                attestation.zoneHeight,
                attestation.withdrawalBatchIndex,
                attestation.verifier,
                attestation.tempoBlockNumber,
                attestation.anchorBlockNumber,
                attestation.anchorBlockHash,
                attestation.blockTransitionHash,
                attestation.depositQueueTransitionHash,
                attestation.tokenEnablementTransitionHash,
                attestation.withdrawalQueueHash,
                attestation.verifierConfigHash,
            )
                .abi_encode(),
        );
        let domain = domain();
        let domain_separator = keccak256(
            (
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
                ),
                keccak256("ZonePortal"),
                keccak256("1"),
                U256::from(domain.l1_chain_id),
                domain.portal_address,
            )
                .abi_encode(),
        );
        let mut encoded_digest = Vec::with_capacity(66);
        encoded_digest.extend_from_slice(&[0x19, 0x01]);
        encoded_digest.extend_from_slice(domain_separator.as_slice());
        encoded_digest.extend_from_slice(struct_hash.as_slice());
        assert_eq!(
            domain.settlement_digest(&attestation),
            keccak256(encoded_digest)
        );

        let signer = PrivateKeySigner::random();
        let signed = SignedSettlementAttestation::sign(attestation, domain, &signer).unwrap();
        assert_eq!(recover(&signed, domain), signer.address());
    }

    #[test]
    fn legacy_settlement_uses_pre_t13_wire_format_and_digest() {
        const LEGACY_PORTAL_TYPE: &str = "SettlementAttestation(uint32 zoneId,uint64 sequencerSetVersion,uint256 zoneHeight,uint256 withdrawalBatchIndex,address verifier,uint64 tempoBlockNumber,uint64 anchorBlockNumber,bytes32 anchorBlockHash,bytes32 blockTransitionHash,bytes32 depositQueueTransitionHash,bytes32 withdrawalQueueHash,bytes32 verifierConfigHash)";
        assert_eq!(
            LegacySettlementAttestation::eip712_encode_type(),
            LEGACY_PORTAL_TYPE
        );

        let attestation = SettlementAttestation {
            zoneId: 7,
            sequencerSetVersion: 3,
            zoneHeight: U256::from(120),
            withdrawalBatchIndex: U256::ONE,
            verifier: Address::repeat_byte(2),
            tempoBlockNumber: 100,
            anchorBlockNumber: 100,
            anchorBlockHash: B256::repeat_byte(3),
            blockTransitionHash: B256::repeat_byte(4),
            depositQueueTransitionHash: B256::repeat_byte(5),
            tokenEnablementTransitionHash: B256::ZERO,
            withdrawalQueueHash: B256::repeat_byte(6),
            verifierConfigHash: B256::repeat_byte(7),
        };
        let legacy = attestation.as_legacy();
        assert_eq!(
            domain().settlement_digest(&attestation),
            legacy.eip712_signing_hash(&domain().eip712())
        );

        let signer = PrivateKeySigner::random();
        let signed = SignedSettlementAttestation::sign(attestation, domain(), &signer).unwrap();
        assert_eq!(recover(&signed, domain()), signer.address());
    }

    fn recover(signed: &SignedSettlementAttestation, domain: AttestationDomain) -> Address {
        let signature = Signature::try_from(signed.signature.as_ref()).unwrap();
        alloy_consensus::crypto::secp256k1::recover_signer(
            &signature,
            domain.settlement_digest(&signed.attestation),
        )
        .unwrap()
    }
}
