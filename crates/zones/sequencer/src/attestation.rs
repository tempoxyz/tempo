//! EIP-712 replication ACKs and settlement attestations.

use alloy_primitives::{Address, B256, Bytes, Signature};
use alloy_signer::SignerSync as _;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{Eip712Domain, SolStruct as _, SolValue as _, eip712_domain, sol};
use eyre::WrapErr as _;

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

    /// Settlement signature returned to the leader for quorum collection.
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

        /// Signed settlement statement used by the pre-T13 portal ABI.
        #[derive(Debug, PartialEq, Eq)]
        struct SignedSettlementAttestation {
            SettlementAttestation attestation;
            bytes signature;
        }
    }
}

use legacy::{
    SettlementAttestation as LegacySettlementAttestation,
    SignedSettlementAttestation as LegacySignedSettlementAttestation,
};

/// Immutable values that domain-separate one zone's attestations.
#[derive(Debug, Clone, Copy)]
pub struct AttestationDomain {
    pub l1_chain_id: u64,
    pub portal_address: Address,
    pub zone_id: u32,
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

    pub fn settlement_digest(self, attestation: &SettlementAttestation) -> B256 {
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

    fn from_legacy(attestation: LegacySettlementAttestation) -> Self {
        Self {
            zoneId: attestation.zoneId,
            sequencerSetVersion: attestation.sequencerSetVersion,
            zoneHeight: attestation.zoneHeight,
            withdrawalBatchIndex: attestation.withdrawalBatchIndex,
            verifier: attestation.verifier,
            tempoBlockNumber: attestation.tempoBlockNumber,
            anchorBlockNumber: attestation.anchorBlockNumber,
            anchorBlockHash: attestation.anchorBlockHash,
            blockTransitionHash: attestation.blockTransitionHash,
            depositQueueTransitionHash: attestation.depositQueueTransitionHash,
            tokenEnablementTransitionHash: B256::ZERO,
            withdrawalQueueHash: attestation.withdrawalQueueHash,
            verifierConfigHash: attestation.verifierConfigHash,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        if self.is_legacy() {
            self.as_legacy().abi_encode()
        } else {
            self.abi_encode()
        }
    }

    pub fn decode(encoded: &[u8]) -> eyre::Result<Self> {
        Self::abi_decode(encoded)
            .or_else(|_| LegacySettlementAttestation::abi_decode(encoded).map(Self::from_legacy))
            .wrap_err("invalid settlement proposal encoding")
    }
}

impl SignedSettlementAttestation {
    pub fn sign(
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

    pub fn encode(&self) -> Vec<u8> {
        if self.attestation.is_legacy() {
            LegacySignedSettlementAttestation {
                attestation: self.attestation.as_legacy(),
                signature: self.signature.clone(),
            }
            .abi_encode()
        } else {
            self.abi_encode()
        }
    }

    pub fn decode(encoded: &[u8]) -> eyre::Result<Self> {
        Self::abi_decode(encoded)
            .or_else(|_| {
                LegacySignedSettlementAttestation::abi_decode(encoded).map(|signed| Self {
                    attestation: SettlementAttestation::from_legacy(signed.attestation),
                    signature: signed.signature,
                })
            })
            .wrap_err("invalid settlement signature encoding")
    }

    pub fn recover_signer(&self, domain: AttestationDomain) -> eyre::Result<Address> {
        let signature = Signature::try_from(self.signature.as_ref())
            .wrap_err("invalid settlement signature")?;
        alloy_consensus::crypto::secp256k1::recover_signer(
            &signature,
            domain.settlement_digest(&self.attestation),
        )
        .wrap_err("failed recovering settlement signer")
    }
}

/// A settlement statement and its distinct signer signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementCertificate {
    pub height: u64,
    pub digest: B256,
    pub attestation: SettlementAttestation,
    pub signatures: Vec<Bytes>,
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256, U256, keccak256, uint};
    use alloy_signer_local::PrivateKeySigner;

    use super::*;

    fn domain() -> AttestationDomain {
        AttestationDomain {
            l1_chain_id: 1337,
            portal_address: Address::repeat_byte(0x11),
            zone_id: 7,
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
        let decoded = SignedSettlementAttestation::decode(&signed.encode()).unwrap();
        assert_eq!(decoded, signed);
        assert_eq!(decoded.recover_signer(domain).unwrap(), signer.address());
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
        assert_eq!(attestation.encode(), legacy.abi_encode());
        assert_eq!(
            SettlementAttestation::decode(&legacy.abi_encode()).unwrap(),
            attestation
        );
        assert_eq!(
            domain().settlement_digest(&attestation),
            legacy.eip712_signing_hash(&domain().eip712())
        );

        let signer = PrivateKeySigner::random();
        let signed = SignedSettlementAttestation::sign(attestation, domain(), &signer).unwrap();
        let legacy_signed = LegacySignedSettlementAttestation {
            attestation: legacy,
            signature: signed.signature.clone(),
        };
        assert_eq!(signed.encode(), legacy_signed.abi_encode());
        assert_eq!(
            SignedSettlementAttestation::decode(&legacy_signed.abi_encode()).unwrap(),
            signed
        );
        assert_eq!(signed.recover_signer(domain()).unwrap(), signer.address());
    }

    #[test]
    fn rejects_high_s_settlement_signature() {
        const SECP256K1_ORDER: U256 =
            uint!(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_U256);

        let signer = PrivateKeySigner::random();
        let domain = domain();
        let attestation = SettlementAttestation {
            zoneId: 7,
            sequencerSetVersion: 3,
            zoneHeight: U256::from(10),
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
        let mut signed = SignedSettlementAttestation::sign(attestation, domain, &signer).unwrap();
        let signature = Signature::try_from(signed.signature.as_ref()).unwrap();
        let high_s_signature = Signature::new(
            signature.r(),
            SECP256K1_ORDER - signature.s(),
            !signature.v(),
        );
        signed.signature = high_s_signature.as_bytes().into();

        assert!(signed.recover_signer(domain).is_err());
    }
}
