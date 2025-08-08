//! Codec implementations for Malachite consensus messages

use crate::{
    Address, ProposalPart, Value, ValueId,
    context::{BasePeerAddress, MalachiteContext},
    height::Height,
    proto,
};
use bytes::Bytes;
use malachitebft_app::engine::util::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_codec::Codec;
use malachitebft_core_consensus::{LivenessMsg, ProposedValue, SignedConsensusMsg};
use malachitebft_core_types::{
    CommitCertificate, CommitSignature, NilOrVal, PolkaCertificate, PolkaSignature, Round,
    RoundCertificate, RoundCertificateType, RoundSignature, SignedProposal, SignedVote, Validity,
    VoteType,
};
use malachitebft_proto::Error as ProtoError;
use malachitebft_signing_ed25519::Signature;
use malachitebft_sync as sync;
use prost::Message;

/// Protobuf codec for Malachite messages
#[derive(Copy, Clone, Debug)]
pub struct ProtoCodec;

// Helper functions for encoding/decoding
#[allow(dead_code)]
fn encode_signature(signature: &Signature) -> proto::Signature {
    proto::Signature {
        bytes: Bytes::copy_from_slice(signature.to_bytes().as_ref()),
    }
}

#[allow(dead_code)]
fn decode_signature(signature: proto::Signature) -> Result<Signature, ProtoError> {
    let bytes = <[u8; 64]>::try_from(signature.bytes.as_ref())
        .map_err(|_| ProtoError::Other("Invalid signature length".to_string()))?;
    Ok(Signature::from_bytes(bytes))
}

#[allow(dead_code)]
fn encode_votetype(vote_type: VoteType) -> proto::VoteType {
    match vote_type {
        VoteType::Prevote => proto::VoteType::Prevote,
        VoteType::Precommit => proto::VoteType::Precommit,
    }
}

#[allow(dead_code)]
fn decode_votetype(vote_type: i32) -> VoteType {
    match proto::VoteType::try_from(vote_type) {
        Ok(proto::VoteType::Prevote) => VoteType::Prevote,
        Ok(proto::VoteType::Precommit) => VoteType::Precommit,
        Err(_) => VoteType::Prevote, // Default fallback
    }
}

// For now, we'll implement only the essential codecs needed to compile
// In production, all of these would have proper implementations

impl Codec<Value> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, bytes: Bytes) -> Result<Value, Self::Error> {
        let proto = proto::Value::decode(bytes.as_ref())?;
        // Decode the hash from the proto value field
        let value_bytes = proto.value.unwrap_or_default();

        if value_bytes.len() != 32 {
            return Err(ProtoError::Other(format!(
                "Invalid hash length: expected 32, got {}",
                value_bytes.len()
            )));
        }

        let hash = alloy_primitives::B256::from_slice(&value_bytes);
        Ok(Value::new(hash))
    }

    fn encode(&self, msg: &Value) -> Result<Bytes, Self::Error> {
        // Encode the hash to bytes
        let proto = proto::Value {
            value: Some(Bytes::from(msg.hash().to_vec())),
        };
        Ok(Bytes::from(proto.encode_to_vec()))
    }
}

impl Codec<ProposalPart> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, bytes: Bytes) -> Result<ProposalPart, Self::Error> {
        let proto = proto::ProposalPart::decode(bytes.as_ref())?;

        match proto.part {
            Some(proto::proposal_part::Part::Init(init)) => {
                let proposer = init
                    .proposer
                    .ok_or_else(|| ProtoError::missing_field::<proto::ProposalInit>("proposer"))?;

                let proposer_addr = if proposer.value.len() == 20 {
                    let mut bytes = [0u8; 20];
                    bytes.copy_from_slice(&proposer.value);
                    Address::new(bytes)
                } else {
                    return Err(ProtoError::Other(
                        "Invalid proposer address length".to_string(),
                    ));
                };

                let block_hash = alloy_primitives::B256::from_slice(&init.block_hash);

                Ok(ProposalPart::Init(crate::types::ProposalInit::new(
                    Height(init.height),
                    Round::new(init.round),
                    proposer_addr,
                    block_hash,
                )))
            }
            Some(proto::proposal_part::Part::Data(data)) => Ok(ProposalPart::Data(
                crate::types::ProposalData::new(data.bytes.clone()),
            )),
            Some(proto::proposal_part::Part::Fin(fin)) => {
                let signature = fin
                    .signature
                    .ok_or_else(|| ProtoError::missing_field::<proto::ProposalFin>("signature"))?;
                Ok(ProposalPart::Fin(crate::types::ProposalFin::new(
                    decode_signature(signature)?,
                )))
            }
            None => Err(ProtoError::missing_field::<proto::ProposalPart>("part")),
        }
    }

    fn encode(&self, msg: &ProposalPart) -> Result<Bytes, Self::Error> {
        let proto = match msg {
            ProposalPart::Init(init) => proto::ProposalPart {
                part: Some(proto::proposal_part::Part::Init(proto::ProposalInit {
                    height: init.height.0,
                    round: init.round.as_u32().ok_or_else(|| {
                        ProtoError::Other("Round is nil, cannot encode".to_string())
                    })?,
                    proposer: Some(proto::Address {
                        value: Bytes::from(init.proposer.as_bytes().to_vec()),
                    }),
                    pol_round: None, // Not used in our implementation
                    block_hash: Bytes::from(init.block_hash.to_vec()),
                })),
            },
            ProposalPart::Data(data) => proto::ProposalPart {
                part: Some(proto::proposal_part::Part::Data(proto::ProposalData {
                    bytes: data.bytes.clone(),
                })),
            },
            ProposalPart::Fin(fin) => proto::ProposalPart {
                part: Some(proto::proposal_part::Part::Fin(proto::ProposalFin {
                    signature: Some(encode_signature(&fin.signature)),
                })),
            },
        };

        Ok(Bytes::from(proto.encode_to_vec()))
    }
}

impl Codec<SignedConsensusMsg<MalachiteContext>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, bytes: Bytes) -> Result<SignedConsensusMsg<MalachiteContext>, Self::Error> {
        let proto = proto::SignedMessage::decode(bytes.as_ref())?;

        let signature = proto
            .signature
            .ok_or_else(|| ProtoError::missing_field::<proto::SignedMessage>("signature"))?;
        let signature = decode_signature(signature)?;

        match proto.message {
            Some(proto::signed_message::Message::Proposal(proposal)) => {
                let proposer = proposal.validator_address.ok_or_else(|| {
                    ProtoError::missing_field::<proto::Proposal>("validator_address")
                })?;

                let proposer_addr = if proposer.value.len() == 20 {
                    let mut bytes = [0u8; 20];
                    bytes.copy_from_slice(&proposer.value);
                    BasePeerAddress(Address::new(bytes))
                } else {
                    return Err(ProtoError::Other(
                        "Invalid proposer address length".to_string(),
                    ));
                };

                let value = proposal
                    .value
                    .ok_or_else(|| ProtoError::missing_field::<proto::Proposal>("value"))?;
                let value_data = value
                    .value
                    .ok_or_else(|| ProtoError::missing_field::<proto::Value>("value"))?;

                // Now we expect a hash, not a full block
                if value_data.len() != 32 {
                    return Err(ProtoError::Other(format!(
                        "Invalid value hash length: expected 32, got {}",
                        value_data.len()
                    )));
                }

                let hash = alloy_primitives::B256::from_slice(&value_data);
                let value = Value::new(hash);

                let base_proposal = crate::context::BaseProposal {
                    height: Height(proposal.height),
                    round: crate::context::RoundWrapper(Round::new(proposal.round)),
                    value,
                    proposer: proposer_addr,
                    parts: vec![], // Parts are sent separately via streaming
                    pol_round: crate::context::RoundWrapper(
                        proposal.pol_round.map(Round::new).unwrap_or(Round::Nil),
                    ),
                };

                let signed_proposal = SignedProposal {
                    message: base_proposal,
                    signature,
                };

                Ok(SignedConsensusMsg::Proposal(signed_proposal))
            }
            Some(proto::signed_message::Message::Vote(vote)) => {
                let voter = vote
                    .validator_address
                    .ok_or_else(|| ProtoError::missing_field::<proto::Vote>("validator_address"))?;

                let voter_addr = if voter.value.len() == 20 {
                    let mut bytes = [0u8; 20];
                    bytes.copy_from_slice(&voter.value);
                    BasePeerAddress(Address::new(bytes))
                } else {
                    return Err(ProtoError::Other(
                        "Invalid voter address length".to_string(),
                    ));
                };

                let value_id = if let Some(value) = vote.value {
                    if let Some(value_bytes) = value.value {
                        let mut hash_bytes = [0u8; 32];
                        let len = value_bytes.len().min(32);
                        hash_bytes[..len].copy_from_slice(&value_bytes[..len]);
                        NilOrVal::Val(ValueId::new(alloy_primitives::B256::from(hash_bytes)))
                    } else {
                        NilOrVal::Nil
                    }
                } else {
                    NilOrVal::Nil
                };

                let base_vote = crate::context::BaseVote {
                    vote_type: crate::context::VoteTypeWrapper(decode_votetype(vote.vote_type)),
                    height: Height(vote.height),
                    round: crate::context::RoundWrapper(Round::new(vote.round)),
                    value_id,
                    voter: voter_addr,
                    extension: None, // Extensions handled separately if needed
                };

                let signed_vote = SignedVote {
                    message: base_vote,
                    signature,
                };

                Ok(SignedConsensusMsg::Vote(signed_vote))
            }
            None => Err(ProtoError::missing_field::<proto::SignedMessage>("message")),
        }
    }

    fn encode(&self, msg: &SignedConsensusMsg<MalachiteContext>) -> Result<Bytes, Self::Error> {
        let proto = match msg {
            SignedConsensusMsg::Proposal(signed_proposal) => {
                let proposal = &signed_proposal.message;
                proto::SignedMessage {
                    message: Some(proto::signed_message::Message::Proposal(proto::Proposal {
                        height: proposal.height.0,
                        round: proposal.round.0.as_u32().ok_or_else(|| {
                            ProtoError::Other("Round is nil, cannot encode".to_string())
                        })?,
                        value: Some(proto::Value {
                            value: Some(crate::app::encode_value(&proposal.value)),
                        }),
                        pol_round: proposal.pol_round.0.as_u32(),
                        validator_address: Some(proto::Address {
                            value: Bytes::from(proposal.proposer.0.as_bytes().to_vec()),
                        }),
                    })),
                    signature: Some(encode_signature(&signed_proposal.signature)),
                }
            }
            SignedConsensusMsg::Vote(signed_vote) => {
                let vote = &signed_vote.message;
                let value_id = match &vote.value_id {
                    NilOrVal::Val(id) => Some(proto::ValueId {
                        value: Some(Bytes::from(id.as_b256().to_vec())),
                    }),
                    NilOrVal::Nil => None,
                };

                proto::SignedMessage {
                    message: Some(proto::signed_message::Message::Vote(proto::Vote {
                        vote_type: encode_votetype(vote.vote_type.0) as i32,
                        height: vote.height.0,
                        round: vote.round.0.as_u32().ok_or_else(|| {
                            ProtoError::Other("Round is nil, cannot encode".to_string())
                        })?,
                        value: value_id,
                        validator_address: Some(proto::Address {
                            value: Bytes::from(vote.voter.0.as_bytes().to_vec()),
                        }),
                    })),
                    signature: Some(encode_signature(&signed_vote.signature)),
                }
            }
        };

        Ok(Bytes::from(proto.encode_to_vec()))
    }
}

impl Codec<ProposedValue<MalachiteContext>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, bytes: Bytes) -> Result<ProposedValue<MalachiteContext>, Self::Error> {
        let proto = proto::ProposedValue::decode(bytes.as_ref())?;
        decode_proposed_value(proto)
    }

    fn encode(&self, msg: &ProposedValue<MalachiteContext>) -> Result<Bytes, Self::Error> {
        let proto = encode_proposed_value(msg)?;
        Ok(Bytes::from(proto.encode_to_vec()))
    }
}

impl Codec<LivenessMsg<MalachiteContext>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, bytes: Bytes) -> Result<LivenessMsg<MalachiteContext>, Self::Error> {
        let proto = proto::LivenessMessage::decode(bytes.as_ref())?;

        match proto.message {
            Some(proto::liveness_message::Message::Vote(signed_message)) => {
                // Decode the signed vote message
                let signed_msg_bytes = Bytes::from(signed_message.encode_to_vec());
                match self.decode(signed_msg_bytes)? {
                    SignedConsensusMsg::Vote(vote) => Ok(LivenessMsg::Vote(vote)),
                    _ => Err(ProtoError::Other(
                        "Expected vote in liveness message".to_string(),
                    )),
                }
            }
            Some(proto::liveness_message::Message::PolkaCertificate(cert)) => {
                let value_id = cert.value_id.ok_or_else(|| {
                    ProtoError::missing_field::<proto::PolkaCertificate>("value_id")
                })?;
                let value_id_bytes = value_id
                    .value
                    .ok_or_else(|| ProtoError::missing_field::<proto::ValueId>("value"))?;

                let mut hash_bytes = [0u8; 32];
                let len = value_id_bytes.len().min(32);
                hash_bytes[..len].copy_from_slice(&value_id_bytes[..len]);
                let value_id = ValueId::new(alloy_primitives::B256::from(hash_bytes));

                let polka_signatures = cert
                    .signatures
                    .into_iter()
                    .map(|sig| {
                        let address = sig.validator_address.ok_or_else(|| {
                            ProtoError::missing_field::<proto::PolkaSignature>("validator_address")
                        })?;
                        let signature = sig.signature.ok_or_else(|| {
                            ProtoError::missing_field::<proto::PolkaSignature>("signature")
                        })?;

                        let addr_bytes = &address.value;
                        let address = if addr_bytes.len() == 20 {
                            let mut bytes = [0u8; 20];
                            bytes.copy_from_slice(addr_bytes);
                            BasePeerAddress(Address::new(bytes))
                        } else {
                            return Err(ProtoError::Other("Invalid address length".to_string()));
                        };

                        Ok(PolkaSignature {
                            address,
                            signature: decode_signature(signature)?,
                        })
                    })
                    .collect::<Result<Vec<_>, ProtoError>>()?;

                Ok(LivenessMsg::PolkaCertificate(PolkaCertificate {
                    height: Height(cert.height),
                    round: Round::new(cert.round),
                    value_id,
                    polka_signatures,
                }))
            }
            Some(proto::liveness_message::Message::RoundCertificate(cert)) => {
                let cert_type = match cert.cert_type {
                    0 => RoundCertificateType::Precommit,
                    1 => RoundCertificateType::Skip,
                    _ => return Err(ProtoError::Other("Invalid certificate type".to_string())),
                };

                let round_signatures = cert
                    .signatures
                    .into_iter()
                    .map(|sig| {
                        let address = sig.validator_address.ok_or_else(|| {
                            ProtoError::missing_field::<proto::RoundSignature>("validator_address")
                        })?;
                        let signature = sig.signature.ok_or_else(|| {
                            ProtoError::missing_field::<proto::RoundSignature>("signature")
                        })?;

                        let addr_bytes = &address.value;
                        let address = if addr_bytes.len() == 20 {
                            let mut bytes = [0u8; 20];
                            bytes.copy_from_slice(addr_bytes);
                            BasePeerAddress(Address::new(bytes))
                        } else {
                            return Err(ProtoError::Other("Invalid address length".to_string()));
                        };

                        let value_id = if let Some(value_id) = sig.value_id {
                            if let Some(value_bytes) = value_id.value {
                                let mut hash_bytes = [0u8; 32];
                                let len = value_bytes.len().min(32);
                                hash_bytes[..len].copy_from_slice(&value_bytes[..len]);
                                NilOrVal::Val(ValueId::new(alloy_primitives::B256::from(
                                    hash_bytes,
                                )))
                            } else {
                                NilOrVal::Nil
                            }
                        } else {
                            NilOrVal::Nil
                        };

                        Ok(RoundSignature {
                            vote_type: decode_votetype(sig.vote_type),
                            value_id,
                            address,
                            signature: decode_signature(signature)?,
                        })
                    })
                    .collect::<Result<Vec<_>, ProtoError>>()?;

                Ok(LivenessMsg::SkipRoundCertificate(RoundCertificate {
                    height: Height(cert.height),
                    round: Round::new(cert.round),
                    cert_type,
                    round_signatures,
                }))
            }
            None => Err(ProtoError::missing_field::<proto::LivenessMessage>(
                "message",
            )),
        }
    }

    fn encode(&self, msg: &LivenessMsg<MalachiteContext>) -> Result<Bytes, Self::Error> {
        let proto = match msg {
            LivenessMsg::Vote(vote) => {
                // Encode the vote as a SignedConsensusMsg first
                let signed_msg = SignedConsensusMsg::Vote(vote.clone());
                let encoded_vote = self.encode(&signed_msg)?;
                let proto_vote = proto::SignedMessage::decode(encoded_vote.as_ref())?;

                proto::LivenessMessage {
                    message: Some(proto::liveness_message::Message::Vote(proto_vote)),
                }
            }
            LivenessMsg::PolkaCertificate(cert) => {
                let signatures = cert
                    .polka_signatures
                    .iter()
                    .map(|sig| proto::PolkaSignature {
                        validator_address: Some(proto::Address {
                            value: Bytes::from(sig.address.0.as_bytes().to_vec()),
                        }),
                        signature: Some(encode_signature(&sig.signature)),
                    })
                    .collect();

                proto::LivenessMessage {
                    message: Some(proto::liveness_message::Message::PolkaCertificate(
                        proto::PolkaCertificate {
                            height: cert.height.0,
                            round: cert.round.as_u32().ok_or_else(|| {
                                ProtoError::Other("Round is nil, cannot encode".to_string())
                            })?,
                            value_id: Some(proto::ValueId {
                                value: Some(Bytes::from(cert.value_id.as_b256().to_vec())),
                            }),
                            signatures,
                        },
                    )),
                }
            }
            LivenessMsg::SkipRoundCertificate(cert) => {
                let cert_type = match cert.cert_type {
                    RoundCertificateType::Precommit => 0,
                    RoundCertificateType::Skip => 1,
                };

                let signatures = cert
                    .round_signatures
                    .iter()
                    .map(|sig| {
                        let value_id = match &sig.value_id {
                            NilOrVal::Val(id) => Some(proto::ValueId {
                                value: Some(Bytes::from(id.as_b256().to_vec())),
                            }),
                            NilOrVal::Nil => None,
                        };

                        proto::RoundSignature {
                            vote_type: encode_votetype(sig.vote_type) as i32,
                            validator_address: Some(proto::Address {
                                value: Bytes::from(sig.address.0.as_bytes().to_vec()),
                            }),
                            signature: Some(encode_signature(&sig.signature)),
                            value_id,
                        }
                    })
                    .collect();

                proto::LivenessMessage {
                    message: Some(proto::liveness_message::Message::RoundCertificate(
                        proto::RoundCertificate {
                            height: cert.height.0,
                            round: cert.round.as_u32().ok_or_else(|| {
                                ProtoError::Other("Round is nil, cannot encode".to_string())
                            })?,
                            cert_type,
                            signatures,
                        },
                    )),
                }
            }
        };

        Ok(Bytes::from(proto.encode_to_vec()))
    }
}

impl Codec<StreamMessage<ProposalPart>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, bytes: Bytes) -> Result<StreamMessage<ProposalPart>, Self::Error> {
        let proto = proto::StreamMessage::decode(bytes.as_ref())?;

        let stream_id = StreamId::new(proto.stream_id);
        let sequence = proto.sequence;

        let content = match proto.content {
            Some(proto::stream_message::Content::Data(data)) => {
                // Decode the ProposalPart from the data bytes
                let part: ProposalPart = self.decode(data)?;
                StreamContent::Data(part)
            }
            Some(proto::stream_message::Content::Fin(true)) => StreamContent::Fin,
            Some(proto::stream_message::Content::Fin(false)) => {
                return Err(ProtoError::Other(
                    "Invalid fin value: expected true".to_string(),
                ));
            }
            None => return Err(ProtoError::missing_field::<proto::StreamMessage>("content")),
        };

        Ok(StreamMessage {
            stream_id,
            sequence,
            content,
        })
    }

    fn encode(&self, msg: &StreamMessage<ProposalPart>) -> Result<Bytes, Self::Error> {
        let content = match &msg.content {
            StreamContent::Data(part) => {
                let encoded_part = self.encode(part)?;
                proto::stream_message::Content::Data(encoded_part)
            }
            StreamContent::Fin => proto::stream_message::Content::Fin(true),
        };

        let proto = proto::StreamMessage {
            stream_id: msg.stream_id.to_bytes().to_vec().into(),
            sequence: msg.sequence,
            content: Some(content),
        };

        Ok(Bytes::from(proto.encode_to_vec()))
    }
}

impl Codec<sync::Status<MalachiteContext>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, bytes: Bytes) -> Result<sync::Status<MalachiteContext>, Self::Error> {
        let proto = proto::Status::decode(bytes.as_ref())?;

        let peer_id_bytes = proto
            .peer_id
            .ok_or_else(|| ProtoError::missing_field::<proto::Status>("peer_id"))?
            .id;

        let peer_id = sync::PeerId::from_bytes(&peer_id_bytes)
            .map_err(|e| ProtoError::Other(format!("Invalid peer ID: {e}")))?;

        Ok(sync::Status {
            peer_id,
            tip_height: Height(proto.height),
            history_min_height: Height(proto.earliest_height),
        })
    }

    fn encode(&self, msg: &sync::Status<MalachiteContext>) -> Result<Bytes, Self::Error> {
        let proto = proto::Status {
            peer_id: Some(proto::PeerId {
                id: Bytes::from(msg.peer_id.to_bytes()),
            }),
            height: msg.tip_height.0,
            earliest_height: msg.history_min_height.0,
        };
        Ok(Bytes::from(proto.encode_to_vec()))
    }
}

impl Codec<sync::Request<MalachiteContext>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, bytes: Bytes) -> Result<sync::Request<MalachiteContext>, Self::Error> {
        let proto = proto::SyncRequest::decode(bytes.as_ref())?;

        match proto.request {
            Some(proto::sync_request::Request::ValueRequest(req)) => {
                Ok(sync::Request::ValueRequest(sync::ValueRequest {
                    height: Height(req.height),
                }))
            }
            None => Err(ProtoError::missing_field::<proto::SyncRequest>("request")),
        }
    }

    fn encode(&self, msg: &sync::Request<MalachiteContext>) -> Result<Bytes, Self::Error> {
        let proto = match msg {
            sync::Request::ValueRequest(req) => proto::SyncRequest {
                request: Some(proto::sync_request::Request::ValueRequest(
                    proto::ValueRequest {
                        height: req.height.0,
                    },
                )),
            },
        };

        Ok(Bytes::from(proto.encode_to_vec()))
    }
}

impl Codec<sync::Response<MalachiteContext>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, bytes: Bytes) -> Result<sync::Response<MalachiteContext>, Self::Error> {
        let proto = proto::SyncResponse::decode(bytes.as_ref())?;

        match proto.response {
            Some(proto::sync_response::Response::ValueResponse(resp)) => {
                let value = if let Some(synced_value) = resp.value {
                    let certificate = synced_value.certificate.ok_or_else(|| {
                        ProtoError::missing_field::<proto::SyncedValue>("certificate")
                    })?;

                    Some(sync::RawDecidedValue {
                        value_bytes: synced_value.value_bytes,
                        certificate: decode_commit_certificate(certificate)?,
                    })
                } else {
                    None
                };

                Ok(sync::Response::ValueResponse(sync::ValueResponse {
                    height: Height(resp.height),
                    value,
                }))
            }
            None => Err(ProtoError::missing_field::<proto::SyncResponse>("response")),
        }
    }

    fn encode(&self, msg: &sync::Response<MalachiteContext>) -> Result<Bytes, Self::Error> {
        let proto = match msg {
            sync::Response::ValueResponse(resp) => {
                let value = if let Some(raw_value) = &resp.value {
                    Some(proto::SyncedValue {
                        value_bytes: raw_value.value_bytes.clone(),
                        certificate: Some(encode_commit_certificate(&raw_value.certificate)?),
                    })
                } else {
                    None
                };

                proto::SyncResponse {
                    response: Some(proto::sync_response::Response::ValueResponse(
                        proto::ValueResponse {
                            height: resp.height.0,
                            value,
                        },
                    )),
                }
            }
        };

        Ok(Bytes::from(proto.encode_to_vec()))
    }
}

// Encoding/decoding functions for CommitCertificate
pub fn encode_commit_certificate(
    certificate: &CommitCertificate<MalachiteContext>,
) -> Result<proto::CommitCertificate, ProtoError> {
    Ok(proto::CommitCertificate {
        height: certificate.height.0,
        round: certificate
            .round
            .as_u32()
            .ok_or_else(|| ProtoError::Other("Round is nil, cannot encode".to_string()))?,
        value_id: Some(proto::ValueId {
            value: Some(Bytes::from(
                certificate.value_id.as_u64().to_be_bytes().to_vec(),
            )),
        }),
        signatures: certificate
            .commit_signatures
            .iter()
            .map(encode_commit_signature)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub fn decode_commit_certificate(
    proto: proto::CommitCertificate,
) -> Result<CommitCertificate<MalachiteContext>, ProtoError> {
    let value_id = proto
        .value_id
        .ok_or_else(|| ProtoError::missing_field::<proto::CommitCertificate>("value_id"))?;

    let value_id_bytes = value_id
        .value
        .ok_or_else(|| ProtoError::missing_field::<proto::ValueId>("value"))?;

    Ok(CommitCertificate {
        height: Height(proto.height),
        round: Round::new(proto.round),
        value_id: {
            // Convert bytes to B256
            let mut hash_bytes = [0u8; 32];
            let len = value_id_bytes.len().min(32);
            hash_bytes[..len].copy_from_slice(&value_id_bytes[..len]);
            ValueId::new(alloy_primitives::B256::from(hash_bytes))
        },
        commit_signatures: proto
            .signatures
            .into_iter()
            .map(decode_commit_signature)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn encode_commit_signature(
    signature: &CommitSignature<MalachiteContext>,
) -> Result<proto::CommitSignature, ProtoError> {
    Ok(proto::CommitSignature {
        validator_address: Some(proto::Address {
            value: Bytes::from(signature.address.0.as_bytes().to_vec()),
        }),
        signature: Some(encode_signature(&signature.signature)),
    })
}

fn decode_commit_signature(
    proto: proto::CommitSignature,
) -> Result<CommitSignature<MalachiteContext>, ProtoError> {
    let address = proto
        .validator_address
        .ok_or_else(|| ProtoError::missing_field::<proto::CommitSignature>("validator_address"))?;

    let signature = proto
        .signature
        .ok_or_else(|| ProtoError::missing_field::<proto::CommitSignature>("signature"))?;

    let addr_bytes = &address.value;
    let address = if addr_bytes.len() == 20 {
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(addr_bytes);
        BasePeerAddress(Address::new(bytes))
    } else {
        return Err(ProtoError::Other("Invalid address length".to_string()));
    };

    Ok(CommitSignature::new(address, decode_signature(signature)?))
}

// Encoding/decoding functions for ProposedValue
fn encode_proposed_value(
    proposed_value: &ProposedValue<MalachiteContext>,
) -> Result<proto::ProposedValue, ProtoError> {
    Ok(proto::ProposedValue {
        height: proposed_value.height.0,
        round: proposed_value
            .round
            .as_u32()
            .ok_or_else(|| ProtoError::Other("Round is nil, cannot encode".to_string()))?,
        valid_round: proposed_value.valid_round.as_u32(),
        proposer: Some(proto::Address {
            value: Bytes::from(proposed_value.proposer.0.as_bytes().to_vec()),
        }),
        value: Some(proto::Value {
            value: Some(crate::app::encode_value(&proposed_value.value)),
        }),
        validity: proposed_value.validity.to_bool(),
    })
}

fn decode_proposed_value(
    proto: proto::ProposedValue,
) -> Result<ProposedValue<MalachiteContext>, ProtoError> {
    let proposer = proto
        .proposer
        .ok_or_else(|| ProtoError::missing_field::<proto::ProposedValue>("proposer"))?;

    let value = proto
        .value
        .ok_or_else(|| ProtoError::missing_field::<proto::ProposedValue>("value"))?;

    let value_data = value
        .value
        .ok_or_else(|| ProtoError::missing_field::<proto::Value>("value"))?;

    Ok(ProposedValue {
        height: Height(proto.height),
        round: Round::new(proto.round),
        valid_round: proto.valid_round.map(Round::new).unwrap_or(Round::Nil),
        proposer: {
            let addr_bytes = &proposer.value;
            if addr_bytes.len() == 20 {
                let mut bytes = [0u8; 20];
                bytes.copy_from_slice(addr_bytes);
                BasePeerAddress(Address::new(bytes))
            } else {
                return Err(ProtoError::Other(
                    "Invalid proposer address length".to_string(),
                ));
            }
        },
        value: crate::app::decode_value(value_data)
            .ok_or_else(|| ProtoError::Other("Failed to decode block value".to_string()))?,
        validity: Validity::from_bool(proto.validity),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use malachitebft_codec::Codec;
    use malachitebft_signing_ed25519::Signature;
    use reth_primitives::Block;

    fn test_address() -> Address {
        Address::new([1u8; 20])
    }

    fn test_signature() -> Signature {
        Signature::from_bytes([0u8; 64])
    }

    #[test]
    fn test_proposal_part_codec() {
        let codec = ProtoCodec;

        // Test ProposalInit
        let block_hash = B256::from([42u8; 32]);
        let init = ProposalPart::Init(crate::types::ProposalInit::new(
            Height(100),
            Round::new(1),
            test_address(),
            block_hash,
        ));
        let encoded = codec.encode(&init).unwrap();
        let decoded: ProposalPart = codec.decode(encoded).unwrap();
        assert_eq!(init, decoded);

        // Test ProposalData
        let data = ProposalPart::Data(crate::types::ProposalData::new(Bytes::from(
            42u64.to_be_bytes().to_vec(),
        )));
        let encoded = codec.encode(&data).unwrap();
        let decoded: ProposalPart = codec.decode(encoded).unwrap();
        assert_eq!(data, decoded);

        // Test ProposalFin
        let fin = ProposalPart::Fin(crate::types::ProposalFin::new(test_signature()));
        let encoded = codec.encode(&fin).unwrap();
        let decoded: ProposalPart = codec.decode(encoded).unwrap();
        assert_eq!(fin, decoded);
    }

    #[test]
    fn test_signed_consensus_msg_vote_codec() {
        let codec = ProtoCodec;

        let vote = crate::context::BaseVote {
            vote_type: crate::context::VoteTypeWrapper(VoteType::Prevote),
            height: Height(100),
            round: crate::context::RoundWrapper(Round::new(1)),
            value_id: NilOrVal::Val(ValueId::new(B256::from([1u8; 32]))),
            voter: BasePeerAddress(test_address()),
            extension: None,
        };

        let signed_vote = SignedVote {
            message: vote,
            signature: test_signature(),
        };

        let msg = SignedConsensusMsg::Vote(signed_vote);
        let encoded = codec.encode(&msg).unwrap();
        let decoded: SignedConsensusMsg<MalachiteContext> = codec.decode(encoded).unwrap();

        match decoded {
            SignedConsensusMsg::Vote(decoded_vote) => {
                assert_eq!(decoded_vote.message.height, Height(100));
                assert_eq!(decoded_vote.message.round.0, Round::new(1));
                assert_eq!(decoded_vote.message.vote_type.0, VoteType::Prevote);
            }
            _ => panic!("Expected Vote variant"),
        }
    }

    #[test]
    fn test_stream_message_codec() {
        let codec = ProtoCodec;

        // Test with data content
        let block_hash = B256::from([99u8; 32]);
        let part = ProposalPart::Init(crate::types::ProposalInit::new(
            Height(200),
            Round::new(2),
            test_address(),
            block_hash,
        ));

        let stream_msg = StreamMessage {
            stream_id: StreamId::new(Bytes::from(vec![1, 2, 3, 4])),
            sequence: 42,
            content: StreamContent::Data(part.clone()),
        };

        let encoded = codec.encode(&stream_msg).unwrap();
        let decoded: StreamMessage<ProposalPart> = codec.decode(encoded).unwrap();

        assert_eq!(decoded.sequence, 42);
        match decoded.content {
            StreamContent::Data(decoded_part) => assert_eq!(decoded_part, part),
            _ => panic!("Expected Data content"),
        }

        // Test with Fin content
        let fin_msg = StreamMessage {
            stream_id: StreamId::new(Bytes::from(vec![5, 6, 7, 8])),
            sequence: 99,
            content: StreamContent::Fin,
        };

        let encoded = codec.encode(&fin_msg).unwrap();
        let decoded: StreamMessage<ProposalPart> = codec.decode(encoded).unwrap();

        assert_eq!(decoded.sequence, 99);
        assert!(matches!(decoded.content, StreamContent::Fin));
    }

    #[test]
    fn test_sync_request_response_codec() {
        let codec = ProtoCodec;

        // Test Request
        let request = sync::Request::ValueRequest(sync::ValueRequest {
            height: Height(300),
        });

        let encoded = codec.encode(&request).unwrap();
        let decoded: sync::Request<MalachiteContext> = codec.decode(encoded).unwrap();

        match decoded {
            sync::Request::ValueRequest(req) => {
                assert_eq!(req.height, Height(300));
            }
        }

        // Test Response with value
        let cert = CommitCertificate {
            height: Height(300),
            round: Round::new(3),
            value_id: ValueId::new(B256::from([2u8; 32])),
            commit_signatures: vec![CommitSignature::new(
                BasePeerAddress(test_address()),
                test_signature(),
            )],
        };

        let response = sync::Response::ValueResponse(sync::ValueResponse {
            height: Height(300),
            value: Some(sync::RawDecidedValue {
                value_bytes: Bytes::from(vec![1, 2, 3, 4, 5]),
                certificate: cert,
            }),
        });

        let encoded = codec.encode(&response).unwrap();
        let decoded: sync::Response<MalachiteContext> = codec.decode(encoded).unwrap();

        match decoded {
            sync::Response::ValueResponse(resp) => {
                assert_eq!(resp.height, Height(300));
                assert!(resp.value.is_some());
                let value = resp.value.unwrap();
                assert_eq!(value.value_bytes, Bytes::from(vec![1, 2, 3, 4, 5]));
                assert_eq!(value.certificate.height, Height(300));
            }
        }

        // Test Response without value
        let empty_response = sync::Response::ValueResponse(sync::ValueResponse {
            height: Height(400),
            value: None,
        });

        let encoded = codec.encode(&empty_response).unwrap();
        let decoded: sync::Response<MalachiteContext> = codec.decode(encoded).unwrap();

        match decoded {
            sync::Response::ValueResponse(resp) => {
                assert_eq!(resp.height, Height(400));
                assert!(resp.value.is_none());
            }
        }
    }

    #[test]
    fn test_value_codec() {
        use reth_primitives_traits::serde_bincode_compat::{BincodeReprFor, SerdeBincodeCompat};

        // Test with bincode-compatible representation
        let block: reth_primitives::Block = Block::default();

        // Convert block to its bincode-compatible representation
        let block_repr: BincodeReprFor<'_, Block> = block.as_repr();

        // Try bincode serialization with the compatible representation
        match bincode::serialize(&block_repr) {
            Ok(bytes) => {
                println!("Block repr serialized to {} bytes", bytes.len());
                match bincode::deserialize::<BincodeReprFor<'_, Block>>(&bytes) {
                    Ok(decoded_repr) => {
                        println!("Block repr deserialization successful!");
                        // Convert back to Block
                        let decoded_block = Block::from_repr(decoded_repr);
                        assert_eq!(block, decoded_block);
                    }
                    Err(e) => {
                        println!("Block repr deserialization failed: {e:?}");
                        return;
                    }
                }
            }
            Err(e) => {
                println!("Block repr serialization failed: {e:?}");
                return;
            }
        }

        // Test our codec with the updated encode/decode functions
        let value = Value::from(&block);
        let codec = ProtoCodec;

        let encoded = codec.encode(&value).unwrap();
        println!("Codec encoded {} bytes", encoded.len());

        let decoded: Value = codec.decode(encoded).unwrap();
        println!("Successfully decoded value");
        assert_eq!(value.hash(), decoded.hash());
    }
}
