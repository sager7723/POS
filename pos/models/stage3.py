from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from pos.models.stage2 import Participant, StakeCommitment


@dataclass(frozen=True)
class PRFShare:
    """
    与当前 key_homomorphic_prf.py 保持一致的 PRF 分片数据结构。

    说明：
    - key_share_scalar / secret_vector / input_bits_length / public_vector_digest / prf_share_value
      是当前工程实现中为承载 KH-PRF 生成与后续验证而保留的字段；
      这些字段名与唯一编码方式未在专利中确认。
    """
    participant_id: str
    key_share_scalar: int
    secret_vector: Tuple[int, ...]
    input_bits_length: int
    public_vector_digest: str
    prf_share_value: int
    prf_share: str


@dataclass(frozen=True)
class PublicProofShare:
    share_index: int
    proof_share: str
    statement_type: str = ""
    statement_public_hash: str = ""
    proof_share_count: int = 0
    reveal_threshold: int = 0
    coefficient_commitments: Dict[str, List[str]] = field(default_factory=dict)
    share_commitment: str = ""
    share_public_key: str = ""
    relation_commitment: str = ""
    noise_estimate: int = 0
    noise_bound: int = 0
    statement_public_data: Dict[str, str] = field(default_factory=dict)
    revealed_share_values: Dict[str, int] = field(default_factory=dict)
    reveal_nonce: str = ""


@dataclass(frozen=True)
class EncryptedPRFShareArtifact:
    participant_id: str
    encrypted_prf_share: str
    proof_shares: List[PublicProofShare]
    share_public_key_set: List[str]


@dataclass(frozen=True)
class EncryptedStakeArtifact:
    participant_id: str
    encrypted_stake: str
    stake_ciphertext_proof_shares: List[PublicProofShare]
    commitment_consistency_proof_shares: List[PublicProofShare]


@dataclass(frozen=True)
class TicketArtifact:
    participant_id: str
    ticket_preimage: str
    ticket_hash: str
    ticket_hash_prefix: str
    ticket_hash_suffix: str
    ticket_hash_suffix_chunks: List[int]
    encrypted_ticket_suffix_chunks: List[str]
    ticket_proof_shares: List[PublicProofShare]


@dataclass(frozen=True)
class CandidateMessage:
    participant_id: str
    stake_commitment: StakeCommitment
    encrypted_stake: str
    encrypted_prf_share: str
    encrypted_ticket: List[str]
    prf_proof_shares: List[PublicProofShare]
    stake_ciphertext_proof_shares: List[PublicProofShare]
    commitment_consistency_proof_shares: List[PublicProofShare]
    ticket_proof_shares: List[PublicProofShare]
    prf_share_public_keys: List[str]
    ticket_hash_prefix: str


@dataclass(frozen=True)
class Phase3ParticipantArtifact:
    participant: Participant
    prf_share: PRFShare
    encrypted_prf_share_artifact: EncryptedPRFShareArtifact
    encrypted_stake_artifact: EncryptedStakeArtifact
    ticket_artifact: TicketArtifact
    candidate_message: CandidateMessage


@dataclass(frozen=True)
class Phase3Result:
    candidate_messages: Dict[str, CandidateMessage]
    participant_artifacts: List[Phase3ParticipantArtifact]