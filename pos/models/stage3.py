from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from pos.models.stage2 import Participant, StakeCommitment


@dataclass(frozen=True)
class PRFShare:
    participant_id: str
    key_share_scalar: int
    secret_vector: tuple[int, ...]
    input_bits_length: int
    public_vector_digest: str
    prf_share_value: int
    prf_share: str


@dataclass(frozen=True)
class PublicProofShare:
    share_index: int
    proof_share: str


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
    encrypted_ticket_suffix: str
    ticket_proof_shares: List[PublicProofShare]


@dataclass(frozen=True)
class CandidateMessage:
    participant_id: str
    stake_commitment: StakeCommitment
    encrypted_stake: str
    encrypted_prf_share: str
    encrypted_ticket: str
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