from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Participant:
    participant_id: str
    stake_value: int


@dataclass(frozen=True)
class StakeCommitment:
    participant_id: str
    stake_commitment: str
    commit_randomness: int


@dataclass(frozen=True)
class PolynomialCommitmentBroadcast:
    participant_id: str
    coefficient_commitments: List[str]


@dataclass(frozen=True)
class PrivateShareDelivery:
    sender_id: str
    recipient_id: str
    share_value: int


@dataclass(frozen=True)
class SharePublicKey:
    participant_id: str
    share_public_key: str


@dataclass(frozen=True)
class DecryptKeyShare:
    participant_id: str
    decrypt_share_key: int


@dataclass(frozen=True)
class DistributedKeyGenerationResult:
    public_key: str
    decrypt_key_shares: Dict[str, DecryptKeyShare]
    share_public_keys: Dict[str, SharePublicKey]
    polynomial_commitments: Dict[str, PolynomialCommitmentBroadcast]
    private_share_deliveries: Dict[str, Dict[str, PrivateShareDelivery]]
    threshold: int
    fhe_public_key: Optional[str] = None
    fhe_secret_key_handles: Optional[Dict[str, str]] = None
    fhe_backend_name: Optional[str] = None


@dataclass(frozen=True)
class RandomSeedCommitment:
    participant_id: str
    seed_commitment: str


@dataclass(frozen=True)
class RandomSeedContribution:
    participant_id: str
    local_random_value: int
    reveal_randomness: int


@dataclass(frozen=True)
class Phase2ParticipantArtifact:
    participant: Participant
    stake_commitment: StakeCommitment
    decrypt_key_share: DecryptKeyShare
    share_public_key: SharePublicKey
    random_seed_commitment: RandomSeedCommitment
    random_seed_contribution: RandomSeedContribution


@dataclass(frozen=True)
class Phase2Result:
    commitments: Dict[str, StakeCommitment]
    distributed_key_result: DistributedKeyGenerationResult
    random_seed: str
    random_seed_commitments: Dict[str, RandomSeedCommitment]
    random_seed_contributions: Dict[str, RandomSeedContribution]
    participant_artifacts: List[Phase2ParticipantArtifact]