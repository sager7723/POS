from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


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
class SharePublicKey:
    participant_id: str
    share_public_key: str


@dataclass(frozen=True)
class DecryptKeyShare:
    participant_id: str
    decrypt_share_key: str


@dataclass(frozen=True)
class DistributedKeyGenerationResult:
    public_key: str
    decrypt_key_shares: Dict[str, DecryptKeyShare]
    share_public_keys: Dict[str, SharePublicKey]


@dataclass(frozen=True)
class RandomSeedContribution:
    participant_id: str
    local_random_value: int


@dataclass(frozen=True)
class Phase2ParticipantArtifact:
    participant: Participant
    stake_commitment: StakeCommitment
    decrypt_key_share: DecryptKeyShare
    share_public_key: SharePublicKey
    random_seed_contribution: RandomSeedContribution


@dataclass(frozen=True)
class Phase2Result:
    commitments: Dict[str, StakeCommitment]
    distributed_key_result: DistributedKeyGenerationResult
    random_seed: str
    random_seed_contributions: Dict[str, RandomSeedContribution]
    participant_artifacts: List[Phase2ParticipantArtifact]