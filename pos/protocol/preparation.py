from __future__ import annotations

from typing import Dict, List

from pos.crypto.commitment import PedersenCommitment
from pos.crypto.dkg import MockDistributedKeyGenerator
from pos.crypto.fhe import MockThresholdFHE
from pos.crypto.random_seed import RandomSeedGenerator
from pos.models.common import PublicParameters
from pos.models.stage2 import (
    DistributedKeyGenerationResult,
    Participant,
    Phase2ParticipantArtifact,
    Phase2Result,
    RandomSeedCommitment,
    RandomSeedContribution,
    StakeCommitment,
)


def step1_generate_and_publish_stake_commitments(
    pp: PublicParameters,
    participants: List[Participant],
) -> Dict[str, StakeCommitment]:
    """
    对应专利步骤1：每个参与者生成并发布质押承诺 CM_i。
    """
    commitment_scheme = PedersenCommitment()
    commitments: Dict[str, StakeCommitment] = {}

    for participant in participants:
        commitment, commit_randomness = commitment_scheme.commit(
            pp=pp,
            stake_value=participant.stake_value,
        )
        commitments[participant.participant_id] = StakeCommitment(
            participant_id=participant.participant_id,
            stake_commitment=commitment,
            commit_randomness=commit_randomness,
        )

    return commitments


def step2_distributed_generate_keys(
    pp: PublicParameters,
    participants: List[Participant],
    threshold: int,
) -> DistributedKeyGenerationResult:
    """
    对应专利步骤2：分布式生成完整公钥、解密密钥分片、分片公钥。
    """
    fhe = MockThresholdFHE()
    dkg = MockDistributedKeyGenerator(fhe=fhe)
    return dkg.distributed_keygen(
        pp=pp,
        threshold=threshold,
        participants=participants,
    )


def step3_distributed_generate_random_seed(
    pp: PublicParameters,
    participants: List[Participant],
) -> tuple[str, Dict[str, RandomSeedCommitment], Dict[str, RandomSeedContribution]]:
    """
    对应专利步骤3：分布式生成随机种子。

    本版使用 commit-reveal：先为每方生成随机值承诺，再验证揭示并聚合成公共随机种子。
    """
    seed_generator = RandomSeedGenerator()
    commitments: List[RandomSeedCommitment] = []
    contributions: List[RandomSeedContribution] = []

    for participant in participants:
        commitment, contribution = seed_generator.generate_commitment_and_contribution(
            pp=pp,
            participant=participant,
        )
        commitments.append(commitment)
        contributions.append(contribution)

    random_seed = seed_generator.combine_contributions(
        pp=pp,
        commitments=commitments,
        contributions=contributions,
    )
    commitment_mapping = seed_generator.commitments_to_mapping(commitments)
    contribution_mapping = seed_generator.contributions_to_mapping(contributions)
    return random_seed, commitment_mapping, contribution_mapping


def run_phase2_preparation(
    pp: PublicParameters,
    participants: List[Participant],
    threshold: int,
) -> Phase2Result:
    """
    阶段2入口：
    - 步骤1：生成并发布质押承诺
    - 步骤2：分布式生成完整公钥/解密密钥分片/分片公钥
    - 步骤3：分布式生成随机种子
    """
    commitments = step1_generate_and_publish_stake_commitments(
        pp=pp,
        participants=participants,
    )
    distributed_key_result = step2_distributed_generate_keys(
        pp=pp,
        participants=participants,
        threshold=threshold,
    )
    random_seed, random_seed_commitments, random_seed_contributions = (
        step3_distributed_generate_random_seed(
            pp=pp,
            participants=participants,
        )
    )

    participant_artifacts: List[Phase2ParticipantArtifact] = []
    for participant in participants:
        participant_id = participant.participant_id
        participant_artifacts.append(
            Phase2ParticipantArtifact(
                participant=participant,
                stake_commitment=commitments[participant_id],
                decrypt_key_share=distributed_key_result.decrypt_key_shares[participant_id],
                share_public_key=distributed_key_result.share_public_keys[participant_id],
                random_seed_commitment=random_seed_commitments[participant_id],
                random_seed_contribution=random_seed_contributions[participant_id],
            )
        )

    return Phase2Result(
        commitments=commitments,
        distributed_key_result=distributed_key_result,
        random_seed=random_seed,
        random_seed_commitments=random_seed_commitments,
        random_seed_contributions=random_seed_contributions,
        participant_artifacts=participant_artifacts,
    )