from __future__ import annotations

import hashlib
import secrets
from typing import Dict, List

from pos.crypto.commitment import CommitmentOpening, PedersenCommitment
from pos.models.common import PublicParameters
from pos.models.stage2 import Participant, RandomSeedCommitment, RandomSeedContribution


class RandomSeedGenerator:
    """
    对应专利步骤3：分布式生成随机种子。

    本版改为真实 commit-reveal 流程：
    1. 每方在 Z_q^* 中选择随机值 s_i；
    2. 每方再选择独立开口随机数 r_i；
    3. 发布 Pedersen 承诺 C_i = g^{s_i} h^{r_i} mod p；
    4. 揭示 (s_i, r_i) 并逐个验证；
    5. 对全部验证通过的揭示值做有序聚合哈希，得到公共随机种子。
    """

    def __init__(self) -> None:
        self._commitment = PedersenCommitment()

    def generate_commitment_and_contribution(
        self,
        pp: PublicParameters,
        participant: Participant,
    ) -> tuple[RandomSeedCommitment, RandomSeedContribution]:
        local_random_value = secrets.randbelow(pp.q - 1) + 1
        seed_commitment, reveal_randomness = self._commitment.commit_value(
            pp=pp,
            secret_value=local_random_value,
        )
        return (
            RandomSeedCommitment(
                participant_id=participant.participant_id,
                seed_commitment=seed_commitment,
            ),
            RandomSeedContribution(
                participant_id=participant.participant_id,
                local_random_value=local_random_value,
                reveal_randomness=reveal_randomness,
            ),
        )

    def verify_reveal(
        self,
        pp: PublicParameters,
        commitment: RandomSeedCommitment,
        contribution: RandomSeedContribution,
    ) -> bool:
        if commitment.participant_id != contribution.participant_id:
            return False
        return self._commitment.verify_value(
            pp=pp,
            commitment=commitment.seed_commitment,
            opening=CommitmentOpening(
                secret_value=contribution.local_random_value,
                opening_randomness=contribution.reveal_randomness,
            ),
        )

    def combine_contributions(
        self,
        pp: PublicParameters,
        commitments: List[RandomSeedCommitment],
        contributions: List[RandomSeedContribution],
    ) -> str:
        commitment_map = {item.participant_id: item for item in commitments}
        contribution_map = {item.participant_id: item for item in contributions}
        if set(commitment_map.keys()) != set(contribution_map.keys()):
            raise ValueError("commitment set and contribution set must match")

        ordered_ids = sorted(contribution_map.keys())
        payload = bytearray()
        payload.extend(b"PSSLE-COMMIT-REVEAL-SEED")
        payload.extend(len(ordered_ids).to_bytes(4, "big"))

        field_length = max(1, (pp.q.bit_length() + 7) // 8)
        for participant_id in ordered_ids:
            commitment = commitment_map[participant_id]
            contribution = contribution_map[participant_id]
            if not self.verify_reveal(pp, commitment, contribution):
                raise ValueError(f"invalid reveal for participant {participant_id}")

            participant_bytes = participant_id.encode("utf-8")
            payload.extend(len(participant_bytes).to_bytes(4, "big"))
            payload.extend(participant_bytes)
            payload.extend(contribution.local_random_value.to_bytes(field_length, "big"))

        return hashlib.sha256(bytes(payload)).hexdigest()

    def commitments_to_mapping(
        self,
        commitments: List[RandomSeedCommitment],
    ) -> Dict[str, RandomSeedCommitment]:
        return {commitment.participant_id: commitment for commitment in commitments}

    def contributions_to_mapping(
        self,
        contributions: List[RandomSeedContribution],
    ) -> Dict[str, RandomSeedContribution]:
        return {contribution.participant_id: contribution for contribution in contributions}


MockRandomSeedGenerator = RandomSeedGenerator