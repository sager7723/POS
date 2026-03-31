from __future__ import annotations

import hashlib
import secrets
from typing import Dict, List

from pos.models.common import PublicParameters
from pos.models.stage2 import Participant, RandomSeedContribution


class MockRandomSeedGenerator:
    """
    对应专利步骤3：分布式生成随机种子。
    这里采用“各参与者本地随机值 + 拼接后哈希”的 mock 聚合方式。
    未在专利中确认：唯一指定的工程聚合算法。
    """

    def generate_contribution(
        self,
        pp: PublicParameters,
        participant: Participant,
    ) -> RandomSeedContribution:
        local_random_value: int = secrets.randbelow(pp.q - 1) + 1
        return RandomSeedContribution(
            participant_id=participant.participant_id,
            local_random_value=local_random_value,
        )

    def combine_contributions(
        self,
        contributions: List[RandomSeedContribution],
    ) -> str:
        sorted_contributions: List[RandomSeedContribution] = sorted(
            contributions,
            key=lambda item: item.participant_id,
        )
        payload: str = "|".join(
            f"{item.participant_id}:{item.local_random_value}"
            for item in sorted_contributions
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def contributions_to_mapping(
        self,
        contributions: List[RandomSeedContribution],
    ) -> Dict[str, RandomSeedContribution]:
        return {
            contribution.participant_id: contribution
            for contribution in contributions
        }