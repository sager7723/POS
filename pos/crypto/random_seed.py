from __future__ import annotations

import secrets
from typing import Dict, List

from pos.models.common import PublicParameters
from pos.models.stage2 import Participant, RandomSeedContribution
from pos.spec import encode_length_prefixed_bytes, get_hash_function, int_to_fixed_length_bytes


class RandomSeedGenerator:
    """
    对应专利步骤3 / 步骤9：分布式生成随机种子。

    第0层规范在这里落成三个工程决策：
    1. 随机值统一在 Z_q^* 中取样；
    2. 聚合前先按 participant_id 排序；
    3. 聚合消息采用长度前缀 + 固定字节序编码，再使用 pp.hash_name 哈希。

    这里仍未引入真正的 commit-reveal 广播轮，但哈希输入格式、字节序和哈希函数已经固定，
    后续把网络协议补上时不用再改数据格式。
    """

    def generate_contribution(
        self,
        pp: PublicParameters,
        participant: Participant,
    ) -> RandomSeedContribution:
        local_random_value = secrets.randbelow(pp.q - 1) + 1
        return RandomSeedContribution(
            participant_id=participant.participant_id,
            local_random_value=local_random_value,
        )

    def combine_contributions(
        self,
        pp: PublicParameters,
        contributions: List[RandomSeedContribution],
    ) -> str:
        sorted_contributions = sorted(contributions, key=lambda item: item.participant_id)
        payload = bytearray()
        payload.extend(b"PSSLE-RANDOM-SEED")
        payload.extend(int_to_fixed_length_bytes(len(sorted_contributions), 4, pp.serialization_byte_order))

        for contribution in sorted_contributions:
            participant_bytes = contribution.participant_id.encode("utf-8")
            payload.extend(
                encode_length_prefixed_bytes(
                    participant_bytes,
                    pp.serialization_length_bytes,
                    pp.serialization_byte_order,
                )
            )
            contribution_bytes_len = max(1, (pp.q.bit_length() + 7) // 8)
            payload.extend(
                int_to_fixed_length_bytes(
                    contribution.local_random_value,
                    contribution_bytes_len,
                    pp.serialization_byte_order,
                )
            )

        digest = get_hash_function(pp.hash_name)(bytes(payload)).hexdigest()
        return digest

    def contributions_to_mapping(
        self,
        contributions: List[RandomSeedContribution],
    ) -> Dict[str, RandomSeedContribution]:
        return {contribution.participant_id: contribution for contribution in contributions}