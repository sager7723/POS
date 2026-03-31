from __future__ import annotations

import hashlib

from pos.models.common import PublicParameters
from pos.models.stage2 import Participant
from pos.models.stage3 import PRFShare


class MockKeyHomomorphicPRF:
    """
    对应专利步骤4。
    这里只保留“基于随机种子和参与者生成伪随机数分片”的接口语义。
    未在专利中确认：Flwe 的具体矩阵构造与工程实现。
    """

    def generate_prf_share(
        self,
        pp: PublicParameters,
        participant: Participant,
        random_seed: str,
    ) -> PRFShare:
        payload = (
            f"prf|participant={participant.participant_id}"
            f"|stake={participant.stake_value}"
            f"|seed={random_seed}|m={pp.m}|k={pp.k}"
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return PRFShare(
            participant_id=participant.participant_id,
            prf_share=f"prf_share({digest})",
        )