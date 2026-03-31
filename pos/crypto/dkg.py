from __future__ import annotations

from typing import Dict, List

from pos.crypto.fhe import MockThresholdFHE
from pos.models.common import PublicParameters
from pos.models.stage2 import (
    DecryptKeyShare,
    DistributedKeyGenerationResult,
    Participant,
    SharePublicKey,
)


class MockDistributedKeyGenerator:
    """
    对应专利步骤2：分布式生成完整公钥、解密密钥分片、分片公钥。
    这里是 mock 实现，只提供显式输入输出与后续阶段可复用的数据结构。
    未在专利中确认：真实 DKG 协议的交互细节与安全机制。
    """

    def __init__(self, fhe: MockThresholdFHE) -> None:
        self._fhe = fhe

    def distributed_keygen(
        self,
        pp: PublicParameters,
        threshold: int,
        participants: List[Participant],
    ) -> DistributedKeyGenerationResult:
        participant_count: int = len(participants)
        public_key, secret_key_fragments = self._fhe.keygen(
            pp=pp,
            t=threshold,
            n=participant_count,
        )

        decrypt_key_shares: Dict[str, DecryptKeyShare] = {}
        share_public_keys: Dict[str, SharePublicKey] = {}

        for participant, secret_key_fragment in zip(participants, secret_key_fragments):
            decrypt_key_share = DecryptKeyShare(
                participant_id=participant.participant_id,
                decrypt_share_key=str(secret_key_fragment),
            )
            share_public_key = SharePublicKey(
                participant_id=participant.participant_id,
                share_public_key=f"share_pk({participant.participant_id}:{secret_key_fragment})",
            )
            decrypt_key_shares[participant.participant_id] = decrypt_key_share
            share_public_keys[participant.participant_id] = share_public_key

        return DistributedKeyGenerationResult(
            public_key=str(public_key),
            decrypt_key_shares=decrypt_key_shares,
            share_public_keys=share_public_keys,
        )