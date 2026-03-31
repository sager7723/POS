from __future__ import annotations

from typing import List

from pos.crypto.secret_sharing import MockSecretSharing
from pos.models.stage3 import PublicProofShare


class MockProofShareGenerator:
    """
    对应专利步骤5、6、8中的证明分片生成。
    未在专利中确认：真实零知识证明语句与验证关系式。
    当前实现仅保留“生成可揭示的 proof_share 集合”这一结构。
    """

    def __init__(self) -> None:
        self._secret_sharing = MockSecretSharing()

    def build_proof_shares(
        self,
        secret_label: str,
        secret_value: str,
        proof_share_count: int,
    ) -> List[PublicProofShare]:
        raw_shares = self._secret_sharing.share_secret(
            secret=f"{secret_label}:{secret_value}",
            n=proof_share_count,
        )
        return [
            PublicProofShare(
                share_index=index + 1,
                proof_share=f"{secret_label}_proof({raw_share})",
            )
            for index, raw_share in enumerate(raw_shares)
        ]

    def build_share_public_keys(
        self,
        participant_id: str,
        proof_share_count: int,
    ) -> List[str]:
        return [
            f"proof_share_public_key({participant_id},share_index={index + 1})"
            for index in range(proof_share_count)
        ]