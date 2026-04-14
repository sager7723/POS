from __future__ import annotations

import secrets
from dataclasses import dataclass

from pos.models.common import PublicParameters


@dataclass(frozen=True)
class CommitmentOpening:
    stake_value: int
    commit_randomness: int


class PedersenCommitment:
    """
    对应专利步骤1中的 Pedersen 承诺。

    在第0层规范固化后，这里直接落成真实的模素数群承诺：
        C = g^stake * h^r mod p
    返回值仍保留字符串外壳，便于与现有 CandidateMessage 结构兼容。
    """

    def commit(self, pp: PublicParameters, stake_value: int) -> tuple[str, int]:
        if stake_value < 0:
            raise ValueError("stake_value must be non-negative")
        commit_randomness = secrets.randbelow(pp.q - 1) + 1
        commitment_value = (
            pow(pp.g, stake_value, pp.p) * pow(pp.h, commit_randomness, pp.p)
        ) % pp.p
        return f"pedersen_commit:0x{commitment_value:x}", commit_randomness

    def verify_commitment(
        self,
        pp: PublicParameters,
        commitment: str,
        opening: CommitmentOpening,
    ) -> bool:
        expected_commitment, _ = self.commit_from_opening(pp, opening)
        return commitment == expected_commitment

    def commit_from_opening(
        self,
        pp: PublicParameters,
        opening: CommitmentOpening,
    ) -> tuple[str, int]:
        commitment_value = (
            pow(pp.g, opening.stake_value, pp.p) * pow(pp.h, opening.commit_randomness, pp.p)
        ) % pp.p
        return f"pedersen_commit:0x{commitment_value:x}", opening.commit_randomness