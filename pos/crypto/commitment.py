from __future__ import annotations

import secrets
from dataclasses import dataclass

from pos.models.common import PublicParameters


@dataclass(frozen=True)
class CommitmentOpening:
    stake_value: int
    commit_randomness: int


class MockPedersenCommitment:
    """
    对应专利步骤1中的 Pedersen 承诺。
    这里使用 mock 表示，不实现真实群运算。
    未在专利中确认：项目工程中具体的 Pedersen 底层实现方式。
    """

    def commit(self, pp: PublicParameters, stake_value: int) -> tuple[str, int]:
        commit_randomness: int = secrets.randbelow(pp.q - 1) + 1
        commitment: str = (
            f"pedersen_commit("
            f"stake={stake_value},"
            f"rand={commit_randomness},"
            f"g={pp.g},h={pp.h})"
        )
        return commitment, commit_randomness

    def verify_commitment(
        self,
        pp: PublicParameters,
        commitment: str,
        opening: CommitmentOpening,
    ) -> bool:
        expected_commitment: str = (
            f"pedersen_commit("
            f"stake={opening.stake_value},"
            f"rand={opening.commit_randomness},"
            f"g={pp.g},h={pp.h})"
        )
        return commitment == expected_commitment