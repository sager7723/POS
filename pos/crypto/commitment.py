from __future__ import annotations

import secrets
from dataclasses import dataclass

from pos.models.common import PublicParameters


@dataclass(frozen=True)
class CommitmentOpening:
    secret_value: int
    opening_randomness: int


class PedersenCommitment:
    """
    真实整数群 Pedersen 承诺：
        C = g^x * h^r mod p
    """

    @staticmethod
    def _normalize_secret(secret_value: int, q: int) -> int:
        if secret_value < 0:
            raise ValueError("secret_value must be non-negative")
        return secret_value % q

    def commit_value(
        self,
        pp: PublicParameters,
        secret_value: int,
        opening_randomness: int | None = None,
    ) -> tuple[str, int]:
        normalized_secret = self._normalize_secret(secret_value, pp.q)
        randomness = opening_randomness
        if randomness is None:
            randomness = secrets.randbelow(pp.q - 1) + 1
        randomness %= pp.q
        if randomness == 0:
            randomness = 1

        commitment_value = (
            pow(pp.g, normalized_secret, pp.p) * pow(pp.h, randomness, pp.p)
        ) % pp.p
        return f"pedersen_commit:0x{commitment_value:x}", randomness

    def verify_value(
        self,
        pp: PublicParameters,
        commitment: str,
        opening: CommitmentOpening,
    ) -> bool:
        expected_commitment, _ = self.commit_value(
            pp=pp,
            secret_value=opening.secret_value,
            opening_randomness=opening.opening_randomness,
        )
        return commitment == expected_commitment

    def commit(self, pp: PublicParameters, stake_value: int) -> tuple[str, int]:
        return self.commit_value(pp=pp, secret_value=stake_value)

    def verify_commitment(
        self,
        pp: PublicParameters,
        commitment: str,
        opening: CommitmentOpening,
    ) -> bool:
        return self.verify_value(pp=pp, commitment=commitment, opening=opening)


MockPedersenCommitment = PedersenCommitment