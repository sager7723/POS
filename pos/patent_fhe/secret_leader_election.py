from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from pos.crypto.fhe import initialize_fhe_backend


@dataclass(frozen=True)
class FheLeaderElectionResult:
    participant_ids: list[str]
    encrypted_scores: list[Any]
    onehot_flags: list[Any]
    expected_index: int | None = None

    def onehot_summary(self) -> list[dict[str, Any]]:
        summary: list[dict[str, Any]] = []
        for participant_id, flag in zip(self.participant_ids, self.onehot_flags):
            if hasattr(flag, "to_json"):
                payload = flag.to_json()
            else:
                payload = repr(flag)

            summary.append(
                {
                    "participant_id": participant_id,
                    "encrypted_flag": payload,
                }
            )
        return summary


class PatentFheLeaderElection:
    """
    Patent-stage PoS FHE leader election adapter.

    This class is the PoS-side protocol entry for:
      - encrypting private stake/ticket/rank scores as euint8 ciphertexts
      - locating the deterministic encrypted winner with TFHE argmin
      - returning one-hot encrypted ebool leader flags

    No plaintext fallback is used for compare/select/locate.
    expected_index is test metadata only while kms-core-client still validates
    decrypt-from-file outputs against CipherWithParams.params.to_encrypt.
    """

    def __init__(
        self,
        participant_ids: Sequence[str],
        *,
        threshold: int,
        setup_params: dict[str, Any] | None = None,
    ) -> None:
        if not participant_ids:
            raise ValueError("participant_ids must not be empty")

        self.participant_ids = list(participant_ids)
        self.threshold = threshold

        self.fhe = initialize_fhe_backend(
            participant_ids=self.participant_ids,
            threshold=threshold,
        )

        self.fhe.setup(
            setup_params
            or {
                "stage": "stage9_1_patent_fhe_leader_entry",
                "strict_no_plaintext_fallback": True,
                "operation": "patent_fhe_secret_leader_election_entry",
            }
        )

    def encrypt_scores(self, scores: Sequence[int]) -> list[Any]:
        if len(scores) != len(self.participant_ids):
            raise ValueError(
                f"scores length {len(scores)} does not match participant count "
                f"{len(self.participant_ids)}"
            )

        encrypted_scores: list[Any] = []
        for idx, score in enumerate(scores):
            if score < 0 or score > 255:
                raise ValueError(
                    f"score[{idx}]={score} does not fit current euint8 Stage-9.1 path"
                )

            encrypted_scores.append(
                self.fhe.encrypt_scalar(
                    int(score),
                    data_type="euint8",
                    no_compression=True,
                    no_precompute_sns=True,
                )
            )

        return encrypted_scores

    def locate_leader_from_encrypted_scores(
        self,
        encrypted_scores: Sequence[Any],
        *,
        expected_index: int | None = None,
    ) -> FheLeaderElectionResult:
        if len(encrypted_scores) != len(self.participant_ids):
            raise ValueError(
                f"encrypted_scores length {len(encrypted_scores)} does not match "
                f"participant count {len(self.participant_ids)}"
            )

        if expected_index is not None:
            if expected_index < 0 or expected_index >= len(self.participant_ids):
                raise ValueError(f"expected_index out of range: {expected_index}")

        onehot_flags = self.fhe.eval_locate(
            list(encrypted_scores),
            expected_index=expected_index,
        )

        return FheLeaderElectionResult(
            participant_ids=self.participant_ids,
            encrypted_scores=list(encrypted_scores),
            onehot_flags=list(onehot_flags),
            expected_index=expected_index,
        )

    def elect_from_plain_scores_for_test(
        self,
        scores: Sequence[int],
        *,
        expected_index: int,
    ) -> FheLeaderElectionResult:
        """
        Test helper only.

        Plain scores are used here only to create input ciphertexts and set
        decrypt validation metadata. The leader location itself is computed
        by TFHE eval_locate over encrypted scores.
        """
        encrypted_scores = self.encrypt_scores(scores)
        return self.locate_leader_from_encrypted_scores(
            encrypted_scores,
            expected_index=expected_index,
        )

    def decrypt_onehot_for_test(self, result: FheLeaderElectionResult) -> tuple[list[int], list[int]]:
        """
        Test helper only.

        Production protocol should consume encrypted one-hot flags directly
        until the final disclosure/verification phase.
        """
        user_bits = [self.fhe.user_decrypt_scalar(flag) for flag in result.onehot_flags]
        public_bits = [self.fhe.public_decrypt_scalar(flag) for flag in result.onehot_flags]
        return user_bits, public_bits
