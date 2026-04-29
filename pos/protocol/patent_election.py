from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from pos.patent_fhe import PatentFheLeaderProtocolResult, run_patent_fhe_leader_election


@dataclass(frozen=True)
class PatentPhase4ElectionResult:
    participant_ids: list[str]
    encrypted_scores: list[Any]
    encrypted_winner_flags: list[Any]
    expected_index: int | None = None
    test_user_bits: list[int] | None = None
    test_public_bits: list[int] | None = None

    def encrypted_winner_flags_json(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for participant_id, flag in zip(self.participant_ids, self.encrypted_winner_flags):
            if hasattr(flag, "to_json"):
                encrypted_flag = flag.to_json()
            else:
                encrypted_flag = repr(flag)

            rows.append(
                {
                    "participant_id": participant_id,
                    "encrypted_winner_flag": encrypted_flag,
                }
            )
        return rows


def _candidate_participant_ids(candidate_messages: Mapping[str, Any]) -> list[str]:
    participant_ids = list(candidate_messages.keys())
    if not participant_ids:
        raise ValueError("candidate_messages must not be empty")
    return participant_ids


def run_phase4_patent_fhe_election(
    candidate_messages: Mapping[str, Any],
    scores: Sequence[int],
    *,
    threshold: int,
    expected_index_for_test: int | None = None,
    decrypt_for_test: bool = False,
) -> PatentPhase4ElectionResult:
    """
    Patent FHE Phase-4 election path.

    This is the protocol-layer bridge from existing PoS candidate messages into
    the real KMS threshold + TFHE leader election path.

    Stage-9.3 uses explicit scores so the wiring is testable and deterministic.
    Stage-9.4 will replace this score input with the project ticket/PRF-derived
    hidden score source.
    """

    participant_ids = _candidate_participant_ids(candidate_messages)

    if len(scores) != len(participant_ids):
        raise ValueError(
            f"scores length {len(scores)} does not match candidate count {len(participant_ids)}"
        )

    result: PatentFheLeaderProtocolResult = run_patent_fhe_leader_election(
        participant_ids,
        list(scores),
        threshold=threshold,
        expected_index_for_test=expected_index_for_test,
        decrypt_for_test=decrypt_for_test,
        setup_params={
            "stage": "stage9_3_patent_phase4_election",
            "strict_no_plaintext_fallback": True,
            "operation": "phase4_secret_leader_election",
            "backend": "kms-threshold",
        },
    )

    return PatentPhase4ElectionResult(
        participant_ids=list(result.participant_ids),
        encrypted_scores=list(result.encrypted_scores),
        encrypted_winner_flags=list(result.encrypted_onehot_flags),
        expected_index=result.expected_index,
        test_user_bits=result.test_user_bits,
        test_public_bits=result.test_public_bits,
    )
