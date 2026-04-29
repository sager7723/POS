from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from pos.patent_fhe import FheLeaderElectionResult, PatentFheLeaderElection


@dataclass(frozen=True)
class PatentFheLeaderProtocolResult:
    participant_ids: list[str]
    encrypted_scores: list[Any]
    encrypted_onehot_flags: list[Any]
    expected_index: int | None = None
    test_user_bits: list[int] | None = None
    test_public_bits: list[int] | None = None

    def encrypted_winner_flags_json(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for participant_id, flag in zip(self.participant_ids, self.encrypted_onehot_flags):
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


def run_patent_fhe_leader_election(
    participant_ids: Sequence[str],
    scores: Sequence[int],
    *,
    threshold: int,
    expected_index_for_test: int | None = None,
    decrypt_for_test: bool = False,
    setup_params: dict[str, Any] | None = None,
) -> PatentFheLeaderProtocolResult:
    """
    Protocol-level entry for patent FHE leader election.

    This is the PoS-facing adapter for the patent path:
      encrypted scores -> TFHE locate/argmin -> encrypted one-hot leader flags.

    scores are plaintext only at this boundary while Stage-9 is still wiring
    the protocol. The FHE election itself is computed over ciphertexts.
    In the final Stage-10 path, callers should pass already-derived encrypted
    scores or hidden stake/ticket commitments instead of test plaintext scores.
    """

    election = PatentFheLeaderElection(
        participant_ids,
        threshold=threshold,
        setup_params=setup_params
        or {
            "stage": "stage9_2_patent_fhe_protocol_entry",
            "strict_no_plaintext_fallback": True,
            "operation": "protocol_level_secret_leader_election",
        },
    )

    encrypted_scores = election.encrypt_scores(scores)

    result: FheLeaderElectionResult = election.locate_leader_from_encrypted_scores(
        encrypted_scores,
        expected_index=expected_index_for_test,
    )

    test_user_bits: list[int] | None = None
    test_public_bits: list[int] | None = None

    if decrypt_for_test:
        test_user_bits, test_public_bits = election.decrypt_onehot_for_test(result)

    return PatentFheLeaderProtocolResult(
        participant_ids=list(participant_ids),
        encrypted_scores=list(result.encrypted_scores),
        encrypted_onehot_flags=list(result.onehot_flags),
        expected_index=expected_index_for_test,
        test_user_bits=test_user_bits,
        test_public_bits=test_public_bits,
    )
