from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from pos.crypto.fhe import initialize_fhe_backend
from pos.crypto.patent_widths import lottery_modulus
from pos.protocol.patent_step18 import (
    PatentStep18WinnerSelectionResult,
    _coerce_kms_ciphertext_handle,
    step18_patent_select_winner_ticket_from_candidate_messages,
)


@dataclass(frozen=True)
class PatentCompletePhase4Result:
    participant_ids: list[str]
    total_stake_ciphertext: Any
    total_stake_plaintext: int
    combined_prf_ciphertext: Any
    scaled_random_ciphertext: Any
    step18_result: PatentStep18WinnerSelectionResult

    @property
    def winning_ticket_ciphertext(self) -> list[Any]:
        return self.step18_result.winning_ticket_ciphertext

    @property
    def winner_onehot_flags(self) -> list[Any]:
        return self.step18_result.winner_onehot_flags


def _participant_ids(candidate_messages: Mapping[str, Any]) -> list[str]:
    ids = list(candidate_messages.keys())
    if not ids:
        raise ValueError("candidate_messages must not be empty")
    return ids


def _sum_lottery_ciphertexts(
    fhe: Any,
    ciphertexts: Sequence[Any],
) -> Any:
    if not ciphertexts:
        raise ValueError("ciphertexts must not be empty")

    ciphertexts = list(ciphertexts)

    running_ciphertext = ciphertexts[0]

    for idx in range(1, len(ciphertexts)):
        running_ciphertext = fhe.eval_add(
            running_ciphertext,
            ciphertexts[idx],
        )

    return running_ciphertext


def run_phase4_patent_complete_election(
    candidate_messages: Mapping[str, Any],
    *,
    threshold: int,
    prf_modulus: int | None = None,
) -> PatentCompletePhase4Result:
    """
    Strict patent Phase4 path.

    Implements patent Steps 12, 14, 16, 17, and 18 over KMS threshold + TFHE:

      Step12: homomorphic sum of encrypted stakes.
      Step14: threshold/public decrypt total stake plaintext.
      Step16: homomorphic sum of encrypted PRF shares.
      Step17: homomorphic scaling of complete PRF ciphertext.
      Step18: Ccompare -> Clocate -> Cselect to obtain encrypted winning ticket.

    Strict rule:
      - only ciphertext inputs are accepted for Step12, Step16, Step17, and Step18
      - no plaintext winner index is computed or returned by Phase4
      - only total stake is revealed before ticket suffix recovery
    """

    if prf_modulus is None:
        prf_modulus = lottery_modulus()

    if prf_modulus <= 0:
        raise ValueError(f"prf_modulus must be positive, got {prf_modulus}")

    participant_ids = _participant_ids(candidate_messages)

    fhe = initialize_fhe_backend(
        participant_ids=participant_ids,
        threshold=threshold,
    )

    fhe.setup(
        {
            "stage": "stage_d_pure_ciphertext_phase4_step12_16_17_18",
            "strict_no_plaintext_fallback": True,
            "strict_pure_ciphertext_path": True,
            "operation": "patent_steps_12_14_16_17_18_pure_ciphertext",
            "backend": "kms-threshold",
        }
    )

    encrypted_stakes = []
    encrypted_prf_shares = []

    for participant_id in participant_ids:
        message = candidate_messages[participant_id]

        if not hasattr(message, "encrypted_stake"):
            raise TypeError(f"candidate message {participant_id!r} has no encrypted_stake")

        if not hasattr(message, "encrypted_prf_share"):
            raise TypeError(f"candidate message {participant_id!r} has no encrypted_prf_share")

        encrypted_stakes.append(_coerce_kms_ciphertext_handle(message.encrypted_stake))
        encrypted_prf_shares.append(_coerce_kms_ciphertext_handle(message.encrypted_prf_share))

    # Step12: encrypted stake sum.
    total_stake_ciphertext = _sum_lottery_ciphertexts(
        fhe,
        encrypted_stakes,
    )

    # Step14: only the total stake is revealed.
    total_stake_plaintext = fhe.public_decrypt_scalar(total_stake_ciphertext)

    # Step16: encrypted PRF share sum.
    combined_prf_ciphertext = _sum_lottery_ciphertexts(
        fhe,
        encrypted_prf_shares,
    )

    # Step17: encrypted PRF scaling by public total stake and PRF modulus.
    scaled_random_ciphertext = fhe.eval_scale_prf(
        combined_prf_ciphertext,
        numerator=total_stake_plaintext,
        denominator=prf_modulus,
    )

    # Step18: encrypted compare / locate / select.
    step18_result = step18_patent_select_winner_ticket_from_candidate_messages(
        fhe,
        dict(candidate_messages),
        scaled_random_ciphertext,
    )

    return PatentCompletePhase4Result(
        participant_ids=participant_ids,
        total_stake_ciphertext=total_stake_ciphertext,
        total_stake_plaintext=total_stake_plaintext,
        combined_prf_ciphertext=combined_prf_ciphertext,
        scaled_random_ciphertext=scaled_random_ciphertext,
        step18_result=step18_result,
    )
