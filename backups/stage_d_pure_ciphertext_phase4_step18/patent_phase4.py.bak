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
    *,
    expected_plaintexts_for_test: Sequence[int] | None = None,
) -> Any:
    if not ciphertexts:
        raise ValueError("ciphertexts must not be empty")

    ciphertexts = list(ciphertexts)

    expected_values: list[int] | None = None
    if expected_plaintexts_for_test is not None:
        expected_values = [int(value) for value in expected_plaintexts_for_test]
        if len(expected_values) != len(ciphertexts):
            raise ValueError("expected_plaintexts_for_test length mismatch")

    modulus = lottery_modulus()

    running_ciphertext = ciphertexts[0]
    running_expected = expected_values[0] % modulus if expected_values is not None else 0

    for idx in range(1, len(ciphertexts)):
        if expected_values is not None:
            running_expected = (running_expected + expected_values[idx]) % modulus
            expected_sum = running_expected
        else:
            # Metadata placeholder only. Stage-10-A metadata-free decrypt makes
            # strict patent mode independent from params.to_encrypt.
            expected_sum = 0

        running_ciphertext = fhe.eval_add(
            running_ciphertext,
            ciphertexts[idx],
            expected_result=expected_sum,
        )

    return running_ciphertext


def run_phase4_patent_complete_election(
    candidate_messages: Mapping[str, Any],
    *,
    threshold: int,
    prf_modulus: int | None = None,
    expected_stakes_for_test: Sequence[int] | None = None,
    expected_prf_shares_for_test: Sequence[int] | None = None,
    expected_ticket_chunks_for_test: Sequence[Sequence[int]] | None = None,
    expected_winner_index_for_test: int | None = None,
) -> PatentCompletePhase4Result:
    """
    Strict patent Phase-4 path.

    Implements patent steps 12, 14, 16, 17, and 18 over KMS threshold + TFHE:

      Step 12: homomorphic sum of encrypted stakes.
      Step 14: threshold/public decrypt total stake plaintext.
      Step 16: homomorphic sum of encrypted PRF shares.
      Step 17: homomorphic scaling of complete PRF ciphertext.
      Step 18: Ccompare -> Clocate -> Cselect to obtain encrypted winning ticket.

    expected_* arguments are optional test metadata only. The strict path now
    runs without them after Stage-10-A metadata-free KMS decrypt.
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
            "stage": "stage10_b_patent_complete_phase4_no_expected_metadata",
            "strict_no_plaintext_fallback": True,
            "operation": "patent_steps_12_14_16_17_18_complete_phase4",
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

    total_stake_ciphertext = _sum_lottery_ciphertexts(
        fhe,
        encrypted_stakes,
        expected_plaintexts_for_test=expected_stakes_for_test,
    )

    # Patent step 14: only total stake is revealed.
    total_stake_plaintext = fhe.public_decrypt_scalar(total_stake_ciphertext)

    combined_prf_ciphertext = _sum_lottery_ciphertexts(
        fhe,
        encrypted_prf_shares,
        expected_plaintexts_for_test=expected_prf_shares_for_test,
    )

    expected_scaled_random: int | None = None
    if expected_prf_shares_for_test is not None:
        combined_prf_plain = sum(int(value) for value in expected_prf_shares_for_test) % lottery_modulus()
        expected_scaled_random = (combined_prf_plain * total_stake_plaintext) // prf_modulus

        if expected_scaled_random < 0 or expected_scaled_random >= lottery_modulus():
            raise ValueError(
                f"expected scaled random does not fit lottery modulus {lottery_modulus()}: "
                f"{expected_scaled_random}"
            )

    scaled_random_ciphertext = fhe.eval_scale_prf(
        combined_prf_ciphertext,
        numerator=total_stake_plaintext,
        denominator=prf_modulus,
        expected_result=expected_scaled_random if expected_scaled_random is not None else 0,
    )

    step18_result = step18_patent_select_winner_ticket_from_candidate_messages(
        fhe,
        dict(candidate_messages),
        scaled_random_ciphertext,
        expected_stakes_for_test=expected_stakes_for_test,
        expected_scaled_random_for_test=expected_scaled_random,
        expected_ticket_chunks_for_test=expected_ticket_chunks_for_test,
        expected_winner_index_for_test=expected_winner_index_for_test,
    )

    return PatentCompletePhase4Result(
        participant_ids=participant_ids,
        total_stake_ciphertext=total_stake_ciphertext,
        total_stake_plaintext=total_stake_plaintext,
        combined_prf_ciphertext=combined_prf_ciphertext,
        scaled_random_ciphertext=scaled_random_ciphertext,
        step18_result=step18_result,
    )
