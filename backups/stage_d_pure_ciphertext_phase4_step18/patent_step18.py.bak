from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from pos.crypto.patent_widths import lottery_modulus


@dataclass(frozen=True)
class PatentStep18WinnerSelectionResult:
    participant_ids: list[str]
    cumulative_stake_ciphertexts: list[Any]
    compare_bits: list[Any]
    winner_onehot_flags: list[Any]
    winning_ticket_ciphertext: list[Any]

    # 测试/验收辅助字段；生产路径最终会在 Stage-10 清理 metadata 依赖。
    expected_cumulative_stakes: list[int] | None = None
    expected_compare_bits: list[int] | None = None
    expected_winner_index: int | None = None
    expected_winning_ticket_chunks: list[int] | None = None


def _validate_rectangular_ticket_chunks(
    encrypted_ticket_chunks_by_participant: Sequence[Sequence[Any]],
) -> int:
    if not encrypted_ticket_chunks_by_participant:
        raise ValueError("encrypted_ticket_chunks_by_participant must not be empty")

    first_len = len(encrypted_ticket_chunks_by_participant[0])
    if first_len == 0:
        raise ValueError("ticket chunk list must not be empty")

    for idx, chunks in enumerate(encrypted_ticket_chunks_by_participant):
        if len(chunks) != first_len:
            raise ValueError(
                f"participant ticket chunk count mismatch at index {idx}: "
                f"got {len(chunks)}, expected {first_len}"
            )

    return first_len


def _select_one_chunk_by_onehot(
    fhe: Any,
    onehot_flags: Sequence[Any],
    chunk_ciphertexts: Sequence[Any],
    *,
    expected_winner_index: int,
    expected_chunk_values: Sequence[int] | None,
) -> Any:
    if len(onehot_flags) != len(chunk_ciphertexts):
        raise ValueError("onehot_flags length must match chunk_ciphertexts length")

    selected = chunk_ciphertexts[0]

    if expected_chunk_values is None:
        selected_expected = 0
    else:
        selected_expected = int(expected_chunk_values[0])

    for idx in range(1, len(chunk_ciphertexts)):
        if expected_chunk_values is not None and idx == expected_winner_index:
            selected_expected = int(expected_chunk_values[idx])

        selected = fhe.eval_select(
            onehot_flags[idx],
            chunk_ciphertexts[idx],
            selected,
            expected_result=selected_expected,
        )

    return selected


def step18_patent_select_winner_ticket(
    fhe: Any,
    participant_ids: Sequence[str],
    encrypted_stakes: Sequence[Any],
    scaled_random_ciphertext: Any,
    encrypted_ticket_chunks_by_participant: Sequence[Sequence[Any]],
    *,
    expected_stakes_for_test: Sequence[int] | None = None,
    expected_scaled_random_for_test: int | None = None,
    expected_ticket_chunks_for_test: Sequence[Sequence[int]] | None = None,
    expected_winner_index_for_test: int | None = None,
) -> PatentStep18WinnerSelectionResult:
    """
    Patent step-18 implementation over KMS threshold + TFHE ciphertexts.

    Computes:
      1. encrypted cumulative stakes
      2. Ccompare(scaled_random, cumulative_stakes)
      3. Clocate(first true compare bit)
      4. Cselect over encrypted ticket chunks

    No plaintext fallback is used for the encrypted computation. The expected_*
    arguments are only used to populate current KMS decrypt-validation metadata
    during Stage-9 tests.
    """

    participant_ids = list(participant_ids)
    encrypted_stakes = list(encrypted_stakes)
    encrypted_ticket_chunks_by_participant = [
        list(chunks)
        for chunks in encrypted_ticket_chunks_by_participant
    ]

    if not participant_ids:
        raise ValueError("participant_ids must not be empty")

    if len(encrypted_stakes) != len(participant_ids):
        raise ValueError(
            f"encrypted_stakes length {len(encrypted_stakes)} does not match "
            f"participant count {len(participant_ids)}"
        )

    if len(encrypted_ticket_chunks_by_participant) != len(participant_ids):
        raise ValueError(
            "encrypted_ticket_chunks_by_participant length does not match participant count"
        )

    ticket_chunk_count = _validate_rectangular_ticket_chunks(
        encrypted_ticket_chunks_by_participant
    )

    expected_stakes: list[int] | None = None
    expected_cumulative: list[int] | None = None
    expected_compare_bits: list[int] | None = None
    expected_ticket_chunks: list[list[int]] | None = None
    expected_winning_ticket_chunks: list[int] | None = None

    if expected_stakes_for_test is not None:
        expected_stakes = [int(value) for value in expected_stakes_for_test]
        if len(expected_stakes) != len(participant_ids):
            raise ValueError("expected_stakes_for_test length mismatch")

        expected_cumulative = []
        running = 0
        modulus = lottery_modulus()
        for stake in expected_stakes:
            running = (running + stake) % modulus
            expected_cumulative.append(running)

    if expected_scaled_random_for_test is not None and expected_cumulative is not None:
        expected_compare_bits = [
            1 if int(expected_scaled_random_for_test) < cumulative else 0
            for cumulative in expected_cumulative
        ]

    if expected_winner_index_for_test is None:
        if expected_compare_bits is None:
            expected_winner_index = 0
        else:
            try:
                expected_winner_index = expected_compare_bits.index(1)
            except ValueError as exc:
                raise ValueError(
                    "expected compare bits contain no winning true bit; "
                    "scaled random must be below total stake"
                ) from exc
    else:
        expected_winner_index = int(expected_winner_index_for_test)

    if expected_winner_index < 0 or expected_winner_index >= len(participant_ids):
        raise ValueError(f"expected_winner_index out of range: {expected_winner_index}")

    if expected_ticket_chunks_for_test is not None:
        expected_ticket_chunks = [
            [int(chunk) for chunk in chunks]
            for chunks in expected_ticket_chunks_for_test
        ]

        if len(expected_ticket_chunks) != len(participant_ids):
            raise ValueError("expected_ticket_chunks_for_test participant length mismatch")

        for idx, chunks in enumerate(expected_ticket_chunks):
            if len(chunks) != ticket_chunk_count:
                raise ValueError(
                    f"expected_ticket_chunks_for_test[{idx}] chunk count mismatch"
                )

        expected_winning_ticket_chunks = list(expected_ticket_chunks[expected_winner_index])

    # 1. 累加质押密文：cum_i = stake_0 + ... + stake_i
    cumulative_stake_ciphertexts: list[Any] = [encrypted_stakes[0]]
    running_ciphertext = encrypted_stakes[0]

    for idx in range(1, len(encrypted_stakes)):
        if expected_cumulative is None:
            expected_sum = 0
        else:
            expected_sum = expected_cumulative[idx]

        running_ciphertext = fhe.eval_add(
            running_ciphertext,
            encrypted_stakes[idx],
            expected_result=expected_sum,
        )
        cumulative_stake_ciphertexts.append(running_ciphertext)

    # 2. Ccompare：scaled_random < cumulative_stake_i
    compare_bits: list[Any] = []
    for idx, cumulative_ciphertext in enumerate(cumulative_stake_ciphertexts):
        if expected_compare_bits is None:
            expected_compare = False
        else:
            expected_compare = bool(expected_compare_bits[idx])

        compare_bits.append(
            fhe.eval_compare(
                scaled_random_ciphertext,
                cumulative_ciphertext,
                expected_result=expected_compare,
            )
        )

    # 3. Clocate：定位第一个 true，得到 one-hot winner flags
    winner_onehot_flags = fhe.eval_locate_first_true(
        compare_bits,
        expected_index=expected_winner_index,
    )

    # 4. Cselect：对每个 ticket chunk 做 one-hot 选择
    winning_ticket_ciphertext: list[Any] = []
    for chunk_index in range(ticket_chunk_count):
        chunk_ciphertexts = [
            encrypted_ticket_chunks_by_participant[participant_index][chunk_index]
            for participant_index in range(len(participant_ids))
        ]

        if expected_ticket_chunks is None:
            expected_chunk_values = None
        else:
            expected_chunk_values = [
                expected_ticket_chunks[participant_index][chunk_index]
                for participant_index in range(len(participant_ids))
            ]

        winning_chunk = _select_one_chunk_by_onehot(
            fhe,
            winner_onehot_flags,
            chunk_ciphertexts,
            expected_winner_index=expected_winner_index,
            expected_chunk_values=expected_chunk_values,
        )
        winning_ticket_ciphertext.append(winning_chunk)

    return PatentStep18WinnerSelectionResult(
        participant_ids=participant_ids,
        cumulative_stake_ciphertexts=cumulative_stake_ciphertexts,
        compare_bits=compare_bits,
        winner_onehot_flags=list(winner_onehot_flags),
        winning_ticket_ciphertext=winning_ticket_ciphertext,
        expected_cumulative_stakes=expected_cumulative,
        expected_compare_bits=expected_compare_bits,
        expected_winner_index=expected_winner_index,
        expected_winning_ticket_chunks=expected_winning_ticket_chunks,
    )


def _coerce_kms_ciphertext_handle(value: Any) -> Any:
    """
    Convert a candidate-message ciphertext field into a KMS threshold ciphertext handle.

    In the patent-complete strict path, candidate messages must carry real
    kms-threshold ciphertext handles or their JSON payloads. Legacy/mock
    ciphertext strings are intentionally rejected by construction here.
    """
    from pos.crypto.thfhe_backend.kms_fhe_backend import KmsThresholdCiphertextHandle

    if isinstance(value, KmsThresholdCiphertextHandle):
        return value

    if hasattr(value, "backend") and getattr(value, "backend") == "kms-threshold":
        return value

    if isinstance(value, str):
        import json

        try:
            payload = json.loads(value)
        except json.JSONDecodeError as exc:
            raise TypeError(
                "strict patent step18 requires kms-threshold ciphertext JSON; "
                f"got non-JSON ciphertext string prefix={value[:48]!r}"
            ) from exc

        if payload.get("backend") != "kms-threshold":
            raise TypeError(
                "strict patent step18 requires backend='kms-threshold'; "
                f"got {payload.get('backend')!r}"
            )

        return KmsThresholdCiphertextHandle(
            backend=payload["backend"],
            key_id=payload["key_id"],
            data_type=payload["data_type"],
            ciphertext_path=payload["ciphertext_path"],
            ciphertext_id=payload["ciphertext_id"],
        )

    raise TypeError(
        "strict patent step18 requires a KmsThresholdCiphertextHandle or JSON payload; "
        f"got {type(value).__name__}"
    )


def step18_patent_select_winner_ticket_from_candidate_messages(
    fhe: Any,
    candidate_messages: dict[str, Any],
    scaled_random_ciphertext: Any,
    *,
    expected_stakes_for_test: Sequence[int] | None = None,
    expected_scaled_random_for_test: int | None = None,
    expected_ticket_chunks_for_test: Sequence[Sequence[int]] | None = None,
    expected_winner_index_for_test: int | None = None,
) -> PatentStep18WinnerSelectionResult:
    """
    Candidate-message adapter for patent step 18.

    Reads:
      - message.encrypted_stake
      - message.encrypted_ticket

    Computes:
      encrypted cumulative stakes
      Ccompare(scaled_random, cumulative_stakes)
      Clocate(first true)
      Cselect(encrypted_ticket_chunks)

    This is the function that Stage-9.5 will call from the strict
    POS_STRICT_PATENT_MODE=1 phase-4 path.
    """
    if not candidate_messages:
        raise ValueError("candidate_messages must not be empty")

    participant_ids = list(candidate_messages.keys())

    encrypted_stakes = []
    encrypted_ticket_chunks_by_participant = []

    for participant_id in participant_ids:
        message = candidate_messages[participant_id]

        if not hasattr(message, "encrypted_stake"):
            raise TypeError(f"candidate message {participant_id!r} has no encrypted_stake")

        if not hasattr(message, "encrypted_ticket"):
            raise TypeError(f"candidate message {participant_id!r} has no encrypted_ticket")

        encrypted_stakes.append(
            _coerce_kms_ciphertext_handle(message.encrypted_stake)
        )

        encrypted_ticket_chunks_by_participant.append(
            [
                _coerce_kms_ciphertext_handle(chunk)
                for chunk in message.encrypted_ticket
            ]
        )

    scaled_random_handle = _coerce_kms_ciphertext_handle(scaled_random_ciphertext)

    return step18_patent_select_winner_ticket(
        fhe,
        participant_ids,
        encrypted_stakes,
        scaled_random_handle,
        encrypted_ticket_chunks_by_participant,
        expected_stakes_for_test=expected_stakes_for_test,
        expected_scaled_random_for_test=expected_scaled_random_for_test,
        expected_ticket_chunks_for_test=expected_ticket_chunks_for_test,
        expected_winner_index_for_test=expected_winner_index_for_test,
    )
