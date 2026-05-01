from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence


@dataclass(frozen=True)
class PatentStep18WinnerSelectionResult:
    participant_ids: list[str]
    cumulative_stake_ciphertexts: list[Any]
    compare_bits: list[Any]
    winner_onehot_flags: list[Any]
    winning_ticket_ciphertext: list[Any]


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
) -> Any:
    if len(onehot_flags) != len(chunk_ciphertexts):
        raise ValueError("onehot_flags length must match chunk_ciphertexts length")

    selected = chunk_ciphertexts[0]

    for idx in range(1, len(chunk_ciphertexts)):
        selected = fhe.eval_select(
            onehot_flags[idx],
            chunk_ciphertexts[idx],
            selected,
        )

    return selected


def step18_patent_select_winner_ticket(
    fhe: Any,
    participant_ids: Sequence[str],
    encrypted_stakes: Sequence[Any],
    scaled_random_ciphertext: Any,
    encrypted_ticket_chunks_by_participant: Sequence[Sequence[Any]],
) -> PatentStep18WinnerSelectionResult:
    """
    Patent Step18 over KMS/TFHE ciphertexts only.

    Computes:
      1. encrypted cumulative stakes
      2. Ccompare(scaled_random, cumulative_stakes)
      3. Clocate(first true compare bit)
      4. Cselect over encrypted ticket chunks

    Strict rule:
      - only ciphertext inputs are accepted
      - no plaintext winner index is computed or returned
      - encrypted compare, locate, and select are performed by the FHE backend
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

    # 1. Cumulative encrypted stake:
    #    cum_i = stake_0 + ... + stake_i
    cumulative_stake_ciphertexts: list[Any] = [encrypted_stakes[0]]
    running_ciphertext = encrypted_stakes[0]

    for idx in range(1, len(encrypted_stakes)):
        running_ciphertext = fhe.eval_add(
            running_ciphertext,
            encrypted_stakes[idx],
        )
        cumulative_stake_ciphertexts.append(running_ciphertext)

    # 2. Ccompare:
    #    compare_i = scaled_random < cumulative_stake_i
    compare_bits: list[Any] = []
    for cumulative_ciphertext in cumulative_stake_ciphertexts:
        compare_bits.append(
            fhe.eval_compare(
                scaled_random_ciphertext,
                cumulative_ciphertext,
            )
        )

    # 3. Clocate:
    #    encrypted one-hot flags for first true compare bit.
    winner_onehot_flags = fhe.eval_locate_first_true(compare_bits)

    # 4. Cselect:
    #    select each encrypted ticket chunk by encrypted one-hot flags.
    winning_ticket_ciphertext: list[Any] = []
    for chunk_index in range(ticket_chunk_count):
        chunk_ciphertexts = [
            encrypted_ticket_chunks_by_participant[participant_index][chunk_index]
            for participant_index in range(len(participant_ids))
        ]

        winning_chunk = _select_one_chunk_by_onehot(
            fhe,
            winner_onehot_flags,
            chunk_ciphertexts,
        )
        winning_ticket_ciphertext.append(winning_chunk)

    return PatentStep18WinnerSelectionResult(
        participant_ids=participant_ids,
        cumulative_stake_ciphertexts=cumulative_stake_ciphertexts,
        compare_bits=compare_bits,
        winner_onehot_flags=list(winner_onehot_flags),
        winning_ticket_ciphertext=winning_ticket_ciphertext,
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
) -> PatentStep18WinnerSelectionResult:
    """
    Candidate-message adapter for patent Step18.

    Reads:
      - message.encrypted_stake
      - message.encrypted_ticket

    Computes:
      - encrypted cumulative stakes
      - Ccompare(scaled_random, cumulative_stakes)
      - Clocate(first true)
      - Cselect(encrypted_ticket_chunks)

    This adapter does not compute or return a plaintext winner index.
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
    )
