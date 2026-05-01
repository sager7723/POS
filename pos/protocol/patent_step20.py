from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from pos.models.common import PublicParameters
from pos.models.stage3 import Phase3ParticipantArtifact, TicketCipherLayout
from pos.models.stage4 import DecryptionShare, Phase4Result
from pos.spec import hash_bytes


@dataclass(frozen=True)
class PatentStep20TicketRecoveryResult:
    winner_participant_id: str
    decryption_shares_by_chunk: dict[int, list[DecryptionShare]]
    decrypted_ticket_chunks: list[int]
    ticket_hash_suffix: str
    ticket_hash: str
    ticket_preimage: str
    ticket_hash_prefix: str
    hash_matches_preimage: bool
    suffix_matches_candidate: bool
    hash_matches_candidate: bool


def _ciphertext_from_wire(fhe: Any, value: Any) -> Any:
    """
    Restore a public KMS ciphertext handle so Step19 can request threshold
    decryption shares. This function does not decrypt.
    """
    if not isinstance(value, str):
        return value

    if hasattr(fhe, "deserialize_ciphertext"):
        try:
            return fhe.deserialize_ciphertext(value)
        except Exception:
            pass

    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise ValueError("ciphertext wire value must decode to a JSON object")

    if payload.get("backend") != "kms-threshold":
        raise ValueError(f"unsupported ciphertext backend: {payload.get('backend')!r}")

    from pos.crypto.thfhe_backend.kms_fhe_backend import KmsThresholdCiphertextHandle

    return KmsThresholdCiphertextHandle(
        backend=str(payload["backend"]),
        key_id=str(payload["key_id"]),
        data_type=str(payload["data_type"]),
        ciphertext_path=str(payload["ciphertext_path"]),
        ciphertext_id=str(payload["ciphertext_id"]),
    )


def step19_generate_winning_ticket_decryption_shares(
    fhe: Any,
    *,
    participant_ids: Sequence[str],
    winning_ticket_ciphertext: Sequence[Any],
    layout: TicketCipherLayout,
) -> dict[int, list[DecryptionShare]]:
    """
    Patent Step19: generate threshold partial decrypt shares only for the
    Step18-selected encrypted winning ticket suffix chunks.
    """
    participant_ids = list(participant_ids)
    if not participant_ids:
        raise ValueError("participant_ids must not be empty")

    if len(winning_ticket_ciphertext) != layout.chunk_count:
        raise ValueError(
            "winning_ticket_ciphertext chunk count does not match public ticket layout"
        )

    shares_by_chunk: dict[int, list[DecryptionShare]] = {}

    for chunk_index, wire_value in enumerate(winning_ticket_ciphertext):
        ciphertext = _ciphertext_from_wire(fhe, wire_value)
        shares_by_chunk[chunk_index] = [
            DecryptionShare(
                participant_id=participant_id,
                share=fhe.decrypt_share(
                    participant_id=participant_id,
                    ciphertext=ciphertext,
                ),
            )
            for participant_id in participant_ids
        ]

    return shares_by_chunk


def step20_recover_winning_ticket_chunks(
    fhe: Any,
    *,
    winning_ticket_ciphertext: Sequence[Any],
    decryption_shares_by_chunk: dict[int, list[DecryptionShare]],
    layout: TicketCipherLayout,
) -> list[int]:
    """
    Patent Step20: combine Step19 threshold shares to recover only the selected
    winning ticket suffix chunks.
    """
    if layout.chunk_bit_width != 16:
        raise ValueError(
            f"Step20 expects euint16 ticket chunks, got {layout.chunk_bit_width}"
        )

    if len(winning_ticket_ciphertext) != layout.chunk_count:
        raise ValueError(
            "winning_ticket_ciphertext chunk count does not match public ticket layout"
        )

    modulus = int(layout.chunk_modulus)
    recovered_chunks: list[int] = []

    for chunk_index, wire_value in enumerate(winning_ticket_ciphertext):
        if chunk_index not in decryption_shares_by_chunk:
            raise ValueError(f"missing decryption shares for winning chunk {chunk_index}")

        ciphertext = _ciphertext_from_wire(fhe, wire_value)
        share_strings = [
            share.share
            for share in decryption_shares_by_chunk[chunk_index]
        ]
        recovered_value = int(
            fhe.decrypt(
                ciphertext=ciphertext,
                shares=share_strings,
            )
        )

        if recovered_value < 0 or recovered_value >= modulus:
            raise ValueError(
                f"recovered ticket chunk {chunk_index} out of range for modulus {modulus}: "
                f"{recovered_value}"
            )

        recovered_chunks.append(recovered_value)

    return recovered_chunks


def recover_ticket_hash_suffix(
    decrypted_ticket_chunks: Sequence[int],
    layout: TicketCipherLayout,
) -> str:
    """
    Patent Step20: reconstruct the ticket hash suffix from recovered chunks.
    """
    if layout.recovery_format != "hex_concat":
        raise ValueError(f"unsupported ticket recovery format: {layout.recovery_format!r}")

    hex_width = int(layout.hex_chars_per_chunk)
    if hex_width <= 0:
        raise ValueError(f"invalid hex_chars_per_chunk: {hex_width}")

    if len(decrypted_ticket_chunks) != layout.chunk_count:
        raise ValueError(
            "recovered chunk count does not match public ticket layout"
        )

    chunk_max = 1 << int(layout.chunk_bit_width)
    parts: list[str] = []

    for idx, chunk in enumerate(decrypted_ticket_chunks):
        chunk = int(chunk)
        if chunk < 0 or chunk >= chunk_max:
            raise ValueError(
                f"chunk {idx}={chunk} does not fit {layout.chunk_bit_width} bits"
            )
        parts.append(f"{chunk:0{hex_width}x}")

    return "".join(parts)


def _iter_phase3_artifacts(
    participant_artifacts: Iterable[Phase3ParticipantArtifact],
) -> list[Phase3ParticipantArtifact]:
    artifacts = list(participant_artifacts)
    if not artifacts:
        raise ValueError("participant_artifacts must not be empty")
    return artifacts


def recover_and_verify_winning_ticket(
    *,
    pp: PublicParameters,
    fhe: Any,
    phase4_result: Phase4Result,
    participant_artifacts: Iterable[Phase3ParticipantArtifact],
) -> PatentStep20TicketRecoveryResult:
    """
    Patent Step19-23 helper.

    Step19: generate partial decrypt shares for Step18-selected ticket chunks.
    Step20: combine shares and recover ticket hash suffix.
    Step21: identify winner by suffix match.
    Step22: reveal the winning ticket preimage.
    Step23: verify H(preimage) prefix/suffix against the candidate message data.
    """
    artifacts = _iter_phase3_artifacts(participant_artifacts)
    layout = artifacts[0].ticket_artifact.ticket_cipher_layout

    for artifact in artifacts:
        if artifact.ticket_artifact.ticket_cipher_layout != layout:
            raise ValueError("participant ticket layouts must match")

    participant_ids = [
        artifact.participant.participant_id
        for artifact in artifacts
    ]

    decryption_shares_by_chunk = step19_generate_winning_ticket_decryption_shares(
        fhe,
        participant_ids=participant_ids,
        winning_ticket_ciphertext=phase4_result.winning_ticket_ciphertext,
        layout=layout,
    )

    decrypted_chunks = step20_recover_winning_ticket_chunks(
        fhe,
        winning_ticket_ciphertext=phase4_result.winning_ticket_ciphertext,
        decryption_shares_by_chunk=decryption_shares_by_chunk,
        layout=layout,
    )

    recovered_suffix = recover_ticket_hash_suffix(decrypted_chunks, layout)

    matches = [
        artifact
        for artifact in artifacts
        if artifact.ticket_artifact.ticket_hash_suffix == recovered_suffix
    ]

    if len(matches) != 1:
        raise ValueError(f"winner suffix match count must be one, got {len(matches)}")

    winner_artifact = matches[0]
    ticket = winner_artifact.ticket_artifact

    reconstructed_hash = ticket.ticket_hash_prefix + recovered_suffix
    preimage_hash = hash_bytes(bytes.fromhex(ticket.ticket_preimage), pp.hash_name)

    hash_matches_preimage = preimage_hash == reconstructed_hash
    suffix_matches_candidate = recovered_suffix == ticket.ticket_hash_suffix
    hash_matches_candidate = reconstructed_hash == ticket.ticket_hash

    if not hash_matches_preimage:
        raise ValueError("recovered ticket hash does not match hash(ticket_preimage)")

    if not suffix_matches_candidate:
        raise ValueError("recovered ticket suffix does not match candidate artifact")

    if not hash_matches_candidate:
        raise ValueError("reconstructed ticket hash does not match candidate ticket_hash")

    return PatentStep20TicketRecoveryResult(
        winner_participant_id=winner_artifact.participant.participant_id,
        decryption_shares_by_chunk=decryption_shares_by_chunk,
        decrypted_ticket_chunks=decrypted_chunks,
        ticket_hash_suffix=recovered_suffix,
        ticket_hash=reconstructed_hash,
        ticket_preimage=ticket.ticket_preimage,
        ticket_hash_prefix=ticket.ticket_hash_prefix,
        hash_matches_preimage=hash_matches_preimage,
        suffix_matches_candidate=suffix_matches_candidate,
        hash_matches_candidate=hash_matches_candidate,
    )
