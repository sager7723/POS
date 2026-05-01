from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from pos.models.common import PublicParameters
from pos.models.stage3 import Phase3ParticipantArtifact, TicketCipherLayout
from pos.models.stage4 import Phase4Result
from pos.spec import hash_bytes


@dataclass(frozen=True)
class PatentStep20TicketRecoveryResult:
    winner_participant_id: str
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
    Convert Phase4 wire JSON back into the FHE backend ciphertext handle.

    This does not decrypt by itself. It only restores the public KMS ciphertext
    handle so Step19 can call the configured threshold decrypt operation.
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

    try:
        from pos.crypto.thfhe_backend.kms_fhe_backend import KmsThresholdCiphertextHandle
    except ImportError:
        from pos.crypto.thfhe_backend.kms_bridge import KmsThresholdCiphertextHandle  # type: ignore

    return KmsThresholdCiphertextHandle(
        backend=str(payload["backend"]),
        key_id=str(payload["key_id"]),
        data_type=str(payload["data_type"]),
        ciphertext_path=str(payload["ciphertext_path"]),
        ciphertext_id=str(payload["ciphertext_id"]),
    )


def decrypt_winning_ticket_chunks(
    fhe: Any,
    winning_ticket_ciphertext: Sequence[Any],
    layout: TicketCipherLayout,
) -> list[int]:
    """
    Patent Step19: threshold decrypt the selected winning ticket suffix chunks.

    The input must be the euint16 chunk vector selected by Step18.
    """
    if layout.chunk_bit_width != 16:
        raise ValueError(
            f"Stage-10-E expects euint16 ticket chunks, got {layout.chunk_bit_width}"
        )

    if len(winning_ticket_ciphertext) != layout.chunk_count:
        raise ValueError(
            f"winning_ticket_ciphertext chunk count mismatch: "
            f"got {len(winning_ticket_ciphertext)}, expected {layout.chunk_count}"
        )

    modulus = int(layout.chunk_modulus)
    decrypted: list[int] = []

    for idx, wire_value in enumerate(winning_ticket_ciphertext):
        ciphertext = _ciphertext_from_wire(fhe, wire_value)
        value = int(fhe.user_decrypt_scalar(ciphertext))

        if value < 0 or value >= modulus:
            raise ValueError(
                f"decrypted ticket chunk {idx} out of range for modulus {modulus}: {value}"
            )

        decrypted.append(value)

    return decrypted


def recover_ticket_hash_suffix(
    decrypted_ticket_chunks: Sequence[int],
    layout: TicketCipherLayout,
) -> str:
    """
    Patent Step20: reconstruct the ticket hash suffix from decrypted chunks.
    """
    if layout.recovery_format != "hex_concat":
        raise ValueError(f"unsupported ticket recovery format: {layout.recovery_format!r}")

    hex_width = int(layout.hex_chars_per_chunk)
    if hex_width <= 0:
        raise ValueError(f"invalid hex_chars_per_chunk: {hex_width}")

    if len(decrypted_ticket_chunks) != layout.chunk_count:
        raise ValueError(
            f"decrypted chunk count mismatch: got {len(decrypted_ticket_chunks)}, "
            f"expected {layout.chunk_count}"
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
    Patent Step19/20 end-to-end recovery.

    1. Decrypt selected euint16 winning ticket chunks.
    2. Reconstruct ticket_hash_suffix.
    3. Match the suffix against Phase3 ticket artifacts.
    4. Verify ticket_hash_prefix + suffix and hash(ticket_preimage).
    """
    artifacts = _iter_phase3_artifacts(participant_artifacts)
    layout = artifacts[0].ticket_artifact.ticket_cipher_layout

    for artifact in artifacts:
        other_layout = artifact.ticket_artifact.ticket_cipher_layout
        if other_layout != layout:
            raise ValueError("all participant ticket layouts must match")

    decrypted_chunks = decrypt_winning_ticket_chunks(
        fhe,
        phase4_result.winning_ticket_ciphertext,
        layout,
    )
    recovered_suffix = recover_ticket_hash_suffix(decrypted_chunks, layout)

    matches = [
        artifact
        for artifact in artifacts
        if artifact.ticket_artifact.ticket_hash_suffix == recovered_suffix
    ]

    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one matching ticket suffix, got {len(matches)}"
        )

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
        decrypted_ticket_chunks=decrypted_chunks,
        ticket_hash_suffix=recovered_suffix,
        ticket_hash=reconstructed_hash,
        ticket_preimage=ticket.ticket_preimage,
        ticket_hash_prefix=ticket.ticket_hash_prefix,
        hash_matches_preimage=hash_matches_preimage,
        suffix_matches_candidate=suffix_matches_candidate,
        hash_matches_candidate=hash_matches_candidate,
    )
