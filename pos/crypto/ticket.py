from __future__ import annotations

import secrets
from typing import List

from pos.crypto.fhe import Ciphertext, FHEThresholdFacade
from pos.crypto.patent_widths import (
    strict_kms_patent_mode_enabled,
    ticket_chunk_bits,
    ticket_chunk_bytes,
    ticket_data_type,
    ticket_encoding_family,
)
from pos.crypto.proofs import PatentProofShareGenerator
from pos.models.common import PublicParameters
from pos.models.stage2 import Participant
from pos.models.stage3 import TicketArtifact, TicketCipherLayout
from pos.spec import encode_ticket_preimage, hash_bytes, split_digest_hex


def _ciphertext_wire_payload(ciphertext: object) -> str:
    if isinstance(ciphertext, str):
        return ciphertext

    payload = getattr(ciphertext, "payload", None)
    if isinstance(payload, str):
        return payload

    if hasattr(ciphertext, "to_json"):
        return ciphertext.to_json()  # type: ignore[no-any-return]

    return str(ciphertext)


def _ciphertext_public_metadata(ciphertext: object) -> dict[str, object]:
    metadata = getattr(ciphertext, "metadata", None)
    if isinstance(metadata, dict):
        return dict(metadata)
    return {}


class TicketBuilder:
    CHUNK_BYTES = ticket_chunk_bytes()
    WORD_BITS = ticket_chunk_bits()
    DATA_TYPE = ticket_data_type()
    ENCODING_FAMILY = ticket_encoding_family()

    PACKING_MODE = "scalar_per_ciphertext"
    SLOT_PACKING = False
    SLOT_COUNT = 1
    RECOVERY_FORMAT = "hex_concat"

    def __init__(self, fhe: FHEThresholdFacade, proof_generator: PatentProofShareGenerator) -> None:
        self._fhe = fhe
        self._proof_generator = proof_generator

    @classmethod
    def _split_suffix_into_chunks(cls, ticket_hash_suffix: str) -> List[int]:
        hex_width = cls.CHUNK_BYTES * 2
        if len(ticket_hash_suffix) % hex_width != 0:
            raise ValueError("ticket_hash_suffix hex length must align to configured chunk width")
        return [
            int(ticket_hash_suffix[i:i + hex_width], 16)
            for i in range(0, len(ticket_hash_suffix), hex_width)
        ]

    @classmethod
    def _build_layout(cls, pp: PublicParameters, chunk_count: int) -> TicketCipherLayout:
        return TicketCipherLayout(
            encoding_family=cls.ENCODING_FAMILY,
            chunk_bit_width=cls.WORD_BITS,
            chunk_count=chunk_count,
            hex_chars_per_chunk=cls.CHUNK_BYTES * 2,
            chunk_modulus=1 << cls.WORD_BITS,
            packing_mode=cls.PACKING_MODE,
            slot_packing=cls.SLOT_PACKING,
            byte_order=pp.serialization_byte_order,
            recovery_format=cls.RECOVERY_FORMAT,
            chunk_bytes=cls.CHUNK_BYTES,
            packing_strategy=cls.PACKING_MODE,
            slot_count=cls.SLOT_COUNT,
            serialization_byte_order=pp.serialization_byte_order,
        )

    def _encrypt_ticket_chunk(self, chunk_value: int) -> object:
        if strict_kms_patent_mode_enabled():
            return self._fhe.encrypt_scalar(
                int(chunk_value),
                data_type=self.DATA_TYPE,
                no_compression=True,
                no_precompute_sns=True,
            )

        return self._fhe.encrypt_scalar(chunk_value)

    def build_ticket_artifact(
        self,
        pp: PublicParameters,
        public_key: str,
        participant: Participant,
        proof_share_count: int,
    ) -> TicketArtifact:
        nonce = secrets.token_bytes(pp.ticket_nonce_bytes)

        ticket_preimage_bytes = encode_ticket_preimage(
            participant_id=participant.participant_id,
            nonce=nonce,
            version=pp.ticket_version,
            length_bytes=pp.serialization_length_bytes,
            byte_order=pp.serialization_byte_order,
        )
        ticket_preimage = ticket_preimage_bytes.hex()

        ticket_hash = hash_bytes(ticket_preimage_bytes, pp.hash_name)
        ticket_hash_prefix, ticket_hash_suffix = split_digest_hex(ticket_hash)

        suffix_chunks = self._split_suffix_into_chunks(ticket_hash_suffix)
        ticket_layout = self._build_layout(pp, len(suffix_chunks))

        encrypted_ticket_suffix_chunks: List[str] = []

        for chunk_index, chunk_value in enumerate(suffix_chunks):
            raw_ciphertext = self._encrypt_ticket_chunk(chunk_value)

            if strict_kms_patent_mode_enabled():
                encrypted_ticket_suffix_chunks.append(_ciphertext_wire_payload(raw_ciphertext))
                continue

            ciphertext = Ciphertext(
                backend=raw_ciphertext.backend,
                encoded_value=raw_ciphertext.encoded_value,
                metadata={
                    **_ciphertext_public_metadata(raw_ciphertext),
                    "kind": "ticket_suffix_chunk",
                    "ticket_chunk_bytes": self.CHUNK_BYTES,
                    "ticket_chunk_index": chunk_index,
                    "ticket_total_chunks": len(suffix_chunks),
                    "ticket_packing": self.PACKING_MODE,
                    "ticket_slot_count": self.SLOT_COUNT,
                    "ticket_byte_order": pp.serialization_byte_order,
                    "encoding_family": self.ENCODING_FAMILY,
                    "chunk_bit_width": self.WORD_BITS,
                    "chunk_count": len(suffix_chunks),
                    "hex_chars_per_chunk": self.CHUNK_BYTES * 2,
                    "chunk_modulus": 1 << self.WORD_BITS,
                    "packing_mode": self.PACKING_MODE,
                    "slot_packing": self.SLOT_PACKING,
                    "byte_order": pp.serialization_byte_order,
                    "recovery_format": self.RECOVERY_FORMAT,
                },
            )
            encrypted_ticket_suffix_chunks.append(ciphertext.payload)

        ticket_proof_shares = self._proof_generator.build_proof_shares(
            statement_type="ciphertext_encryption_correctness",
            statement_public_data={
                "participant_id": participant.participant_id,
                "public_key": public_key,
                "ciphertext": "|".join(encrypted_ticket_suffix_chunks),
                "plaintext_label": "ticket_hash_suffix_chunks",
                "proof_label": "ticket_suffix_ciphertext",
                "encoding_family": self.ENCODING_FAMILY,
                "chunk_bit_width": str(self.WORD_BITS),
                "chunk_count": str(len(suffix_chunks)),
                "hex_chars_per_chunk": str(self.CHUNK_BYTES * 2),
                "chunk_modulus": str(1 << self.WORD_BITS),
                "packing_mode": self.PACKING_MODE,
                "slot_packing": str(self.SLOT_PACKING).lower(),
                "byte_order": pp.serialization_byte_order,
                "recovery_format": self.RECOVERY_FORMAT,
            },
            witness_values={
                "plaintext_scalar": sum(suffix_chunks),
            },
            proof_share_count=proof_share_count,
            reveal_threshold=max(2, proof_share_count),
            noise_estimate=0,
            noise_bound=0,
        )

        return TicketArtifact(
            participant_id=participant.participant_id,
            ticket_preimage=ticket_preimage,
            ticket_hash=ticket_hash,
            ticket_hash_prefix=ticket_hash_prefix,
            ticket_hash_suffix=ticket_hash_suffix,
            ticket_hash_suffix_chunks=suffix_chunks,
            encrypted_ticket_suffix_chunks=encrypted_ticket_suffix_chunks,
            ticket_proof_shares=ticket_proof_shares,
            ticket_cipher_layout=ticket_layout,
            ticket_layout=ticket_layout,
        )


MockTicketBuilder = TicketBuilder
