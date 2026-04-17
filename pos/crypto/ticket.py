from __future__ import annotations

import secrets
from typing import List

from pos.crypto.fhe import MockCiphertext, MockThresholdFHE
from pos.crypto.proofs import MockProofShareGenerator
from pos.models.common import PublicParameters
from pos.models.stage2 import Participant
from pos.models.stage3 import TicketArtifact, TicketCipherLayout
from pos.spec import encode_ticket_preimage, hash_bytes, split_digest_hex


class TicketBuilder:
    """
    终版票根密文建模：

    1. 票根后半哈希按固定 2-byte chunk 切分；
    2. 每个 chunk 单独对应一个密文；
    3. 同时补齐第3步证明系统和第6步 reveal 所需的布局元数据。
    """

    CHUNK_BYTES = 2
    ENCODING_FAMILY = "hex_suffix_word"
    PACKING_MODE = "scalar_per_ciphertext"
    SLOT_PACKING = False
    SLOT_COUNT = 1
    RECOVERY_FORMAT = "hex_concat"

    def __init__(self, fhe: MockThresholdFHE, proof_generator: MockProofShareGenerator) -> None:
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
            chunk_bit_width=cls.CHUNK_BYTES * 8,
            chunk_count=chunk_count,
            hex_chars_per_chunk=cls.CHUNK_BYTES * 2,
            chunk_modulus=1 << (cls.CHUNK_BYTES * 8),
            packing_mode=cls.PACKING_MODE,
            slot_packing=cls.SLOT_PACKING,
            byte_order=pp.serialization_byte_order,
            recovery_format=cls.RECOVERY_FORMAT,
            chunk_bytes=cls.CHUNK_BYTES,
            packing_strategy=cls.PACKING_MODE,
            slot_count=cls.SLOT_COUNT,
            serialization_byte_order=pp.serialization_byte_order,
        )

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
            ciphertext = self._fhe.encrypt(
                pk=public_key,
                value=chunk_value,
            )
            ciphertext = MockCiphertext(
                backend=ciphertext.backend,
                encoded_value=ciphertext.encoded_value,
                metadata={
                    **ciphertext.metadata,
                    "kind": "ticket_suffix_chunk",
                    "ticket_chunk_bytes": self.CHUNK_BYTES,
                    "ticket_chunk_index": chunk_index,
                    "ticket_total_chunks": len(suffix_chunks),
                    "ticket_packing": self.PACKING_MODE,
                    "ticket_slot_count": self.SLOT_COUNT,
                    "ticket_byte_order": pp.serialization_byte_order,
                    "encoding_family": self.ENCODING_FAMILY,
                    "chunk_bit_width": self.CHUNK_BYTES * 8,
                    "chunk_count": len(suffix_chunks),
                    "hex_chars_per_chunk": self.CHUNK_BYTES * 2,
                    "chunk_modulus": 1 << (self.CHUNK_BYTES * 8),
                    "packing_mode": self.PACKING_MODE,
                    "slot_packing": self.SLOT_PACKING,
                    "byte_order": pp.serialization_byte_order,
                    "recovery_format": self.RECOVERY_FORMAT,
                },
            )
            encrypted_ticket_suffix_chunks.append(ciphertext.payload)

        # 这里先保留基础 artifact；正式方程级 ticket proof 仍由 candidacy.step7 重新生成并替换
        ticket_proof_shares = self._proof_generator.build_proof_shares(
            statement_type="ciphertext_encryption_correctness",
            statement_public_data={
                "participant_id": participant.participant_id,
                "public_key": public_key,
                "ciphertext": "|".join(encrypted_ticket_suffix_chunks),
                "plaintext_label": "ticket_hash_suffix_chunks",
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