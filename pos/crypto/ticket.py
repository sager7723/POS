from __future__ import annotations

import secrets
from typing import List

from pos.crypto.fhe import MockThresholdFHE
from pos.crypto.proofs import MockProofShareGenerator
from pos.models.common import PublicParameters
from pos.models.stage2 import Participant
from pos.models.stage3 import TicketArtifact
from pos.spec import encode_ticket_preimage, hash_bytes, split_digest_hex


class TicketBuilder:
    """
    第6层闭环需要精确恢复 ticket_hash_suffix。
    因此这里将 suffix 按字节分块，每个 chunk 单独加密。
    """

    def __init__(self, fhe: MockThresholdFHE, proof_generator: MockProofShareGenerator) -> None:
        self._fhe = fhe
        self._proof_generator = proof_generator

    @staticmethod
    def _split_suffix_into_chunks(ticket_hash_suffix: str) -> List[int]:
        if len(ticket_hash_suffix) % 2 != 0:
            raise ValueError("ticket_hash_suffix hex length must be even")
        return [int(ticket_hash_suffix[i:i + 2], 16) for i in range(0, len(ticket_hash_suffix), 2)]

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
        encrypted_ticket_suffix_chunks = [
            self._fhe.encrypt(
                pk=public_key,
                value=chunk_value,
            ).payload
            for chunk_value in suffix_chunks
        ]

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
        )


MockTicketBuilder = TicketBuilder