from __future__ import annotations

import secrets

from pos.crypto.fhe import MockThresholdFHE
from pos.crypto.proofs import MockProofShareGenerator
from pos.models.common import PublicParameters
from pos.models.stage2 import Participant
from pos.models.stage3 import TicketArtifact
from pos.spec import encode_ticket_preimage, hash_bytes, split_digest_hex


class TicketBuilder:
    def __init__(self, fhe: MockThresholdFHE, proof_generator: MockProofShareGenerator) -> None:
        self._fhe = fhe
        self._proof_generator = proof_generator

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

        encrypted_ticket_suffix = self._fhe.encrypt(
            pk=public_key,
            value=f"ticket_hash_suffix({ticket_hash_suffix})",
        ).payload

        ticket_proof_shares = self._proof_generator.build_proof_shares(
            secret_label="ticket",
            secret_value=(
                f"participant={participant.participant_id}"
                f"|ticket_preimage={ticket_preimage}"
                f"|ticket_hash={ticket_hash}"
                f"|ticket_hash_suffix={ticket_hash_suffix}"
            ),
            proof_share_count=proof_share_count,
        )

        return TicketArtifact(
            participant_id=participant.participant_id,
            ticket_preimage=ticket_preimage,
            ticket_hash=ticket_hash,
            ticket_hash_prefix=ticket_hash_prefix,
            ticket_hash_suffix=ticket_hash_suffix,
            encrypted_ticket_suffix=encrypted_ticket_suffix,
            ticket_proof_shares=ticket_proof_shares,
        )


MockTicketBuilder = TicketBuilder