from __future__ import annotations

import hashlib
import secrets

from pos.crypto.fhe import MockThresholdFHE
from pos.models.common import PublicParameters
from pos.models.stage2 import Participant
from pos.models.stage3 import TicketArtifact
from pos.crypto.proofs import MockProofShareGenerator


class MockTicketBuilder:
    """
    对应专利步骤7、8。
    生成票根、票根哈希、前后半段，并加密后半段票根哈希。
    未在专利中确认：票根编码与哈希拆分的唯一工程格式。
    """

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
        ticket_preimage = (
            f"ticket_preimage("
            f"{participant.participant_id}:"
            f"{secrets.token_hex(16)})"
        )
        ticket_hash = hashlib.sha256(ticket_preimage.encode("utf-8")).hexdigest()
        midpoint = len(ticket_hash) // 2
        ticket_hash_prefix = ticket_hash[:midpoint]
        ticket_hash_suffix = ticket_hash[midpoint:]

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