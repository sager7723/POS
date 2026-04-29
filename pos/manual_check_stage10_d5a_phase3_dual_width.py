from __future__ import annotations

import json
import os

os.environ["POS_FHE_BACKEND"] = "kms-threshold"
os.environ["POS_STRICT_PATENT_MODE"] = "1"
os.environ["POS_LOTTERY_WORD_BITS"] = "32"
os.environ["POS_TICKET_CHUNK_BITS"] = "16"

from pos.crypto.fhe import reset_fhe_backend_cache
from pos.models.stage2 import Participant
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation


def parse_payload(payload: str) -> dict:
    return json.loads(payload)


def main() -> None:
    reset_fhe_backend_cache()

    phase1 = run_phase1_initialization()
    pp = phase1["public_parameters"]

    participants = [
        Participant("P1", 10),
        Participant("P2", 20),
        Participant("P3", 30),
    ]

    phase2 = run_phase2_preparation(
        pp=pp,
        participants=participants,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )

    phase3 = run_phase3_candidacy(
        pp=pp,
        participants=participants,
        phase2_result=phase2,
        proof_share_count=3,
    )

    print("=== Stage-10-D5-A Phase3 strict KMS dual-width candidate messages ===")

    for participant_id, message in phase3.candidate_messages.items():
        stake_payload = parse_payload(message.encrypted_stake)
        prf_payload = parse_payload(message.encrypted_prf_share)
        first_ticket_payload = parse_payload(message.encrypted_ticket[0])

        report = {
            "stake_type": stake_payload["data_type"],
            "prf_type": prf_payload["data_type"],
            "ticket_type": first_ticket_payload["data_type"],
            "ticket_chunk_bit_width": message.ticket_cipher_layout.chunk_bit_width,
            "ticket_chunk_modulus": message.ticket_cipher_layout.chunk_modulus,
            "ticket_chunk_count": message.ticket_cipher_layout.chunk_count,
            "proof_counts": {
                "prf": len(message.prf_proof_shares),
                "stake": len(message.stake_ciphertext_proof_shares),
                "commitment": len(message.commitment_consistency_proof_shares),
                "ticket": len(message.ticket_proof_shares),
            },
        }
        print(participant_id, report)

        assert stake_payload["backend"] == "kms-threshold"
        assert prf_payload["backend"] == "kms-threshold"
        assert first_ticket_payload["backend"] == "kms-threshold"

        assert stake_payload["data_type"] == "euint32"
        assert prf_payload["data_type"] == "euint32"
        assert first_ticket_payload["data_type"] == "euint16"

        assert message.ticket_cipher_layout.chunk_bit_width == 16
        assert message.ticket_cipher_layout.chunk_modulus == 65536
        assert message.ticket_cipher_layout.chunk_count == 8

        assert len(message.prf_proof_shares) == 3
        assert len(message.stake_ciphertext_proof_shares) == 3
        assert len(message.commitment_consistency_proof_shares) == 3
        assert len(message.ticket_proof_shares) == 3

    print("\\nStage-10-D5-A Phase3 strict KMS dual-width check passed.")


if __name__ == "__main__":
    main()
