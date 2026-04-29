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
from pos.protocol.election import run_phase4_election
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation


def main() -> None:
    reset_fhe_backend_cache()

    phase1 = run_phase1_initialization()
    pp = phase1["public_parameters"]

    participants = [
        Participant("P1", 10),
        Participant("P2", 20),
        Participant("P3", 30),
    ]

    # Strict KMS patent mode binds Phase2 to the same KMS threshold keyset.
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

    for participant_id, message in phase3.candidate_messages.items():
        print(
            "candidate",
            participant_id,
            "proof_counts",
            {
                "prf": len(message.prf_proof_shares),
                "stake_cipher": len(message.stake_ciphertext_proof_shares),
                "commitment": len(message.commitment_consistency_proof_shares),
                "ticket": len(message.ticket_proof_shares),
            },
            "ticket_layout",
            {
                "encoding_family": message.ticket_cipher_layout.encoding_family,
                "chunk_bit_width": message.ticket_cipher_layout.chunk_bit_width,
                "chunk_modulus": message.ticket_cipher_layout.chunk_modulus,
                "chunk_count": message.ticket_cipher_layout.chunk_count,
            },
        )

    phase4 = run_phase4_election(
        phase2,
        phase3.candidate_messages,
    )

    print("=== Stage-10-D5-D real Phase3 -> run_phase4 strict patent dual-width KMS path ===")
    print("total_stake_plaintext:", phase4.total_stake_plaintext)
    print("round_id:", phase4.round_id)
    print("proof_valid_candidate_ids:", phase4.proof_valid_candidate_ids)
    print("scaled_random_ciphertext:", phase4.scaled_random_ciphertext)
    print("winning_ticket_ciphertext_count:", len(phase4.winning_ticket_ciphertext))
    print("first_winning_ticket_chunk:", phase4.winning_ticket_ciphertext[0])

    scaled_payload = json.loads(phase4.scaled_random_ciphertext)
    first_chunk_payload = json.loads(phase4.winning_ticket_ciphertext[0])

    assert phase4.total_stake_plaintext == 60
    assert phase4.round_id.startswith("round-")
    assert phase4.proof_valid_candidate_ids == ["P1", "P2", "P3"]
    assert scaled_payload["backend"] == "kms-threshold"
    assert scaled_payload["data_type"] == "euint32"
    assert first_chunk_payload["backend"] == "kms-threshold"
    assert first_chunk_payload["data_type"] == "euint16"
    assert len(phase4.winning_ticket_ciphertext) > 0

    for idx, chunk_json in enumerate(phase4.winning_ticket_ciphertext):
        chunk_payload = json.loads(chunk_json)
        assert chunk_payload["backend"] == "kms-threshold"
        assert chunk_payload["data_type"] == "euint16", (
            f"winning ticket chunk {idx} must be euint16, got "
            f"{chunk_payload['data_type']!r}"
        )

    print("\\nStage-10-D5-D real Phase3 run_phase4 strict patent dual-width KMS path check passed.")


if __name__ == "__main__":
    main()
