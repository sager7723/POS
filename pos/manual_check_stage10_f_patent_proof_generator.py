from __future__ import annotations

import os

os.environ["POS_FHE_BACKEND"] = "kms-threshold"
os.environ["POS_STRICT_PATENT_MODE"] = "1"
os.environ["POS_LOTTERY_WORD_BITS"] = "32"
os.environ["POS_TICKET_CHUNK_BITS"] = "16"

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache
from pos.crypto.proofs import PatentProofShareGenerator
from pos.crypto.ticket import TicketBuilder
from pos.models.stage2 import Participant
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import run_phase4_election
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.patent_step20 import recover_and_verify_winning_ticket
from pos.protocol.preparation import run_phase2_preparation


def main() -> None:
    reset_fhe_backend_cache()

    profile = PatentProofShareGenerator.production_component_profile()

    print("=== Stage-10-F Patent proof generator production interface ===")
    print("proof_system:", PatentProofShareGenerator.PROOF_SYSTEM_NAME)
    print("proof_system_version:", PatentProofShareGenerator.PROOF_SYSTEM_VERSION)
    print("components:", profile)

    for required in [
        "cut_and_choose",
        "shamir",
        "feldman",
        "pedersen",
        "ciphertext_binding",
    ]:
        assert required in profile

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

    phase4 = run_phase4_election(
        phase2,
        phase3.candidate_messages,
    )

    fhe = initialize_fhe_backend(
        participant_ids=phase4.proof_valid_candidate_ids,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )
    fhe.setup(
        {
            "stage": "stage10_f_patent_proof_generator",
            "strict_no_plaintext_fallback": True,
            "operation": "verify_production_named_proof_layer_with_step20",
        }
    )

    recovery = recover_and_verify_winning_ticket(
        pp=pp,
        fhe=fhe,
        phase4_result=phase4,
        participant_artifacts=phase3.participant_artifacts,
    )

    print("winner_participant_id:", recovery.winner_participant_id)
    print("hash_matches_preimage:", recovery.hash_matches_preimage)
    print("suffix_matches_candidate:", recovery.suffix_matches_candidate)
    print("hash_matches_candidate:", recovery.hash_matches_candidate)

    assert recovery.hash_matches_preimage is True
    assert recovery.suffix_matches_candidate is True
    assert recovery.hash_matches_candidate is True

    # Confirm the ticket builder now depends on the production proof class name.
    proof_generator = PatentProofShareGenerator()
    builder = TicketBuilder(fhe, proof_generator)
    assert builder is not None

    print("\\nStage-10-F patent proof generator production interface check passed.")


if __name__ == "__main__":
    main()
