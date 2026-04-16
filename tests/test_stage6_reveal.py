import os

from pos.crypto.fhe import reset_fhe_backend_cache
from pos.models.stage2 import Participant
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import run_phase4_election
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation
from pos.protocol.reveal import run_phase5_reveal


def _build_pipeline(use_openfhe: bool):
    reset_fhe_backend_cache()
    os.environ["POS_FHE_BACKEND"] = "openfhe" if use_openfhe else "compatibility"

    pp = run_phase1_initialization()["public_parameters"]
    participants = [
        Participant("P1", 10),
        Participant("P2", 20),
        Participant("P3", 30),
    ]
    phase2 = run_phase2_preparation(pp, participants, threshold=2)
    phase3 = run_phase3_candidacy(pp, participants, phase2, proof_share_count=3)
    phase4 = run_phase4_election(phase3.candidate_messages)

    return pp, phase3, phase4


def test_stage6_reveal_closed_loop_compatibility_backend() -> None:
    try:
        pp, phase3, phase4 = _build_pipeline(use_openfhe=False)
        phase5 = run_phase5_reveal(
            pp=pp,
            phase3_result=phase3,
            winning_ticket_ciphertext=phase4.winning_ticket_ciphertext,
        )

        assert phase5.recovered_ticket_suffix != ""
        assert phase5.winner_id is not None
        assert phase5.revealed_ticket_preimage is not None
        assert phase5.public_verification_passed is True
    finally:
        os.environ["POS_FHE_BACKEND"] = "compatibility"
        reset_fhe_backend_cache()


def test_stage6_reveal_closed_loop_openfhe_backend() -> None:
    try:
        pp, phase3, phase4 = _build_pipeline(use_openfhe=True)
        phase5 = run_phase5_reveal(
            pp=pp,
            phase3_result=phase3,
            winning_ticket_ciphertext=phase4.winning_ticket_ciphertext,
        )

        assert phase5.recovered_ticket_suffix != ""
        assert phase5.winner_id is not None
        assert phase5.revealed_ticket_preimage is not None
        assert phase5.public_verification_passed is True
    finally:
        os.environ["POS_FHE_BACKEND"] = "compatibility"
        reset_fhe_backend_cache()