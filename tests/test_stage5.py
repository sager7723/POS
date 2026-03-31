from pos.models.stage2 import Participant
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import run_phase4_election
from pos.protocol.reveal import run_phase5_reveal


def test_phase5():
    pp = run_phase1_initialization()["public_parameters"]

    participants = [
        Participant("P1", 10),
        Participant("P2", 20),
        Participant("P3", 30),
    ]

    phase2 = run_phase2_preparation(pp, participants, 2)
    phase3 = run_phase3_candidacy(pp, participants, phase2, 3)
    phase4 = run_phase4_election(phase3.candidate_messages)

    result = run_phase5_reveal(
        phase3.candidate_messages,
        phase4.winning_ticket_ciphertext,
    )

    assert result.winner_id in ["P1", "P2", "P3"]
    assert result.verification_passed is True