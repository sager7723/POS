from pos.models.stage2 import Participant
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import run_phase4_election


def test_phase4():
    pp = run_phase1_initialization()["public_parameters"]

    participants = [
        Participant("P1", 10),
        Participant("P2", 20),
        Participant("P3", 30),
    ]

    phase2 = run_phase2_preparation(pp, participants, threshold=2)
    phase3 = run_phase3_candidacy(pp, participants, phase2, proof_share_count=3)

    result = run_phase4_election(phase3.candidate_messages)

    assert result.total_stake_plaintext > 0
    assert result.scaled_random_ciphertext.startswith("scaled(")
    assert result.winning_ticket_ciphertext.startswith("enc(")