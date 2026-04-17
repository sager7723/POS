import importlib.util
import os

import pytest

from pos.crypto.fhe import reset_fhe_backend_cache
from pos.models.stage2 import Participant
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import run_phase4_election
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation


OPENFHE_AVAILABLE = importlib.util.find_spec("openfhe") is not None


@pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="openfhe package is not installed")
def test_stage4_with_real_openfhe_backend() -> None:
    reset_fhe_backend_cache()
    os.environ["POS_FHE_BACKEND"] = "openfhe"
    try:
        pp = run_phase1_initialization()["public_parameters"]

        participants = [
            Participant("P1", 10),
            Participant("P2", 20),
            Participant("P3", 30),
        ]

        phase2 = run_phase2_preparation(pp, participants, threshold=2)
        phase3 = run_phase3_candidacy(pp, participants, phase2, proof_share_count=3)
        phase4 = run_phase4_election(phase2, phase3.candidate_messages)

        assert phase4.total_stake_plaintext == 60
        assert isinstance(phase4.scaled_random_ciphertext, str)
        assert isinstance(phase4.winning_ticket_ciphertext, list)
        assert len(phase4.winning_ticket_ciphertext) > 0
    finally:
        os.environ["POS_FHE_BACKEND"] = "compatibility"
        reset_fhe_backend_cache()
