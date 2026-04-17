import os

import pytest

from pos.crypto.fhe import OPENFHE_AVAILABLE, reset_fhe_backend_cache
from pos.models.stage2 import Participant
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import run_phase4_election
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation
from pos.protocol.reveal import run_phase5_reveal


def _build_pipeline(use_openfhe: bool):
    reset_fhe_backend_cache()
    original_backend = os.environ.get("POS_FHE_BACKEND")

    if use_openfhe:
        os.environ["POS_FHE_BACKEND"] = "openfhe"
    else:
        os.environ["POS_FHE_BACKEND"] = "compatibility"

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
        return pp, phase2, phase3, phase4
    finally:
        reset_fhe_backend_cache()
        if original_backend is None:
            os.environ.pop("POS_FHE_BACKEND", None)
        else:
            os.environ["POS_FHE_BACKEND"] = original_backend


def test_stage6_reveal_closed_loop_compatibility_backend() -> None:
    pp, phase2, phase3, phase4 = _build_pipeline(use_openfhe=False)

    phase5 = run_phase5_reveal(
        pp=pp,
        phase2_result=phase2,
        phase3_result=phase3,
        phase4_result=phase4,
    )

    assert phase5.recovered_ticket_suffix != ""
    assert phase5.winner_id is not None
    assert phase5.revealed_ticket_preimage is not None
    assert phase5.public_verification_passed is True

    assert phase5.round_id == phase4.round_id
    assert phase5.proof_valid_candidate_ids == phase4.proof_valid_candidate_ids
    assert phase5.public_reveal_object is not None
    assert phase5.public_reveal_object.round_id == phase4.round_id
    assert phase5.public_reveal_object.participant_id == phase5.winner_id
    assert phase5.public_reveal_object.revealed_ticket_preimage == phase5.revealed_ticket_preimage
    assert phase5.public_reveal_object.recovered_ticket_suffix == phase5.recovered_ticket_suffix
    assert phase5.public_reveal_object.proof_valid_candidate_ids == phase4.proof_valid_candidate_ids
    assert phase5.candidate_message_reference == phase5.public_reveal_object.candidate_message_reference


@pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="openfhe package is not installed")
def test_stage6_reveal_closed_loop_openfhe_backend() -> None:
    pp, phase2, phase3, phase4 = _build_pipeline(use_openfhe=True)

    phase5 = run_phase5_reveal(
        pp=pp,
        phase2_result=phase2,
        phase3_result=phase3,
        phase4_result=phase4,
    )

    assert phase5.recovered_ticket_suffix != ""
    assert phase5.winner_id is not None
    assert phase5.revealed_ticket_preimage is not None
    assert phase5.public_verification_passed is True

    assert phase5.round_id == phase4.round_id
    assert phase5.proof_valid_candidate_ids == phase4.proof_valid_candidate_ids
    assert phase5.public_reveal_object is not None
    assert phase5.public_reveal_object.round_id == phase4.round_id
    assert phase5.public_reveal_object.participant_id == phase5.winner_id
    assert phase5.public_reveal_object.revealed_ticket_preimage == phase5.revealed_ticket_preimage
    assert phase5.public_reveal_object.recovered_ticket_suffix == phase5.recovered_ticket_suffix
    assert phase5.public_reveal_object.proof_valid_candidate_ids == phase4.proof_valid_candidate_ids
    assert phase5.candidate_message_reference == phase5.public_reveal_object.candidate_message_reference