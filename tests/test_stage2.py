from pos.models.stage2 import Participant
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import (
    run_phase2_preparation,
    step1_generate_and_publish_stake_commitments,
    step2_distributed_generate_keys,
    step3_distributed_generate_random_seed,
)


def build_test_participants() -> list[Participant]:
    return [
        Participant(participant_id="P1", stake_value=10),
        Participant(participant_id="P2", stake_value=20),
        Participant(participant_id="P3", stake_value=30),
    ]


def test_step1_generate_and_publish_stake_commitments() -> None:
    initialization_result = run_phase1_initialization(security_parameter=64)
    pp = initialization_result["public_parameters"]
    participants = build_test_participants()

    commitments = step1_generate_and_publish_stake_commitments(
        pp=pp,
        participants=participants,
    )

    assert len(commitments) == 3
    assert "P1" in commitments
    assert commitments["P1"].participant_id == "P1"
    assert commitments["P1"].stake_commitment.startswith("pedersen_commit:0x")


def test_step2_distributed_generate_keys() -> None:
    initialization_result = run_phase1_initialization(security_parameter=64)
    pp = initialization_result["public_parameters"]
    participants = build_test_participants()

    result = step2_distributed_generate_keys(
        pp=pp,
        participants=participants,
        threshold=2,
    )

    assert result.public_key == "mock_public_key"
    assert len(result.decrypt_key_shares) == 3
    assert len(result.share_public_keys) == 3
    assert result.decrypt_key_shares["P2"].participant_id == "P2"


def test_step3_distributed_generate_random_seed() -> None:
    initialization_result = run_phase1_initialization(security_parameter=64)
    pp = initialization_result["public_parameters"]
    participants = build_test_participants()

    random_seed, contributions = step3_distributed_generate_random_seed(
        pp=pp,
        participants=participants,
    )

    assert isinstance(random_seed, str)
    assert len(random_seed) >= 64
    assert len(contributions) == 3
    assert "P3" in contributions


def test_run_phase2_preparation() -> None:
    initialization_result = run_phase1_initialization(security_parameter=64)
    pp = initialization_result["public_parameters"]
    participants = build_test_participants()

    result = run_phase2_preparation(
        pp=pp,
        participants=participants,
        threshold=2,
    )

    assert len(result.commitments) == 3
    assert result.distributed_key_result.public_key == "mock_public_key"
    assert len(result.participant_artifacts) == 3
    assert isinstance(result.random_seed, str)