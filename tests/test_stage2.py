from pos.models.stage2 import Participant
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation


def test_phase2_outputs_explicit_unified_key_material() -> None:
    pp = run_phase1_initialization()["public_parameters"]
    participants = [
        Participant("P1", 10),
        Participant("P2", 20),
        Participant("P3", 30),
    ]

    phase2 = run_phase2_preparation(pp=pp, participants=participants, threshold=2)

    assert phase2.complete_public_key == phase2.distributed_key_result.public_key
    assert phase2.distributed_key_result.fhe_backend_name == "compatibility"
    assert phase2.distributed_key_result.fhe_keyset_reference is not None

    assert set(phase2.threshold_fhe_private_key_shares.keys()) == {"P1", "P2", "P3"}
    assert set(phase2.share_public_keys.keys()) == {"P1", "P2", "P3"}

    for participant_id, private_share in phase2.threshold_fhe_private_key_shares.items():
        assert private_share.participant_id == participant_id
        assert private_share.fhe_private_key_share != ""
        assert private_share.decrypt_share_key >= 0
        assert (
            private_share.corresponding_share_public_key
            == phase2.share_public_keys[participant_id].share_public_key
        )
        assert private_share.backend_name == phase2.distributed_key_result.fhe_backend_name
        assert private_share.key_material_reference == phase2.distributed_key_result.fhe_keyset_reference


def test_phase2_decrypt_key_share_alias_remains_compatible() -> None:
    pp = run_phase1_initialization()["public_parameters"]
    participants = [
        Participant("P1", 11),
        Participant("P2", 22),
        Participant("P3", 33),
    ]

    phase2 = run_phase2_preparation(pp=pp, participants=participants, threshold=2)
    alias_map = phase2.distributed_key_result.decrypt_key_shares

    assert alias_map is phase2.distributed_key_result.threshold_fhe_private_key_shares
    assert all(share.decrypt_share_key == share.secret_share_scalar for share in alias_map.values())
