import importlib.util
import os

import pytest

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache
from pos.models.stage2 import Participant
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation


OPENFHE_AVAILABLE = importlib.util.find_spec("openfhe") is not None


def _build_openfhe_facade():
    reset_fhe_backend_cache()
    os.environ["POS_FHE_BACKEND"] = "openfhe"

    pp = run_phase1_initialization()["public_parameters"]
    participants = [
        Participant("P1", 10),
        Participant("P2", 20),
        Participant("P3", 30),
    ]
    phase2 = run_phase2_preparation(pp, participants, threshold=2)
    facade = initialize_fhe_backend(distributed_key_result=phase2.distributed_key_result)
    return phase2, facade


def _collect_shares(facade, participant_ids: list[str], ciphertext) -> list[str]:
    return [facade.decrypt_share(pid, ciphertext) for pid in participant_ids]


@pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="openfhe package is not installed")
def test_openfhe_backend_uses_phase2_key_material() -> None:
    try:
        phase2, facade = _build_openfhe_facade()
        participant_ids = [artifact.participant.participant_id for artifact in phase2.participant_artifacts]

        c1 = facade.encrypt(10)
        c2 = facade.encrypt(20)
        c3 = facade.encrypt(30)

        total = facade.homomorphic_sum([c1, c2, c3])
        total_shares = _collect_shares(facade, participant_ids, total)
        assert facade.decrypt(total, total_shares) == 60

        prefix = facade.prefix_sum([c1, c2, c3])
        assert len(prefix) == 3

        prefix_0_shares = _collect_shares(facade, participant_ids, prefix[0])
        prefix_1_shares = _collect_shares(facade, participant_ids, prefix[1])
        prefix_2_shares = _collect_shares(facade, participant_ids, prefix[2])

        assert facade.decrypt(prefix[0], prefix_0_shares) == 10
        assert facade.decrypt(prefix[1], prefix_1_shares) == 30
        assert facade.decrypt(prefix[2], prefix_2_shares) == 60

        random_ct = facade.encrypt(25)
        compare_bits = facade.compare_lt_vector(random_ct, prefix)

        bit_0 = facade.decrypt(compare_bits[0], _collect_shares(facade, participant_ids, compare_bits[0]))
        bit_1 = facade.decrypt(compare_bits[1], _collect_shares(facade, participant_ids, compare_bits[1]))
        bit_2 = facade.decrypt(compare_bits[2], _collect_shares(facade, participant_ids, compare_bits[2]))

        assert bit_0 == 0
        assert bit_1 == 1
        assert bit_2 == 1

        ticket_1 = facade.encrypt(111)
        ticket_2 = facade.encrypt(222)
        ticket_3 = facade.encrypt(333)

        selected = facade.select_first_true(compare_bits, [ticket_1, ticket_2, ticket_3])
        selected_value = facade.decrypt(selected, _collect_shares(facade, participant_ids, selected))
        assert selected_value == 222

        scaled = facade.scale_ciphertext(c1, 3.0)
        scaled_value = facade.decrypt(scaled, _collect_shares(facade, participant_ids, scaled))
        assert scaled_value == 30
    finally:
        os.environ["POS_FHE_BACKEND"] = "compatibility"
        reset_fhe_backend_cache()
