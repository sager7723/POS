import os

from pos.crypto.fhe import OpenFHEBackend, initialize_fhe_backend, reset_fhe_backend_cache


def _collect_shares(backend: OpenFHEBackend, participant_ids: list[str], ciphertext) -> list[str]:
    return [backend.decrypt_share(pid, ciphertext) for pid in participant_ids]


def test_openfhe_backend_stage_b_subset() -> None:
    reset_fhe_backend_cache()
    backend = OpenFHEBackend()
    participant_ids = ["P1", "P2", "P3"]
    backend.configure_participants(participant_ids)

    c1 = backend.encrypt(10)
    c2 = backend.encrypt(20)
    c3 = backend.encrypt(30)

    assert c1.backend == "openfhe"
    assert c2.backend == "openfhe"
    assert c3.backend == "openfhe"

    total = backend.homomorphic_sum([c1, c2, c3])
    total_shares = _collect_shares(backend, participant_ids, total)
    assert backend.decrypt(total, total_shares) == 60

    prefix = backend.prefix_sum([c1, c2, c3])
    assert len(prefix) == 3

    prefix_0_shares = _collect_shares(backend, participant_ids, prefix[0])
    prefix_1_shares = _collect_shares(backend, participant_ids, prefix[1])
    prefix_2_shares = _collect_shares(backend, participant_ids, prefix[2])

    assert backend.decrypt(prefix[0], prefix_0_shares) == 10
    assert backend.decrypt(prefix[1], prefix_1_shares) == 30
    assert backend.decrypt(prefix[2], prefix_2_shares) == 60

    random_ct = backend.encrypt(25)
    compare_bits = backend.compare_lt_vector(random_ct, prefix)

    bit_0 = backend.decrypt(compare_bits[0], _collect_shares(backend, participant_ids, compare_bits[0]))
    bit_1 = backend.decrypt(compare_bits[1], _collect_shares(backend, participant_ids, compare_bits[1]))
    bit_2 = backend.decrypt(compare_bits[2], _collect_shares(backend, participant_ids, compare_bits[2]))

    assert bit_0 == 0
    assert bit_1 == 1
    assert bit_2 == 1

    ticket_1 = backend.encrypt(111)
    ticket_2 = backend.encrypt(222)
    ticket_3 = backend.encrypt(333)

    selected = backend.select_first_true(compare_bits, [ticket_1, ticket_2, ticket_3])
    selected_value = backend.decrypt(selected, _collect_shares(backend, participant_ids, selected))
    assert selected_value == 222

    scaled = backend.scale_ciphertext(c1, 3.0)
    scaled_value = backend.decrypt(scaled, _collect_shares(backend, participant_ids, scaled))
    assert scaled_value == 30


def test_initialize_openfhe_backend_via_env_and_full_share_combine() -> None:
    reset_fhe_backend_cache()
    os.environ["POS_FHE_BACKEND"] = "openfhe"
    try:
        facade = initialize_fhe_backend(participant_ids=["P1", "P2", "P3"])
        c = facade.encrypt(7)
        shares = [facade.decrypt_share(pid, c) for pid in ["P1", "P2", "P3"]]
        assert facade.decrypt(c, shares) == 7
    finally:
        os.environ["POS_FHE_BACKEND"] = "compatibility"
        reset_fhe_backend_cache()