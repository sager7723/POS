from __future__ import annotations

import os
from types import SimpleNamespace

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache
from pos.protocol.patent_phase4 import run_phase4_patent_complete_election


def encrypt_u8(fhe, value: int):
    return fhe.encrypt_scalar(
        value,
        data_type="euint8",
        no_compression=True,
        no_precompute_sns=True,
    )


def main() -> None:
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"
    os.environ["POS_STRICT_PATENT_MODE"] = "1"

    reset_fhe_backend_cache()

    participant_ids = ["P1", "P2", "P3"]

    stakes = [10, 20, 30]
    prf_shares = [20, 44, 0]
    ticket_chunks = [
        [101, 102],
        [201, 202],
        [77, 78],
    ]

    expected_total_stake = 60
    expected_combined_prf = 64
    expected_scaled_random = 15
    expected_cumulative = [10, 30, 60]
    expected_compare_bits = [0, 1, 1]
    expected_onehot = [0, 1, 0]
    expected_winning_ticket = [201, 202]

    fhe_for_inputs = initialize_fhe_backend(
        participant_ids=participant_ids,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )
    fhe_for_inputs.setup(
        {
            "stage": "stage10_b_candidate_input_generation",
            "strict_no_plaintext_fallback": True,
            "operation": "generate_kms_candidate_message_ciphertexts",
        }
    )

    candidate_messages = {}
    for participant_id, stake, prf_share, chunks in zip(
        participant_ids,
        stakes,
        prf_shares,
        ticket_chunks,
    ):
        candidate_messages[participant_id] = SimpleNamespace(
            participant_id=participant_id,
            encrypted_stake=encrypt_u8(fhe_for_inputs, stake),
            encrypted_prf_share=encrypt_u8(fhe_for_inputs, prf_share),
            encrypted_ticket=[encrypt_u8(fhe_for_inputs, chunk) for chunk in chunks],
        )

    # Critical check:
    # Do NOT pass expected_stakes_for_test, expected_prf_shares_for_test,
    # expected_ticket_chunks_for_test, or expected_winner_index_for_test.
    result = run_phase4_patent_complete_election(
        candidate_messages,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
        prf_modulus=256,
    )

    fhe_for_verify = initialize_fhe_backend(
        participant_ids=participant_ids,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )

    total_stake_user = fhe_for_verify.user_decrypt_scalar(result.total_stake_ciphertext)
    total_stake_public = fhe_for_verify.public_decrypt_scalar(result.total_stake_ciphertext)

    combined_prf_user = fhe_for_verify.user_decrypt_scalar(result.combined_prf_ciphertext)
    combined_prf_public = fhe_for_verify.public_decrypt_scalar(result.combined_prf_ciphertext)

    scaled_random_user = fhe_for_verify.user_decrypt_scalar(result.scaled_random_ciphertext)
    scaled_random_public = fhe_for_verify.public_decrypt_scalar(result.scaled_random_ciphertext)

    cumulative_user = [
        fhe_for_verify.user_decrypt_scalar(ciphertext)
        for ciphertext in result.step18_result.cumulative_stake_ciphertexts
    ]
    cumulative_public = [
        fhe_for_verify.public_decrypt_scalar(ciphertext)
        for ciphertext in result.step18_result.cumulative_stake_ciphertexts
    ]

    compare_user = [
        fhe_for_verify.user_decrypt_scalar(flag)
        for flag in result.step18_result.compare_bits
    ]
    compare_public = [
        fhe_for_verify.public_decrypt_scalar(flag)
        for flag in result.step18_result.compare_bits
    ]

    onehot_user = [
        fhe_for_verify.user_decrypt_scalar(flag)
        for flag in result.step18_result.winner_onehot_flags
    ]
    onehot_public = [
        fhe_for_verify.public_decrypt_scalar(flag)
        for flag in result.step18_result.winner_onehot_flags
    ]

    winning_ticket_user = [
        fhe_for_verify.user_decrypt_scalar(chunk)
        for chunk in result.winning_ticket_ciphertext
    ]
    winning_ticket_public = [
        fhe_for_verify.public_decrypt_scalar(chunk)
        for chunk in result.winning_ticket_ciphertext
    ]

    print("=== Stage-10-B patent Phase-4 without expected metadata ===")
    print("participant_ids:", result.participant_ids)
    print("total_stake_user:", total_stake_user)
    print("total_stake_public:", total_stake_public)
    print("expected_total_stake:", expected_total_stake)
    print("combined_prf_user:", combined_prf_user)
    print("combined_prf_public:", combined_prf_public)
    print("expected_combined_prf:", expected_combined_prf)
    print("scaled_random_user:", scaled_random_user)
    print("scaled_random_public:", scaled_random_public)
    print("expected_scaled_random:", expected_scaled_random)
    print("cumulative_user:", cumulative_user)
    print("cumulative_public:", cumulative_public)
    print("expected_cumulative:", expected_cumulative)
    print("compare_user:", compare_user)
    print("compare_public:", compare_public)
    print("expected_compare_bits:", expected_compare_bits)
    print("onehot_user:", onehot_user)
    print("onehot_public:", onehot_public)
    print("expected_onehot:", expected_onehot)
    print("winning_ticket_user:", winning_ticket_user)
    print("winning_ticket_public:", winning_ticket_public)
    print("expected_winning_ticket:", expected_winning_ticket)

    assert result.participant_ids == participant_ids
    assert total_stake_user == expected_total_stake
    assert total_stake_public == expected_total_stake
    assert combined_prf_user == expected_combined_prf
    assert combined_prf_public == expected_combined_prf
    assert scaled_random_user == expected_scaled_random
    assert scaled_random_public == expected_scaled_random
    assert cumulative_user == expected_cumulative
    assert cumulative_public == expected_cumulative
    assert compare_user == expected_compare_bits
    assert compare_public == expected_compare_bits
    assert onehot_user == expected_onehot
    assert onehot_public == expected_onehot
    assert winning_ticket_user == expected_winning_ticket
    assert winning_ticket_public == expected_winning_ticket

    print("\nStage-10-B patent Phase-4 no-expected-metadata check passed.")


if __name__ == "__main__":
    main()
