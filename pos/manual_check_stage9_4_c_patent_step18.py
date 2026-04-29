from __future__ import annotations

import os

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache
from pos.protocol.patent_step18 import step18_patent_select_winner_ticket


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
    scaled_random = 15

    # 每个参与者两个 ticket suffix chunk，模拟专利步骤18选择“中签者加密票根”。
    ticket_chunks = [
        [101, 102],
        [201, 202],
        [77, 78],
    ]

    expected_winner_index = 1
    expected_cumulative = [10, 30, 60]
    expected_compare_bits = [0, 1, 1]
    expected_onehot = [0, 1, 0]
    expected_winning_ticket = [201, 202]

    fhe = initialize_fhe_backend(
        participant_ids=participant_ids,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )

    fhe.setup(
        {
            "stage": "stage9_4_c_patent_step18",
            "strict_no_plaintext_fallback": True,
            "operation": "patent_step18_cumulative_compare_locate_select_ticket",
        }
    )

    encrypted_stakes = [encrypt_u8(fhe, value) for value in stakes]
    scaled_random_ciphertext = encrypt_u8(fhe, scaled_random)
    encrypted_ticket_chunks = [
        [encrypt_u8(fhe, value) for value in chunks]
        for chunks in ticket_chunks
    ]

    result = step18_patent_select_winner_ticket(
        fhe,
        participant_ids,
        encrypted_stakes,
        scaled_random_ciphertext,
        encrypted_ticket_chunks,
        expected_stakes_for_test=stakes,
        expected_scaled_random_for_test=scaled_random,
        expected_ticket_chunks_for_test=ticket_chunks,
        expected_winner_index_for_test=expected_winner_index,
    )

    cumulative_user = [
        fhe.user_decrypt_scalar(ciphertext)
        for ciphertext in result.cumulative_stake_ciphertexts
    ]
    cumulative_public = [
        fhe.public_decrypt_scalar(ciphertext)
        for ciphertext in result.cumulative_stake_ciphertexts
    ]

    compare_user = [
        fhe.user_decrypt_scalar(flag)
        for flag in result.compare_bits
    ]
    compare_public = [
        fhe.public_decrypt_scalar(flag)
        for flag in result.compare_bits
    ]

    onehot_user = [
        fhe.user_decrypt_scalar(flag)
        for flag in result.winner_onehot_flags
    ]
    onehot_public = [
        fhe.public_decrypt_scalar(flag)
        for flag in result.winner_onehot_flags
    ]

    winning_ticket_user = [
        fhe.user_decrypt_scalar(chunk)
        for chunk in result.winning_ticket_ciphertext
    ]
    winning_ticket_public = [
        fhe.public_decrypt_scalar(chunk)
        for chunk in result.winning_ticket_ciphertext
    ]

    print("=== Stage-9.4-C patent step18 ===")
    print("participant_ids:", participant_ids)
    print("stakes:", stakes)
    print("scaled_random:", scaled_random)
    print("ticket_chunks:", ticket_chunks)
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
    assert result.expected_winner_index == expected_winner_index
    assert result.expected_cumulative_stakes == expected_cumulative
    assert result.expected_compare_bits == expected_compare_bits
    assert result.expected_winning_ticket_chunks == expected_winning_ticket

    assert cumulative_user == expected_cumulative
    assert cumulative_public == expected_cumulative
    assert compare_user == expected_compare_bits
    assert compare_public == expected_compare_bits
    assert onehot_user == expected_onehot
    assert onehot_public == expected_onehot
    assert winning_ticket_user == expected_winning_ticket
    assert winning_ticket_public == expected_winning_ticket

    print("\nStage-9.4-C patent step18 check passed.")


if __name__ == "__main__":
    main()
