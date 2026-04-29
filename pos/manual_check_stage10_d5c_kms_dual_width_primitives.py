from __future__ import annotations

import os

os.environ["POS_FHE_BACKEND"] = "kms-threshold"
os.environ["POS_STRICT_PATENT_MODE"] = "1"
os.environ["POS_LOTTERY_WORD_BITS"] = "32"
os.environ["POS_TICKET_CHUNK_BITS"] = "16"

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache


def main() -> None:
    reset_fhe_backend_cache()

    fhe = initialize_fhe_backend(
        participant_ids=["P1", "P2", "P3"],
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )

    fhe.setup(
        {
            "stage": "stage10_d5c_kms_dual_width_primitives",
            "strict_no_plaintext_fallback": True,
            "operation": "validate_euint32_lottery_and_euint16_ticket_primitives",
        }
    )

    # Patent election arithmetic domain: euint32.
    stake_a = fhe.encrypt_scalar(
        10,
        data_type="euint32",
        no_compression=True,
        no_precompute_sns=True,
    )
    stake_b = fhe.encrypt_scalar(
        20,
        data_type="euint32",
        no_compression=True,
        no_precompute_sns=True,
    )
    cumulative = fhe.eval_add(stake_a, stake_b, expected_result=30)

    scaled_random = fhe.encrypt_scalar(
        15,
        data_type="euint32",
        no_compression=True,
        no_precompute_sns=True,
    )
    compare_flag = fhe.eval_compare(
        scaled_random,
        cumulative,
        expected_result=True,
    )

    prf = fhe.encrypt_scalar(
        64,
        data_type="euint32",
        no_compression=True,
        no_precompute_sns=True,
    )
    scaled_prf = fhe.eval_scale_prf(
        prf,
        numerator=60,
        denominator=256,
        expected_result=15,
    )

    # Patent ticket suffix chunk domain: euint16.
    ticket_true = fhe.encrypt_scalar(
        0xCAFE,
        data_type="euint16",
        no_compression=True,
        no_precompute_sns=True,
    )
    ticket_false = fhe.encrypt_scalar(
        0x1234,
        data_type="euint16",
        no_compression=True,
        no_precompute_sns=True,
    )
    selected_ticket_chunk = fhe.eval_select(
        compare_flag,
        ticket_true,
        ticket_false,
        expected_result=0xCAFE,
    )

    cumulative_user = fhe.user_decrypt_scalar(cumulative)
    cumulative_public = fhe.public_decrypt_scalar(cumulative)

    compare_user = fhe.user_decrypt_scalar(compare_flag)
    compare_public = fhe.public_decrypt_scalar(compare_flag)

    scaled_prf_user = fhe.user_decrypt_scalar(scaled_prf)
    scaled_prf_public = fhe.public_decrypt_scalar(scaled_prf)

    selected_user = fhe.user_decrypt_scalar(selected_ticket_chunk)
    selected_public = fhe.public_decrypt_scalar(selected_ticket_chunk)

    print("=== Stage-10-D5-C KMS dual-width primitives ===")
    print("euint32 add cumulative user/public:", cumulative_user, cumulative_public)
    print("euint32 compare user/public:", compare_user, compare_public)
    print("euint32 scale_prf user/public:", scaled_prf_user, scaled_prf_public)
    print("euint16 select user/public:", selected_user, selected_public)

    assert cumulative_user == 30
    assert cumulative_public == 30
    assert compare_user == 1
    assert compare_public == 1
    assert scaled_prf_user == 15
    assert scaled_prf_public == 15
    assert selected_user == 0xCAFE
    assert selected_public == 0xCAFE

    print("\nStage-10-D5-C KMS dual-width primitive check passed.")


if __name__ == "__main__":
    main()
