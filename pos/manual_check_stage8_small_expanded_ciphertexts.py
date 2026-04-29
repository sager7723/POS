from __future__ import annotations

import os

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache


def main() -> None:
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"
    os.environ["POS_STRICT_PATENT_MODE"] = "1"

    reset_fhe_backend_cache()

    fhe = initialize_fhe_backend(
        participant_ids=["P1", "P2", "P3", "P4"],
        threshold=1,
    )

    fhe.setup(
        {
            "stage": "stage8_small_expanded_ciphertext_check",
            "strict_no_plaintext_fallback": True,
            "purpose": "prepare real TFHE evaluator input format",
        }
    )

    left = fhe.encrypt_scalar(
        7,
        data_type="euint8",
        no_compression=True,
        no_precompute_sns=True,
    )
    right = fhe.encrypt_scalar(
        9,
        data_type="euint8",
        no_compression=True,
        no_precompute_sns=True,
    )

    print("=== SmallExpanded ciphertext handles ===")
    print("left:", left.to_json())
    print("right:", right.to_json())

    left_plain_user = fhe.user_decrypt_scalar(left)
    right_plain_user = fhe.user_decrypt_scalar(right)

    left_plain_public = fhe.public_decrypt_scalar(left)
    right_plain_public = fhe.public_decrypt_scalar(right)

    print("\n=== KMS decrypt check ===")
    print("left user:", left_plain_user)
    print("right user:", right_plain_user)
    print("left public:", left_plain_public)
    print("right public:", right_plain_public)

    assert left_plain_user == 7
    assert right_plain_user == 9
    assert left_plain_public == 7
    assert right_plain_public == 9

    print("\nStage-8 SmallExpanded ciphertext check passed.")


if __name__ == "__main__":
    main()