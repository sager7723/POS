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
            "stage": "stage8_2_kms_eval_compare",
            "strict_no_plaintext_fallback": True,
            "operation": "real_tfhe_euint8_lt",
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

    compare_ct = fhe.eval_compare(left, right)

    print("=== Stage-8.2 eval_compare ciphertext ===")
    print(compare_ct.to_json())

    user_plaintext = fhe.user_decrypt_scalar(compare_ct)
    public_plaintext = fhe.public_decrypt_scalar(compare_ct)

    print("\n=== Stage-8.2 KMS threshold decrypt of compare result ===")
    print("user_plaintext:", user_plaintext)
    print("public_plaintext:", public_plaintext)

    assert user_plaintext == 1
    assert public_plaintext == 1

    print("\nStage-8.2 KMS TFHE eval_compare check passed.")


if __name__ == "__main__":
    main()
