from __future__ import annotations

import os

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache


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

    fhe = initialize_fhe_backend(
        participant_ids=["P1", "P2", "P3", "P4"],
        threshold=1,
    )

    fhe.setup(
        {
            "stage": "stage8_4_kms_eval_select",
            "strict_no_plaintext_fallback": True,
            "operation": "real_tfhe_ebool_cmux_euint8",
            "note": "expected_result is test metadata only; selection is computed by TFHE.",
        }
    )

    true_value = encrypt_u8(fhe, 11)
    false_value = encrypt_u8(fhe, 22)

    selector_true = fhe.eval_compare(
        encrypt_u8(fhe, 7),
        encrypt_u8(fhe, 9),
        expected_result=True,
    )

    selector_false = fhe.eval_compare(
        encrypt_u8(fhe, 9),
        encrypt_u8(fhe, 7),
        expected_result=False,
    )

    selected_true = fhe.eval_select(
        selector_true,
        true_value,
        false_value,
        expected_result=11,
    )

    selected_false = fhe.eval_select(
        selector_false,
        true_value,
        false_value,
        expected_result=22,
    )

    selected_true_user = fhe.user_decrypt_scalar(selected_true)
    selected_true_public = fhe.public_decrypt_scalar(selected_true)

    selected_false_user = fhe.user_decrypt_scalar(selected_false)
    selected_false_public = fhe.public_decrypt_scalar(selected_false)

    print("=== Stage-8.4 KMS TFHE eval_select / CMUX ===")
    print(f"selector=true  => user={selected_true_user}, public={selected_true_public}, expected=11")
    print(f"selector=false => user={selected_false_user}, public={selected_false_public}, expected=22")

    assert selected_true_user == 11
    assert selected_true_public == 11
    assert selected_false_user == 22
    assert selected_false_public == 22

    print("\nStage-8.4 KMS TFHE eval_select check passed.")


if __name__ == "__main__":
    main()
