from __future__ import annotations

import os

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache


def main() -> None:
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"

    reset_fhe_backend_cache()

    fhe = initialize_fhe_backend(
        participant_ids=["P1", "P2", "P3", "P4"],
        threshold=1,
    )

    ctx = fhe.setup(
        {
            "stage": "stage6_fhe_entry_kms_check",
            "strict_no_plaintext_fallback": True,
        }
    )

    print("=== initialize_fhe_backend kms-threshold ===")
    print(ctx.to_dict())

    keygen = fhe.distributed_keygen()

    print("\n=== distributed_keygen binding ===")
    print(keygen)

    ciphertext = fhe.encrypt_scalar(7, data_type="euint8")

    print("\n=== encrypt_scalar through pos.crypto.fhe entry ===")
    print(ciphertext.to_json())

    user_plaintext = fhe.user_decrypt_scalar(ciphertext)
    public_plaintext = fhe.public_decrypt_scalar(ciphertext)

    print("\n=== decrypt through pos.crypto.fhe entry ===")
    print("user_plaintext:", user_plaintext)
    print("public_plaintext:", public_plaintext)

    assert user_plaintext == 7
    assert public_plaintext == 7

    try:
        fhe.eval_compare(ciphertext, ciphertext)
    except NotImplementedError as exc:
        print("\n=== strict eval_compare guard ===")
        print(str(exc))
    else:
        raise AssertionError("eval_compare must not use plaintext fallback")

    print("\nStage-6 FHE entry KMS threshold check passed.")


if __name__ == "__main__":
    main()