from __future__ import annotations

from pos.crypto.thfhe_backend.kms_fhe_backend import KmsThresholdFHEBackend


def main() -> None:
    backend = KmsThresholdFHEBackend.from_env(
        participant_ids=["P1", "P2", "P3", "P4"],
        threshold=1,
    )

    context = backend.setup(
        {
            "stage": "stage5_kms_backend_check",
            "strict_no_plaintext_fallback": True,
        }
    )

    print("=== KMS threshold backend setup ===")
    print(context.to_dict())

    keygen = backend.distributed_keygen()

    print("\n=== KMS threshold distributed_keygen binding ===")
    print(keygen)

    ciphertext = backend.encrypt_scalar(7, data_type="euint8")

    print("\n=== KMS threshold backend encrypt_scalar ===")
    print(ciphertext.to_json())

    user_plaintext = backend.user_decrypt_scalar(ciphertext)
    public_plaintext = backend.public_decrypt_scalar(ciphertext)

    print("\n=== KMS threshold backend decrypt ===")
    print("user_plaintext:", user_plaintext)
    print("public_plaintext:", public_plaintext)

    assert user_plaintext == 7
    assert public_plaintext == 7

    try:
        backend.eval_compare(ciphertext, ciphertext)
    except NotImplementedError as exc:
        print("\n=== strict eval_compare guard ===")
        print(str(exc))
    else:
        raise AssertionError("eval_compare must not silently fall back to plaintext")

    print("\nStage-5 KMS threshold backend check passed.")


if __name__ == "__main__":
    main()