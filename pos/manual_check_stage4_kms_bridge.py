from __future__ import annotations

from pos.crypto.thfhe_backend.kms_bridge import KmsThresholdBridge


def main() -> None:
    bridge = KmsThresholdBridge()

    ciphertext = bridge.encrypt_scalar(7, data_type="euint8")

    print("=== KMS threshold encrypt_scalar ===")
    print(ciphertext.to_public_dict())

    user_plaintext = bridge.user_decrypt_scalar(ciphertext)
    print("\n=== KMS threshold user_decrypt_scalar ===")
    print("plaintext:", user_plaintext)

    public_plaintext = bridge.public_decrypt_scalar(ciphertext)
    print("\n=== KMS threshold public_decrypt_scalar ===")
    print("plaintext:", public_plaintext)

    assert user_plaintext == 7
    assert public_plaintext == 7

    print("\nStage-4 KMS threshold bridge check passed.")


if __name__ == "__main__":
    main()