from __future__ import annotations

import os

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache
from pos.crypto.thfhe_backend.kms_eval_bridge import KmsTfheEvalBridge


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
            "stage": "stage8_1_kms_cipher_decode",
            "strict_no_plaintext_fallback": True,
            "purpose": "decode real KMS CipherWithParams without plaintext fallback",
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

    eval_bridge = KmsTfheEvalBridge()
    report = eval_bridge.decode_pair(left, right)

    print("=== Stage-8.1 native decode report ===")
    print(report)

    assert report["ok"] is True
    assert report["left"]["data_type"] == "euint8"
    assert report["right"]["data_type"] == "euint8"
    assert report["left"]["ct_format"] == "SmallExpanded"
    assert report["right"]["ct_format"] == "SmallExpanded"
    assert report["left"]["key_id"] == os.environ["POS_KMS_KEY_ID"]
    assert report["right"]["key_id"] == os.environ["POS_KMS_KEY_ID"]
    assert report["left"]["no_compression"] is True
    assert report["right"]["no_compression"] is True
    assert report["left"]["no_precompute_sns"] is True
    assert report["right"]["no_precompute_sns"] is True
    assert report["left"]["cipher_len"] > 0
    assert report["right"]["cipher_len"] > 0
    assert report["server_key_len"] > 0

    print("\nStage-8.1 KMS ciphertext decode check passed.")


if __name__ == "__main__":
    main()
