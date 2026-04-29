from __future__ import annotations

import os

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache
from pos.crypto.ticket import TicketBuilder


def main() -> None:
    os.environ["POS_STRICT_PATENT_MODE"] = "1"
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"

    reset_fhe_backend_cache()

    participant_ids = ["P1"]

    fhe = initialize_fhe_backend(
        participant_ids=participant_ids,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )
    fhe.setup(
        {
            "stage": "stage10_c_kms_ticket_suffix_chunks",
            "strict_no_plaintext_fallback": True,
            "operation": "encrypt_ticket_suffix_as_euint8_chunks",
        }
    )

    # 模拟“后半部分票根哈希”。专利要求加密后半票根哈希；
    # 严格 KMS 路径下用 1 字节 chunk，保证每块都可被 euint8 Cselect 处理。
    suffix_hex = "00010aff80ff"
    suffix_chunks = TicketBuilder._split_suffix_into_chunks(suffix_hex)

    encrypted_chunks = [
        fhe.encrypt_scalar(
            chunk,
            data_type="euint8",
            no_compression=True,
            no_precompute_sns=True,
        )
        for chunk in suffix_chunks
    ]

    decrypted_user = [fhe.user_decrypt_scalar(chunk) for chunk in encrypted_chunks]
    decrypted_public = [fhe.public_decrypt_scalar(chunk) for chunk in encrypted_chunks]

    print("=== Stage-10-C KMS ticket suffix chunk encryption ===")
    print("CHUNK_BYTES:", TicketBuilder.CHUNK_BYTES)
    print("ENCODING_FAMILY:", TicketBuilder.ENCODING_FAMILY)
    print("suffix_hex:", suffix_hex)
    print("suffix_chunks:", suffix_chunks)
    print("decrypted_user:", decrypted_user)
    print("decrypted_public:", decrypted_public)
    print("first_encrypted_chunk:", encrypted_chunks[0])

    assert TicketBuilder.CHUNK_BYTES == 1
    assert TicketBuilder.ENCODING_FAMILY == "hex_suffix_byte"
    assert suffix_chunks == [0, 1, 10, 255, 128, 255]
    assert all(0 <= value <= 255 for value in suffix_chunks)
    assert decrypted_user == suffix_chunks
    assert decrypted_public == suffix_chunks

    first_json = encrypted_chunks[0].to_json() if hasattr(encrypted_chunks[0], "to_json") else str(encrypted_chunks[0])
    assert '"backend": "kms-threshold"' in first_json
    assert '"data_type": "euint8"' in first_json

    print("\nStage-10-C KMS ticket suffix chunk encryption check passed.")


if __name__ == "__main__":
    main()
