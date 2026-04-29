from __future__ import annotations

import os


def main() -> None:
    os.environ["POS_STRICT_PATENT_MODE"] = "1"
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"

    # Import after env is set because TicketBuilder.CHUNK_BYTES is backend-sensitive.
    from pos.crypto.ticket import TicketBuilder

    suffix_hex = "00010aff80ff"
    chunks = TicketBuilder._split_suffix_into_chunks(suffix_hex)

    print("=== Stage-10-C strict KMS ticket chunk layout ===")
    print("CHUNK_BYTES:", TicketBuilder.CHUNK_BYTES)
    print("ENCODING_FAMILY:", TicketBuilder.ENCODING_FAMILY)
    print("suffix_hex:", suffix_hex)
    print("chunks:", chunks)

    assert TicketBuilder.CHUNK_BYTES == 1
    assert TicketBuilder.ENCODING_FAMILY == "hex_suffix_byte"
    assert chunks == [0, 1, 10, 255, 128, 255]
    assert all(0 <= value <= 255 for value in chunks)

    print("\nStage-10-C strict KMS ticket chunks are euint8-compatible.")


if __name__ == "__main__":
    main()
