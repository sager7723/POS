from __future__ import annotations

import inspect

from pos.crypto.proofs import (
    KmsCiphertextPublicBinding,
    PRFShareCiphertextBindingProof,
    PatentProofShareGenerator,
    StakeCiphertextPedersenConsistencyProof,
    TicketSuffixCiphertextBindingProof,
)


def main() -> None:
    print("=== Stage E Opaque KMS Proof Check ===")

    required_binding_fields = {
        "dkg_transcript_hash",
        "kms_key_id",
        "ciphertext_id",
        "ciphertext_path_hash",
        "public_key_sha256",
        "participant_id",
        "statement_type",
        "data_type",
        "ciphertext_path",
    }
    binding_fields = set(KmsCiphertextPublicBinding.__dataclass_fields__)
    missing = required_binding_fields - binding_fields
    if missing:
        raise AssertionError(
            "KmsCiphertextPublicBinding missing fields: "
            + ", ".join(sorted(missing))
        )

    for cls in [
        PRFShareCiphertextBindingProof,
        StakeCiphertextPedersenConsistencyProof,
        TicketSuffixCiphertextBindingProof,
    ]:
        if "proof_shares" not in cls.__dataclass_fields__:
            raise AssertionError(f"{cls.__name__} missing proof_shares")
        print("binding proof dataclass clean:", cls.__name__)

    generator = PatentProofShareGenerator()

    for method_name in [
        "build_prf_share_ciphertext_binding_proof",
        "build_stake_ciphertext_pedersen_binding_proof",
        "build_ticket_suffix_ciphertext_binding_proof",
        "build_ciphertext_binding_proof",
    ]:
        method = getattr(generator, method_name)
        signature = inspect.signature(method)
        if "kwargs" not in signature.parameters:
            raise AssertionError(f"{method_name} should be kwargs passthrough")
        print("opaque builder available:", method_name)

    print("Stage E opaque KMS proof check passed.")


if __name__ == "__main__":
    main()
