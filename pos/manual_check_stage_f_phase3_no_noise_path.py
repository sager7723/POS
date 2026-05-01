from __future__ import annotations

import inspect
from pathlib import Path


CANDIDACY_FORBIDDEN = {
    "_extract_public_noise",
    "_sample_proof_randomizer",
    "ciphertext_noise",
    "ciphertext_noises",
    "noise_values",
    "noise_bound",
    "encryption_randomizer",
    "encryption_randomizers",
    "plaintext_components",
    "metadata",
    "encoded_value",
    "build_prf_share_proof",
    "build_ciphertext_encryption_proof",
    "build_stake_commitment_consistency_proof",
}


def main() -> None:
    print("=== Stage F Phase3 No Noise Path Check ===")

    candidacy_source = Path("pos/protocol/candidacy.py").read_text(encoding="utf-8")

    remaining = sorted(token for token in CANDIDACY_FORBIDDEN if token in candidacy_source)
    if remaining:
        raise AssertionError(
            "candidacy.py still contains forbidden proof-generation tokens: "
            + ", ".join(remaining)
        )

    from pos.crypto.proofs import CiphertextEncryptionCorrectnessProofSystem

    method = CiphertextEncryptionCorrectnessProofSystem.build_opaque_binding_proof
    signature = inspect.signature(method)

    if "witness_components" not in signature.parameters:
        raise AssertionError("opaque binding builder must accept witness_components")
    if "plaintext_components" in signature.parameters:
        raise AssertionError("opaque binding builder must not expose plaintext_components")

    print("candidacy proof-generation source clean")
    print("opaque ciphertext binding builder uses witness_components")
    print("Stage F Phase3 no noise path check passed.")


if __name__ == "__main__":
    main()
