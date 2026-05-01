from __future__ import annotations

import inspect
from pathlib import Path

from pos.crypto.proofs import (
    CiphertextEncryptionCorrectnessProofSystem,
    KmsCiphertextPublicBinding,
    PatentProofShareGenerator,
)
from pos.models.stage3 import CandidateMessage, Phase3Result, PublicProofShare
from pos.models.stage4 import Phase4Result, ProofVerificationRecord, ValidationResult
from pos.models.stage5 import Phase5Result, PublicRevealObject
from pos.protocol import candidacy, election, patent_phase4, patent_step18, patent_step20, reveal


STRICT_PATH_FILES = [
    Path("pos/crypto/proofs.py"),
    Path("pos/protocol/candidacy.py"),
    Path("pos/protocol/election.py"),
    Path("pos/protocol/patent_phase4.py"),
    Path("pos/protocol/patent_step18.py"),
    Path("pos/protocol/patent_step20.py"),
    Path("pos/protocol/reveal.py"),
    Path("pos/crypto/thfhe_backend/kms_eval_bridge.py"),
    Path("pos/crypto/thfhe_backend/kms_fhe_backend.py"),
]

STRICT_FORBIDDEN = {
    "expected_result",
    "expected_index",
    "expected_winner",
    "expected_winner_index",
    "winner_index_for_test",
    "expected_stakes_for_test",
    "expected_prf_shares_for_test",
    "expected_ticket_chunks_for_test",
    "expected_scaled_random_for_test",
    "expected_plaintexts_for_test",
    "POS_KMS_EVAL_ADD_EXPECTED_RESULT",
    "POS_KMS_EVAL_SCALE_PRF_EXPECTED_RESULT",
    "POS_KMS_EVAL_COMPARE_EXPECTED_RESULT",
    "POS_KMS_EVAL_SELECT_EXPECTED_RESULT",
    "POS_KMS_EVAL_LOCATE_EXPECTED_INDEX",
    "encoded_value",
    "metadata.noise",
    "decrypt_all",
    "all_tickets",
    "all_ticket",
}


def assert_forbidden_clean() -> None:
    for path in STRICT_PATH_FILES:
        source = path.read_text(encoding="utf-8")
        remaining = sorted(token for token in STRICT_FORBIDDEN if token in source)

        # Step14 is allowed to reveal only total stake via public/threshold decrypt.
        if path.name == "patent_phase4.py":
            remaining = [
                token for token in remaining
                if token not in {"expected_result", "expected_index"}
            ]

        # kms_fhe_backend.py may mention encoded_value only in comments/error text
        # that explicitly reject plaintext fallback. Actual attribute/dict access
        # is checked separately below.
        if path.name == "kms_fhe_backend.py" and "encoded_value" in remaining:
            actual_encoded_value_access = [
                ".encoded_value",
                "['encoded_value']",
                '[\"encoded_value\"]',
                ".get(\"encoded_value\"",
                ".get('encoded_value'",
            ]
            if not any(pattern in source for pattern in actual_encoded_value_access):
                remaining = [token for token in remaining if token != "encoded_value"]

        if remaining:
            raise AssertionError(f"{path} contains forbidden strict-path tokens: {remaining}")

        print("strict source clean:", path)


def assert_phase2_model_has_transcript() -> None:
    from pos.models.stage2 import DistributedKeyGenerationResult

    fields = set(DistributedKeyGenerationResult.__dataclass_fields__)
    if "dkg_transcript" not in fields:
        raise AssertionError("DistributedKeyGenerationResult must contain dkg_transcript")
    print("Phase2 model contains dkg_transcript")


def assert_phase3_opaque_proof_path() -> None:
    candidacy_source = Path("pos/protocol/candidacy.py").read_text(encoding="utf-8")

    required_calls = [
        "build_prf_share_ciphertext_binding_proof",
        "build_ciphertext_binding_proof",
        "build_stake_ciphertext_pedersen_binding_proof",
        "build_ticket_suffix_ciphertext_binding_proof",
        "witness_components",
    ]
    missing = [item for item in required_calls if item not in candidacy_source]
    if missing:
        raise AssertionError(f"candidacy.py missing strict opaque proof calls: {missing}")

    forbidden = [
        "_extract_public_noise",
        "ciphertext_noise",
        "noise_values",
        "encryption_randomizer",
        "plaintext_components",
        "metadata",
        "encoded_value",
    ]
    remaining = [item for item in forbidden if item in candidacy_source]
    if remaining:
        raise AssertionError(f"candidacy.py still contains Phase3 leakage path: {remaining}")

    method_sig = inspect.signature(CiphertextEncryptionCorrectnessProofSystem.build_opaque_binding_proof)
    if "witness_components" not in method_sig.parameters:
        raise AssertionError("opaque binding proof builder must accept witness_components")
    if "plaintext_components" in method_sig.parameters:
        raise AssertionError("opaque binding proof builder must not expose plaintext_components")

    binding_fields = set(KmsCiphertextPublicBinding.__dataclass_fields__)
    required_binding = {
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
    missing_binding = required_binding - binding_fields
    if missing_binding:
        raise AssertionError(f"KmsCiphertextPublicBinding missing fields: {sorted(missing_binding)}")

    print("Phase3 opaque KMS proof path structurally clean")


def assert_step11_binding_expectations() -> None:
    source = Path("pos/protocol/election.py").read_text(encoding="utf-8")

    if '"witness_label": "stake"' not in source:
        raise AssertionError("Step11 must verify stake_ciphertext proof with witness_label=stake")
    if '"plaintext_label": "stake"' in source:
        raise AssertionError("Step11 must not expect plaintext_label=stake after Stage F")

    if "_adapt_kms_external_ciphertext_equation" in source:
        raise AssertionError("Step11 must not use legacy KMS ciphertext equation adapter")

    print("Step11 opaque proof verification expectations clean")


def assert_phase4_no_winner_index() -> None:
    step18_fields = set(patent_step18.PatentStep18WinnerSelectionResult.__dataclass_fields__)
    forbidden_step18_fields = {
        "expected_winner_index",
        "winner_index",
        "expected_compare_bits",
        "expected_winning_ticket_chunks",
    }
    remaining = step18_fields & forbidden_step18_fields
    if remaining:
        raise AssertionError(f"Step18 result exposes forbidden winner oracle fields: {remaining}")

    phase4_fields = set(Phase4Result.__dataclass_fields__)
    if "winning_ticket_ciphertext" not in phase4_fields:
        raise AssertionError("Phase4Result must expose winning_ticket_ciphertext")
    if "winner_index" in phase4_fields:
        raise AssertionError("Phase4Result must not expose winner_index")

    phase4_source = inspect.getsource(patent_phase4.run_phase4_patent_complete_election)
    for required in ["eval_scale_prf", "step18_patent_select_winner_ticket_from_candidate_messages"]:
        if required not in phase4_source:
            raise AssertionError(f"strict Phase4 missing {required}")

    print("Phase4/Step18 no winner-index oracle structure clean")


def assert_stage_g_reveal_chain() -> None:
    patent_step19_source = inspect.getsource(
        patent_step20.step19_generate_winning_ticket_decryption_shares
    )
    patent_step20_source = inspect.getsource(
        patent_step20.step20_recover_winning_ticket_chunks
    )
    reveal_step23_source = inspect.getsource(reveal.step23_verify_winner)
    run_phase5_source = inspect.getsource(reveal.run_phase5_reveal)

    if "winning_ticket_ciphertext" not in patent_step19_source:
        raise AssertionError("Patent Step19 must operate on winning_ticket_ciphertext")
    if "decrypt_share" not in patent_step19_source:
        raise AssertionError("Patent Step19 must call decrypt_share")
    if "fhe.decrypt(" not in patent_step20_source:
        raise AssertionError("Patent Step20 must combine shares with fhe.decrypt")
    if "user_decrypt_scalar" in patent_step19_source + patent_step20_source:
        raise AssertionError("Patent Step19/20 must not call user_decrypt_scalar")

    if "ticket_artifact.ticket_hash_suffix" in reveal_step23_source:
        raise AssertionError("Step23 must not use local ticket suffix artifact oracle")
    if "strict reveal requires phase4_result" not in run_phase5_source:
        raise AssertionError("strict Phase5 must require phase4_result")

    print("Stage G reveal chain structure clean")


def assert_core_models_present() -> None:
    for cls in [
        PublicProofShare,
        CandidateMessage,
        Phase3Result,
        ProofVerificationRecord,
        ValidationResult,
        Phase4Result,
        PublicRevealObject,
        Phase5Result,
    ]:
        if not getattr(cls, "__dataclass_fields__", None):
            raise AssertionError(f"{cls.__name__} must be a dataclass")
        print("model dataclass present:", cls.__name__)


def main() -> None:
    print("=== Stage H Strict End-to-End Structural Check ===")

    assert_forbidden_clean()
    assert_phase2_model_has_transcript()
    assert_phase3_opaque_proof_path()
    assert_step11_binding_expectations()
    assert_phase4_no_winner_index()
    assert_stage_g_reveal_chain()
    assert_core_models_present()

    print("Stage H strict end-to-end structural check passed.")


if __name__ == "__main__":
    main()
