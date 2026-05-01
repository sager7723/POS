from __future__ import annotations

import json
import os
from pathlib import Path

from pos.crypto.proofs import PatentProofShareGenerator


def make_ciphertext_payload(
    *,
    tmp_dir: Path,
    key_id: str,
    data_type: str,
    ciphertext_id: str,
    body: bytes,
) -> str:
    path = tmp_dir / f"{ciphertext_id}.{data_type}.ct"
    path.write_bytes(body)
    return json.dumps(
        {
            "backend": "kms-threshold",
            "key_id": key_id,
            "data_type": data_type,
            "ciphertext_path": str(path),
            "ciphertext_id": ciphertext_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def assert_opaque_public_data(proof_shares, *, expected_statement: str) -> None:
    if not proof_shares:
        raise AssertionError("proof_shares must not be empty")

    first = proof_shares[0]
    public_data = first.statement_public_data

    required = {
        "strict_opaque_kms_binding",
        "opaque_statement_type",
        "participant_id",
        "public_key",
        "dkg_transcript_hash",
        "public_key_sha256",
        "ciphertext_bindings_json",
        "witness_commitment",
    }
    missing = required - set(public_data)
    if missing:
        raise AssertionError(
            f"missing opaque public data fields: {sorted(missing)}"
        )

    if public_data["strict_opaque_kms_binding"] != "true":
        raise AssertionError("strict_opaque_kms_binding must be true")

    if public_data["opaque_statement_type"] != expected_statement:
        raise AssertionError(
            f"opaque statement mismatch: {public_data['opaque_statement_type']}"
        )

    bindings = json.loads(public_data["ciphertext_bindings_json"])
    if not isinstance(bindings, list) or not bindings:
        raise AssertionError("ciphertext_bindings_json must be non-empty list")

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
    for binding in bindings:
        missing_binding = required_binding_fields - set(binding)
        if missing_binding:
            raise AssertionError(
                f"missing binding fields: {sorted(missing_binding)}"
            )

    public_data_text = json.dumps(public_data, sort_keys=True)
    forbidden = [
        "encoded_value",
        "metadata.noise",
        '"metadata"',
        '"noise"',
        "enc(",
    ]
    for token in forbidden:
        if token in public_data_text:
            raise AssertionError(f"forbidden token in opaque public data: {token}")


def assert_record_ok(record, *, label: str) -> None:
    flags = {
        "polynomial_ok": record.polynomial_ok,
        "share_commitment_ok": record.share_commitment_ok,
        "share_public_key_ok": record.share_public_key_ok,
        "declared_public_key_vector_ok": record.declared_public_key_vector_ok,
        "relation_ok": record.relation_ok,
        "noise_ok": record.noise_ok,
        "recovery_ok": record.recovery_ok,
        "ciphertext_equation_ok": record.ciphertext_equation_ok,
        "commitment_equation_ok": record.commitment_equation_ok,
        "discrete_log_key_ok": record.discrete_log_key_ok,
        "secret_recover_ok": record.secret_recover_ok,
        "public_binding_ok": record.public_binding_ok,
    }
    failed = [name for name, ok in flags.items() if not ok]
    if failed:
        raise AssertionError(f"{label} failed flags: {failed}")


def main() -> None:
    print("=== Stage E-4A Opaque Binding Verify Check ===")

    os.environ["POS_STRICT_PATENT_MODE"] = "1"
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"

    tmp_dir = Path("/tmp/stage_e4_opaque_binding_verify")
    tmp_dir.mkdir(parents=True, exist_ok=True)

    participant_id = "P1"
    public_key = "kms-public-key"
    key_id = "stage-e-key"
    dkg_transcript_hash = "dkg-transcript-hash-stage-e"
    public_key_sha256 = "public-key-sha256-stage-e"

    proof_share_count = 4
    reveal_threshold = 3

    proof_system = PatentProofShareGenerator()

    encrypted_prf_share = make_ciphertext_payload(
        tmp_dir=tmp_dir,
        key_id=key_id,
        data_type="euint32",
        ciphertext_id="prf-share-ct",
        body=b"opaque-prf-share-ciphertext",
    )
    encrypted_stake = make_ciphertext_payload(
        tmp_dir=tmp_dir,
        key_id=key_id,
        data_type="euint32",
        ciphertext_id="stake-ct",
        body=b"opaque-stake-ciphertext",
    )
    encrypted_ticket_chunks = [
        make_ciphertext_payload(
            tmp_dir=tmp_dir,
            key_id=key_id,
            data_type="euint16",
            ciphertext_id=f"ticket-chunk-{idx}",
            body=f"opaque-ticket-ciphertext-{idx}".encode(),
        )
        for idx in range(2)
    ]

    dlog_generator = 5
    dlog_modulus = 23
    key_share_scalar = 7
    declared_share_public_key = f"0x{pow(dlog_generator, key_share_scalar, dlog_modulus):x}"
    declared_share_public_key_set = [declared_share_public_key]

    prf_proof = proof_system.build_prf_share_ciphertext_binding_proof(
        participant_id=participant_id,
        encrypted_prf_share=encrypted_prf_share,
        public_key=public_key,
        prf_share_scalar=11,
        key_share_scalar=key_share_scalar,
        dlog_generator=dlog_generator,
        dlog_modulus=dlog_modulus,
        declared_share_public_key=declared_share_public_key,
        declared_share_public_key_set=declared_share_public_key_set,
        proof_share_count=proof_share_count,
        reveal_threshold=reveal_threshold,
        dkg_transcript_hash=dkg_transcript_hash,
        public_key_sha256=public_key_sha256,
    )
    assert_opaque_public_data(
        prf_proof,
        expected_statement="prf_share_ciphertext_binding",
    )
    prf_revealed = proof_system.reveal_selected_shares(
        prf_proof,
        proof_system.derive_reveal_indices(
            validation_seed="stage-e-seed",
            participant_id=participant_id,
            statement_label="prf_share_correctness",
            proof_share_count=proof_share_count,
            reveal_threshold=reveal_threshold,
        ),
    )
    prf_record = proof_system.verify_prf_share_proof(
        prf_proof,
        prf_revealed,
        expected_ciphertext=encrypted_prf_share,
        expected_public_key_vector=declared_share_public_key_set,
    )
    assert_record_ok(prf_record, label="prf opaque binding")
    print("verified opaque PRF binding proof")

    stake_cipher_proof = proof_system.build_ciphertext_binding_proof(
        participant_id=participant_id,
        ciphertext_payloads=[encrypted_stake],
        public_key=public_key,
        witness_components=[123],
        proof_share_count=proof_share_count,
        reveal_threshold=reveal_threshold,
        proof_label="stake_ciphertext",
        extra_public_data={"plaintext_label": "stake"},
        dkg_transcript_hash=dkg_transcript_hash,
        public_key_sha256=public_key_sha256,
    )
    assert_opaque_public_data(
        stake_cipher_proof,
        expected_statement="stake_ciphertext",
    )
    stake_cipher_revealed = proof_system.reveal_selected_shares(
        stake_cipher_proof,
        proof_system.derive_reveal_indices(
            validation_seed="stage-e-seed",
            participant_id=participant_id,
            statement_label="stake_ciphertext_correctness",
            proof_share_count=proof_share_count,
            reveal_threshold=reveal_threshold,
        ),
    )
    stake_cipher_record = proof_system.verify_ciphertext_encryption_proof(
        stake_cipher_proof,
        stake_cipher_revealed,
        expected_ciphertexts=[encrypted_stake],
        expected_extra_public_data={
            "proof_label": "stake_ciphertext",
            "plaintext_label": "stake",
        },
    )
    assert_record_ok(stake_cipher_record, label="stake ciphertext opaque binding")
    print("verified opaque stake ciphertext binding proof")

    pedersen_g = 5
    pedersen_h = 7
    pedersen_modulus = 23
    stake_scalar = 3
    pedersen_randomness = 4
    commitment_value = (
        pow(pedersen_g, stake_scalar, pedersen_modulus)
        * pow(pedersen_h, pedersen_randomness, pedersen_modulus)
    ) % pedersen_modulus
    stake_commitment = f"pedersen_commit:0x{commitment_value:x}"

    stake_pedersen_proof = proof_system.build_stake_ciphertext_pedersen_binding_proof(
        participant_id=participant_id,
        encrypted_stake=encrypted_stake,
        stake_commitment=stake_commitment,
        public_key=public_key,
        stake_scalar=stake_scalar,
        pedersen_randomness=pedersen_randomness,
        pedersen_g=pedersen_g,
        pedersen_h=pedersen_h,
        pedersen_modulus=pedersen_modulus,
        proof_share_count=proof_share_count,
        reveal_threshold=reveal_threshold,
        dkg_transcript_hash=dkg_transcript_hash,
        public_key_sha256=public_key_sha256,
    )
    assert_opaque_public_data(
        stake_pedersen_proof,
        expected_statement="stake_ciphertext_pedersen_binding",
    )
    stake_pedersen_revealed = proof_system.reveal_selected_shares(
        stake_pedersen_proof,
        proof_system.derive_reveal_indices(
            validation_seed="stage-e-seed",
            participant_id=participant_id,
            statement_label="stake_commitment_consistency",
            proof_share_count=proof_share_count,
            reveal_threshold=reveal_threshold,
        ),
    )
    stake_pedersen_record = proof_system.verify_stake_commitment_consistency_proof(
        stake_pedersen_proof,
        stake_pedersen_revealed,
        expected_ciphertext=encrypted_stake,
        expected_commitment=stake_commitment,
    )
    assert_record_ok(stake_pedersen_record, label="stake pedersen opaque binding")
    print("verified opaque stake Pedersen binding proof")

    ticket_proof = proof_system.build_ticket_suffix_ciphertext_binding_proof(
        participant_id=participant_id,
        ciphertext_payloads=encrypted_ticket_chunks,
        public_key=public_key,
        witness_components=[0x1234, 0x5678],
        proof_share_count=proof_share_count,
        reveal_threshold=reveal_threshold,
        proof_label="ticket_suffix_ciphertext",
        extra_public_data={
            "plaintext_label": "ticket_hash_suffix_chunk_words",
            "encoding_family": "fixed-width",
            "chunk_bit_width": "16",
            "chunk_count": "2",
            "hex_chars_per_chunk": "4",
            "chunk_modulus": "65536",
            "packing_mode": "one-word-per-ciphertext",
            "slot_packing": "false",
            "byte_order": "big",
            "recovery_format": "hex",
        },
        dkg_transcript_hash=dkg_transcript_hash,
        public_key_sha256=public_key_sha256,
    )
    assert_opaque_public_data(
        ticket_proof,
        expected_statement="ticket_suffix_ciphertext",
    )
    ticket_revealed = proof_system.reveal_selected_shares(
        ticket_proof,
        proof_system.derive_reveal_indices(
            validation_seed="stage-e-seed",
            participant_id=participant_id,
            statement_label="ticket_ciphertext_correctness",
            proof_share_count=proof_share_count,
            reveal_threshold=reveal_threshold,
        ),
    )
    ticket_record = proof_system.verify_ciphertext_encryption_proof(
        ticket_proof,
        ticket_revealed,
        expected_ciphertexts=encrypted_ticket_chunks,
        expected_extra_public_data={
            "proof_label": "ticket_suffix_ciphertext",
            "plaintext_label": "ticket_hash_suffix_chunk_words",
            "encoding_family": "fixed-width",
            "chunk_bit_width": "16",
            "chunk_count": "2",
            "hex_chars_per_chunk": "4",
            "chunk_modulus": "65536",
            "packing_mode": "one-word-per-ciphertext",
            "slot_packing": "false",
            "byte_order": "big",
            "recovery_format": "hex",
        },
    )
    assert_record_ok(ticket_record, label="ticket opaque binding")
    print("verified opaque ticket suffix binding proof")

    print("Stage E-4A opaque binding verify check passed.")


if __name__ == "__main__":
    main()
