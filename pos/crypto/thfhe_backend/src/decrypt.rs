use crate::api::{
    FinalDecryptRequest, FinalDecryptResponse, PartialDecryptRequest, PartialDecryptResponse,
};
use crate::error::BackendError;
use crate::kms::{run_threshold_final_decrypt, run_threshold_partial_decrypt};
use serde_json::json;

pub fn partial_decrypt(
    request: PartialDecryptRequest,
) -> Result<PartialDecryptResponse, BackendError> {
    if request.ciphertext.backend != "thfhe" {
        return Err(BackendError::InvalidArgument(
            "ciphertext backend must be 'thfhe'".to_string(),
        ));
    }

    if request.keyset_reference.trim().is_empty() {
        return Err(BackendError::MissingField(
            "keyset_reference".to_string(),
        ));
    }

    if request.participant_id.trim().is_empty() {
        return Err(BackendError::MissingField(
            "participant_id".to_string(),
        ));
    }

    if request.share_handle.trim().is_empty() {
        return Err(BackendError::MissingField(
            "share_handle".to_string(),
        ));
    }

    let ciphertext_json = json!({
        "backend": request.ciphertext.backend,
        "encoded_value": request.ciphertext.encoded_value,
        "metadata": request.ciphertext.metadata,
    });

    let resp = run_threshold_partial_decrypt(
        &request.keyset_reference,
        &request.participant_id,
        &request.share_handle,
        &ciphertext_json,
    )?;

    let share = resp
        .get("share")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            BackendError::KmsResponseParseFailed("missing share".to_string())
        })?
        .to_string();

    Ok(PartialDecryptResponse { ok: true, share })
}

pub fn final_decrypt(
    request: FinalDecryptRequest,
) -> Result<FinalDecryptResponse, BackendError> {
    if request.ciphertext.backend != "thfhe" {
        return Err(BackendError::InvalidArgument(
            "ciphertext backend must be 'thfhe'".to_string(),
        ));
    }

    if request.keyset_reference.trim().is_empty() {
        return Err(BackendError::MissingField(
            "keyset_reference".to_string(),
        ));
    }

    if request.shares.is_empty() {
        return Err(BackendError::InvalidArgument(
            "shares must not be empty".to_string(),
        ));
    }

    let ciphertext_json = json!({
        "backend": request.ciphertext.backend,
        "encoded_value": request.ciphertext.encoded_value,
        "metadata": request.ciphertext.metadata,
    });

    let resp = run_threshold_final_decrypt(
        &request.keyset_reference,
        &ciphertext_json,
        &request.shares,
    )?;

    let plaintext = resp
        .get("plaintext")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| {
            BackendError::KmsResponseParseFailed("missing plaintext".to_string())
        })?;

    Ok(FinalDecryptResponse {
        ok: true,
        plaintext,
    })
}