use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("invalid json request: {0}")]
    InvalidJson(String),

    #[error("missing field: {0}")]
    MissingField(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("keyset not found: {0}")]
    KeysetNotFound(String),

    #[error("ciphertext not found: {0}")]
    CiphertextNotFound(String),

    #[error("kms execution is not configured: {0}")]
    KmsNotConfigured(String),

    #[error("kms command failed: {0}")]
    KmsCommandFailed(String),

    #[error("kms response file missing: {0}")]
    KmsResponseMissing(String),

    #[error("kms response parse failed: {0}")]
    KmsResponseParseFailed(String),

    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub ok: bool,
    pub error: String,
}

impl BackendError {
    pub fn to_error_response(&self) -> ErrorResponse {
        ErrorResponse {
            ok: false,
            error: self.to_string(),
        }
    }
}