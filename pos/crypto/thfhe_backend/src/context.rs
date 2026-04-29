use crate::error::BackendError;
use crate::handles::{KeysetBundle, KEYSETS};
use serde_json::json;
use tfhe::{generate_keys, set_server_key, ConfigBuilder};
use uuid::Uuid;

pub fn create_keyset(participant_ids: Vec<String>, threshold: u32) -> Result<String, BackendError> {
    if participant_ids.is_empty() {
        return Err(BackendError::InvalidArgument(
            "participant_ids must not be empty".to_string(),
        ));
    }
    if threshold == 0 || threshold as usize > participant_ids.len() {
        return Err(BackendError::InvalidArgument(
            "threshold must satisfy 1 <= threshold <= len(participant_ids)".to_string(),
        ));
    }

    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    // 为当前线程设置高层 API server key，使 FheUint32 的运算可用
    set_server_key(server_key.clone());

    let keyset_reference = format!("thfhe-keyset://{}", Uuid::new_v4());
    let bundle = KeysetBundle {
        client_key,
        server_key,
        participant_ids,
        threshold,
    };

    KEYSETS
        .lock()
        .map_err(|_| BackendError::Internal("failed to lock KEYSETS".to_string()))?
        .insert(keyset_reference.clone(), bundle);

    Ok(keyset_reference)
}

pub fn default_params_json() -> serde_json::Value {
    json!({
        "scheme": "tfhe_rs_integer_stage1",
        "family": "tfhe",
        "ciphertext_kind": "FheUint32",
        "notes": "Stage-1 real native backend over TFHE-rs high-level Rust API; threshold decomposition is not implemented yet."
    })
}