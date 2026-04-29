use crate::api::DistributedKeygenResponse;
use crate::error::BackendError;
use crate::kms::run_threshold_keygen;
use std::collections::HashMap;

pub fn distributed_keygen(
    participant_ids: Vec<String>,
    threshold: u32,
) -> Result<DistributedKeygenResponse, BackendError> {
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

    // 严格路线：这里必须走外部 threshold 协议执行器
    let resp = run_threshold_keygen(&participant_ids, threshold)?;

    let keyset_reference = resp
        .get("keyset_reference")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BackendError::KmsResponseParseFailed("missing keyset_reference".to_string()))?
        .to_string();

    let public_key = resp
        .get("public_key")
        .ok_or_else(|| BackendError::KmsResponseParseFailed("missing public_key".to_string()))?
        .to_string();

    let mut participant_private_share_handles: HashMap<String, String> = HashMap::new();
    let handles_obj = resp
        .get("participant_private_share_handles")
        .and_then(|v| v.as_object())
        .ok_or_else(|| BackendError::KmsResponseParseFailed("missing participant_private_share_handles".to_string()))?;

    for participant_id in &participant_ids {
        let handle = handles_obj
            .get(participant_id)
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BackendError::KmsResponseParseFailed(format!(
                    "missing participant_private_share_handles[{participant_id}]"
                ))
            })?
            .to_string();
        participant_private_share_handles.insert(participant_id.clone(), handle);
    }

    Ok(DistributedKeygenResponse {
        ok: true,
        backend_name: "thfhe".to_string(),
        public_key,
        keyset_reference,
        participant_private_share_handles,
    })
}