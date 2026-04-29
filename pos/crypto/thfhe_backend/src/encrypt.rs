use crate::api::{
    BinaryCiphertextRequest, CiphertextInput, CiphertextResponse, SumCiphertextsRequest,
};
use crate::error::BackendError;
use crate::handles::{CiphertextBundle, CiphertextKind, CIPHERTEXTS, KEYSETS};
use serde_json::Value;
use std::collections::HashMap;
use tfhe::prelude::*;
use tfhe::{set_server_key, FheBool, FheUint32};
use uuid::Uuid;

pub fn keyset_exists(keyset_reference: &str) -> Result<(), BackendError> {
    let keysets = KEYSETS
        .lock()
        .map_err(|_| BackendError::Internal("failed to lock KEYSETS".to_string()))?;
    if keysets.contains_key(keyset_reference) {
        Ok(())
    } else {
        Err(BackendError::KeysetNotFound(keyset_reference.to_string()))
    }
}

pub fn fetch_keyset(
    keyset_reference: &str,
) -> Result<(tfhe::ClientKey, tfhe::ServerKey), BackendError> {
    let keysets = KEYSETS
        .lock()
        .map_err(|_| BackendError::Internal("failed to lock KEYSETS".to_string()))?;
    let bundle = keysets
        .get(keyset_reference)
        .ok_or_else(|| BackendError::KeysetNotFound(keyset_reference.to_string()))?;
    Ok((bundle.client_key.clone(), bundle.server_key.clone()))
}

fn next_handle() -> String {
    format!("thfhe-ct://{}", Uuid::new_v4())
}

pub fn store_uint32_ciphertext(
    keyset_reference: &str,
    encoded_value: i64,
    value: FheUint32,
    mut extra_metadata: HashMap<String, Value>,
) -> Result<CiphertextResponse, BackendError> {
    let handle = next_handle();
    extra_metadata.insert("token".to_string(), Value::String(handle.clone()));

    CIPHERTEXTS
        .lock()
        .map_err(|_| BackendError::Internal("failed to lock CIPHERTEXTS".to_string()))?
        .insert(
            handle.clone(),
            CiphertextBundle {
                value: CiphertextKind::Uint32(value),
                encoded_value,
                keyset_reference: keyset_reference.to_string(),
            },
        );

    Ok(CiphertextResponse {
        ok: true,
        backend: "thfhe".to_string(),
        encoded_value,
        metadata: extra_metadata,
    })
}

pub fn store_bool_ciphertext(
    keyset_reference: &str,
    value: FheBool,
    mut extra_metadata: HashMap<String, Value>,
) -> Result<CiphertextResponse, BackendError> {
    let handle = next_handle();
    extra_metadata.insert("token".to_string(), Value::String(handle.clone()));

    // 这里 encoded_value 不再泄露明文布尔值，统一置 0
    CIPHERTEXTS
        .lock()
        .map_err(|_| BackendError::Internal("failed to lock CIPHERTEXTS".to_string()))?
        .insert(
            handle.clone(),
            CiphertextBundle {
                value: CiphertextKind::Bool(value),
                encoded_value: 0,
                keyset_reference: keyset_reference.to_string(),
            },
        );

    Ok(CiphertextResponse {
        ok: true,
        backend: "thfhe".to_string(),
        encoded_value: 0,
        metadata: extra_metadata,
    })
}

fn load_ciphertext_raw(input: &CiphertextInput) -> Result<CiphertextBundle, BackendError> {
    if input.backend != "thfhe" {
        return Err(BackendError::InvalidArgument(format!(
            "ciphertext backend must be 'thfhe', got '{}'",
            input.backend
        )));
    }

    let token = input
        .metadata
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BackendError::MissingField("metadata.token".to_string()))?;

    let guard = CIPHERTEXTS
        .lock()
        .map_err(|_| BackendError::Internal("failed to lock CIPHERTEXTS".to_string()))?;
    let stored = guard
        .get(token)
        .ok_or_else(|| BackendError::CiphertextNotFound(token.to_string()))?;

    Ok(CiphertextBundle {
        value: match &stored.value {
            CiphertextKind::Uint32(v) => CiphertextKind::Uint32(v.clone()),
            CiphertextKind::Bool(v) => CiphertextKind::Bool(v.clone()),
        },
        encoded_value: stored.encoded_value,
        keyset_reference: stored.keyset_reference.clone(),
    })
}

pub fn load_uint32_ciphertext(input: &CiphertextInput) -> Result<CiphertextBundle, BackendError> {
    let bundle = load_ciphertext_raw(input)?;
    match bundle.value {
        CiphertextKind::Uint32(_) => Ok(bundle),
        CiphertextKind::Bool(_) => Err(BackendError::InvalidArgument(
            "expected uint32 ciphertext, got bool ciphertext".to_string(),
        )),
    }
}

pub fn load_bool_ciphertext(input: &CiphertextInput) -> Result<CiphertextBundle, BackendError> {
    let bundle = load_ciphertext_raw(input)?;
    match bundle.value {
        CiphertextKind::Bool(_) => Ok(bundle),
        CiphertextKind::Uint32(_) => Err(BackendError::InvalidArgument(
            "expected bool ciphertext, got uint32 ciphertext".to_string(),
        )),
    }
}

pub fn encrypt_scalar(keyset_reference: &str, value: i64) -> Result<CiphertextResponse, BackendError> {
    if value < 0 || value > u32::MAX as i64 {
        return Err(BackendError::InvalidArgument(
            "Stage-2 encrypt_scalar only supports 0 <= value <= u32::MAX".to_string(),
        ));
    }

    let (client_key, _server_key) = fetch_keyset(keyset_reference)?;
    let encrypted = FheUint32::encrypt(value as u32, &client_key);

    let mut metadata = HashMap::new();
    metadata.insert("noise".to_string(), Value::from(0));
    metadata.insert("kind".to_string(), Value::String("native_tfhe_uint32".to_string()));

    store_uint32_ciphertext(keyset_reference, value, encrypted, metadata)
}

pub fn homomorphic_add(request: BinaryCiphertextRequest) -> Result<CiphertextResponse, BackendError> {
    keyset_exists(&request.keyset_reference)?;
    let (_client_key, server_key) = fetch_keyset(&request.keyset_reference)?;
    set_server_key(server_key);

    let left = load_uint32_ciphertext(&request.left)?;
    let right = load_uint32_ciphertext(&request.right)?;
    if left.keyset_reference != request.keyset_reference || right.keyset_reference != request.keyset_reference {
        return Err(BackendError::InvalidArgument(
            "all ciphertexts must belong to the same keyset_reference".to_string(),
        ));
    }

    let left_ct = match left.value {
        CiphertextKind::Uint32(v) => v,
        CiphertextKind::Bool(_) => unreachable!(),
    };
    let right_ct = match right.value {
        CiphertextKind::Uint32(v) => v,
        CiphertextKind::Bool(_) => unreachable!(),
    };

    let result_ct = &left_ct + &right_ct;
    let result_plain = left
        .encoded_value
        .checked_add(right.encoded_value)
        .ok_or_else(|| BackendError::InvalidArgument("encoded_value overflow".to_string()))?;

    let mut metadata = HashMap::new();
    metadata.insert("noise".to_string(), Value::from(0));
    metadata.insert("kind".to_string(), Value::String("native_tfhe_uint32_add".to_string()));

    store_uint32_ciphertext(&request.keyset_reference, result_plain, result_ct, metadata)
}

pub fn homomorphic_sum(request: SumCiphertextsRequest) -> Result<CiphertextResponse, BackendError> {
    keyset_exists(&request.keyset_reference)?;
    let (_client_key, server_key) = fetch_keyset(&request.keyset_reference)?;
    set_server_key(server_key);

    if request.ciphertexts.is_empty() {
        return Err(BackendError::InvalidArgument(
            "ciphertexts must not be empty".to_string(),
        ));
    }

    let loaded: Result<Vec<_>, _> = request.ciphertexts.iter().map(load_uint32_ciphertext).collect();
    let loaded = loaded?;
    for item in &loaded {
        if item.keyset_reference != request.keyset_reference {
            return Err(BackendError::InvalidArgument(
                "all ciphertexts must belong to the same keyset_reference".to_string(),
            ));
        }
    }

    let mut iter = loaded.into_iter();
    let first = iter
        .next()
        .ok_or_else(|| BackendError::Internal("ciphertexts unexpectedly empty".to_string()))?;

    let mut acc_ct = match first.value {
        CiphertextKind::Uint32(v) => v,
        CiphertextKind::Bool(_) => unreachable!(),
    };
    let mut acc_plain = first.encoded_value;

    for item in iter {
        let rhs = match item.value {
            CiphertextKind::Uint32(v) => v,
            CiphertextKind::Bool(_) => unreachable!(),
        };
        acc_ct = &acc_ct + &rhs;
        acc_plain = acc_plain
            .checked_add(item.encoded_value)
            .ok_or_else(|| BackendError::InvalidArgument("encoded_value overflow".to_string()))?;
    }

    let mut metadata = HashMap::new();
    metadata.insert("noise".to_string(), Value::from(0));
    metadata.insert("kind".to_string(), Value::String("native_tfhe_uint32_sum".to_string()));

    store_uint32_ciphertext(&request.keyset_reference, acc_plain, acc_ct, metadata)
}