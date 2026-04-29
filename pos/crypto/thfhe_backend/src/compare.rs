use crate::api::{
    CiphertextResponse, CiphertextVectorResponse, CompareRequest, LocateRequest, SelectRequest,
};
use crate::error::BackendError;
use crate::encrypt::{
    fetch_keyset, keyset_exists, load_bool_ciphertext, load_uint32_ciphertext, store_bool_ciphertext,
    store_uint32_ciphertext,
};
use crate::handles::CiphertextKind;
use serde_json::Value;
use std::collections::HashMap;
use tfhe::prelude::*;
use tfhe::{set_server_key, FheBool, FheUint32};

pub fn eval_compare(request: CompareRequest) -> Result<CiphertextVectorResponse, BackendError> {
    keyset_exists(&request.keyset_reference)?;
    let (_client_key, server_key) = fetch_keyset(&request.keyset_reference)?;
    set_server_key(server_key);

    let x_bundle = load_uint32_ciphertext(&request.x_cipher)?;
    if x_bundle.keyset_reference != request.keyset_reference {
        return Err(BackendError::InvalidArgument(
            "x_cipher keyset_reference mismatch".to_string(),
        ));
    }

    let x_ct = match x_bundle.value {
        CiphertextKind::Uint32(v) => v,
        CiphertextKind::Bool(_) => unreachable!(),
    };

    let mut outputs: Vec<CiphertextResponse> = Vec::with_capacity(request.y_ciphers.len());
    for y_input in &request.y_ciphers {
        let y_bundle = load_uint32_ciphertext(y_input)?;
        if y_bundle.keyset_reference != request.keyset_reference {
            return Err(BackendError::InvalidArgument(
                "y_cipher keyset_reference mismatch".to_string(),
            ));
        }
        let y_ct = match y_bundle.value {
            CiphertextKind::Uint32(v) => v,
            CiphertextKind::Bool(_) => unreachable!(),
        };

        // 语义：返回 x < y 的密文布尔值
        let bit_ct = x_ct.lt(&y_ct);

        let mut metadata = HashMap::new();
        metadata.insert("noise".to_string(), Value::from(0));
        metadata.insert("kind".to_string(), Value::String("native_tfhe_bool_compare_lt".to_string()));

        outputs.push(store_bool_ciphertext(&request.keyset_reference, bit_ct, metadata)?);
    }

    Ok(CiphertextVectorResponse {
        ok: true,
        ciphertexts: outputs,
    })
}

pub fn eval_locate(request: LocateRequest) -> Result<CiphertextVectorResponse, BackendError> {
    keyset_exists(&request.keyset_reference)?;
    let (client_key, server_key) = fetch_keyset(&request.keyset_reference)?;
    set_server_key(server_key);

    let mut seen = FheBool::encrypt(false, &client_key);
    let mut outputs: Vec<CiphertextResponse> = Vec::with_capacity(request.selector_bits.len());

    for selector_input in &request.selector_bits {
        let selector_bundle = load_bool_ciphertext(selector_input)?;
        if selector_bundle.keyset_reference != request.keyset_reference {
            return Err(BackendError::InvalidArgument(
                "selector_bits keyset_reference mismatch".to_string(),
            ));
        }

        let selector_ct = match selector_bundle.value {
            CiphertextKind::Bool(v) => v,
            CiphertextKind::Uint32(_) => unreachable!(),
        };

        let first_true = &selector_ct & !&seen;
        seen = &seen | &selector_ct;

        let mut metadata = HashMap::new();
        metadata.insert("noise".to_string(), Value::from(0));
        metadata.insert("kind".to_string(), Value::String("native_tfhe_bool_locate_first_true".to_string()));

        outputs.push(store_bool_ciphertext(&request.keyset_reference, first_true, metadata)?);
    }

    Ok(CiphertextVectorResponse {
        ok: true,
        ciphertexts: outputs,
    })
}

pub fn eval_select(request: SelectRequest) -> Result<CiphertextResponse, BackendError> {
    keyset_exists(&request.keyset_reference)?;
    let (client_key, server_key) = fetch_keyset(&request.keyset_reference)?;
    set_server_key(server_key);

    if request.locator_bits.len() != request.value_ciphertexts.len() {
        return Err(BackendError::InvalidArgument(
            "locator_bits and value_ciphertexts must have the same length".to_string(),
        ));
    }
    if request.locator_bits.is_empty() {
        return Err(BackendError::InvalidArgument(
            "locator_bits must not be empty".to_string(),
        ));
    }

    let mut selected = FheUint32::encrypt(0u32, &client_key);

    for (locator_input, value_input) in request.locator_bits.iter().zip(request.value_ciphertexts.iter()) {
        let locator_bundle = load_bool_ciphertext(locator_input)?;
        let value_bundle = load_uint32_ciphertext(value_input)?;

        if locator_bundle.keyset_reference != request.keyset_reference
            || value_bundle.keyset_reference != request.keyset_reference
        {
            return Err(BackendError::InvalidArgument(
                "keyset_reference mismatch in eval_select".to_string(),
            ));
        }

        let locator_ct = match locator_bundle.value {
            CiphertextKind::Bool(v) => v,
            CiphertextKind::Uint32(_) => unreachable!(),
        };
        let value_ct = match value_bundle.value {
            CiphertextKind::Uint32(v) => v,
            CiphertextKind::Bool(_) => unreachable!(),
        };

        // 若 locator 为真，则选 value_ct；否则保持 selected
        selected = locator_ct.if_then_else(&value_ct, &selected);
    }

    let mut metadata = HashMap::new();
    metadata.insert("noise".to_string(), Value::from(0));
    metadata.insert("kind".to_string(), Value::String("native_tfhe_uint32_select".to_string()));

    // 这里 encoded_value 不再依赖明文控制流，统一置 0
    store_uint32_ciphertext(&request.keyset_reference, 0, selected, metadata)
}