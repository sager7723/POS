use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub backend_name: Option<String>,
    pub threshold: Option<u32>,
    pub participant_ids: Option<Vec<String>>,
    pub params: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct SetupResponse {
    pub ok: bool,
    pub backend_name: String,
    pub keyset_reference: String,
    pub threshold: u32,
    pub participant_ids: Vec<String>,
    pub params: Value,
}

#[derive(Debug, Deserialize)]
pub struct DistributedKeygenRequest {
    pub backend_name: Option<String>,
    pub participant_ids: Vec<String>,
    pub threshold: u32,
    pub params: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct DistributedKeygenResponse {
    pub ok: bool,
    pub backend_name: String,
    pub public_key: String,
    pub keyset_reference: String,
    pub participant_private_share_handles: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct EncryptScalarRequest {
    pub keyset_reference: String,
    pub value: i64,
}

#[derive(Debug, Serialize, Clone)]
pub struct CiphertextResponse {
    pub ok: bool,
    pub backend: String,
    pub encoded_value: i64,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct BinaryCiphertextRequest {
    pub keyset_reference: String,
    pub left: CiphertextInput,
    pub right: CiphertextInput,
}

#[derive(Debug, Deserialize)]
pub struct SumCiphertextsRequest {
    pub keyset_reference: String,
    pub ciphertexts: Vec<CiphertextInput>,
}

#[derive(Debug, Deserialize)]
pub struct CompareRequest {
    pub keyset_reference: String,
    pub x_cipher: CiphertextInput,
    pub y_ciphers: Vec<CiphertextInput>,
}

#[derive(Debug, Deserialize)]
pub struct LocateRequest {
    pub keyset_reference: String,
    pub selector_bits: Vec<CiphertextInput>,
}

#[derive(Debug, Deserialize)]
pub struct SelectRequest {
    pub keyset_reference: String,
    pub locator_bits: Vec<CiphertextInput>,
    pub value_ciphertexts: Vec<CiphertextInput>,
}

#[derive(Debug, Deserialize)]
pub struct PartialDecryptRequest {
    pub keyset_reference: String,
    pub participant_id: String,
    pub share_handle: String,
    pub ciphertext: CiphertextInput,
}

#[derive(Debug, Serialize)]
pub struct PartialDecryptResponse {
    pub ok: bool,
    pub share: String,
}

#[derive(Debug, Deserialize)]
pub struct FinalDecryptRequest {
    pub keyset_reference: String,
    pub ciphertext: CiphertextInput,
    pub shares: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct FinalDecryptResponse {
    pub ok: bool,
    pub plaintext: i64,
}

#[derive(Debug, Deserialize)]
pub struct CiphertextInput {
    pub backend: String,
    pub encoded_value: i64,
    pub metadata: HashMap<String, Value>,
}

#[derive(Debug, Serialize)]
pub struct CiphertextVectorResponse {
    pub ok: bool,
    pub ciphertexts: Vec<CiphertextResponse>,
}