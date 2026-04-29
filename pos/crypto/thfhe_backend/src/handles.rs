use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use tfhe::{ClientKey, FheBool, FheUint32, ServerKey};

pub struct KeysetBundle {
    pub client_key: ClientKey,
    pub server_key: ServerKey,
    pub participant_ids: Vec<String>,
    pub threshold: u32,
}

pub enum CiphertextKind {
    Uint32(FheUint32),
    Bool(FheBool),
}

pub struct CiphertextBundle {
    pub value: CiphertextKind,
    pub encoded_value: i64,
    pub keyset_reference: String,
}

pub static KEYSETS: Lazy<Mutex<HashMap<String, KeysetBundle>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub static CIPHERTEXTS: Lazy<Mutex<HashMap<String, CiphertextBundle>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));