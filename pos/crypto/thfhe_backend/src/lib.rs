mod api;
mod compare;
mod context;
mod decrypt;
mod encrypt;
mod error;
mod handles;
mod keygen;
mod kms;

use api::{
    BinaryCiphertextRequest, CompareRequest, DistributedKeygenRequest, EncryptScalarRequest,
    FinalDecryptRequest, LocateRequest, PartialDecryptRequest, SelectRequest, SetupRequest,
    SumCiphertextsRequest,
};
use context::{create_keyset, default_params_json};
use error::{BackendError, ErrorResponse};
use std::ffi::{c_char, c_void, CStr, CString};

fn make_json_cstring<T: serde::Serialize>(value: &T) -> *mut c_char {
    let json = match serde_json::to_string(value) {
        Ok(s) => s,
        Err(e) => {
            let fallback = ErrorResponse {
                ok: false,
                error: format!("failed to serialize response: {e}"),
            };
            serde_json::to_string(&fallback)
                .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"serialization failure\"}".to_string())
        }
    };

    match CString::new(json) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => CString::new("{\"ok\":false,\"error\":\"response contains interior NUL\"}")
            .expect("static fallback must be CString-compatible")
            .into_raw(),
    }
}

fn read_request_json(ptr: *const c_char) -> Result<String, BackendError> {
    if ptr.is_null() {
        return Err(BackendError::InvalidArgument(
            "request_json pointer must not be null".to_string(),
        ));
    }

    let cstr = unsafe { CStr::from_ptr(ptr) };
    let s = cstr
        .to_str()
        .map_err(|e| BackendError::InvalidJson(e.to_string()))?;
    Ok(s.to_string())
}

fn handle_setup(req: SetupRequest) -> Result<api::SetupResponse, BackendError> {
    let participant_ids = req
        .participant_ids
        .unwrap_or_else(|| vec!["P1".to_string(), "P2".to_string(), "P3".to_string()]);
    let threshold = req.threshold.unwrap_or(2);
    let backend_name = req.backend_name.unwrap_or_else(|| "thfhe".to_string());

    if backend_name != "thfhe" {
        return Err(BackendError::InvalidArgument(
            "threshold backend only supports backend_name='thfhe'".to_string(),
        ));
    }

    // setup 仍用于本地 compare/locate/select 的计算上下文初始化；
    // 但 distributed_keygen / partial_decrypt / final_decrypt 已切到外部 threshold 协议执行器。
    let keyset_reference = create_keyset(participant_ids.clone(), threshold)?;
    Ok(api::SetupResponse {
        ok: true,
        backend_name,
        keyset_reference,
        threshold,
        participant_ids,
        params: req.params.unwrap_or_else(default_params_json),
    })
}

fn parse_request<T: serde::de::DeserializeOwned>(ptr: *const c_char) -> Result<T, BackendError> {
    let s = read_request_json(ptr)?;
    serde_json::from_str::<T>(&s).map_err(|e| BackendError::InvalidJson(e.to_string()))
}

#[no_mangle]
pub extern "C" fn thfhe_setup(request_json: *const c_char) -> *mut c_char {
    match parse_request::<SetupRequest>(request_json).and_then(handle_setup) {
        Ok(ok) => make_json_cstring(&ok),
        Err(err) => make_json_cstring(&err.to_error_response()),
    }
}

#[no_mangle]
pub extern "C" fn thfhe_distributed_keygen(request_json: *const c_char) -> *mut c_char {
    match parse_request::<DistributedKeygenRequest>(request_json)
        .and_then(|req| keygen::distributed_keygen(req.participant_ids, req.threshold))
    {
        Ok(ok) => make_json_cstring(&ok),
        Err(err) => make_json_cstring(&err.to_error_response()),
    }
}

#[no_mangle]
pub extern "C" fn thfhe_encrypt_scalar(request_json: *const c_char) -> *mut c_char {
    match parse_request::<EncryptScalarRequest>(request_json)
        .and_then(|req| encrypt::encrypt_scalar(&req.keyset_reference, req.value))
    {
        Ok(ok) => make_json_cstring(&ok),
        Err(err) => make_json_cstring(&err.to_error_response()),
    }
}

#[no_mangle]
pub extern "C" fn thfhe_homomorphic_add(request_json: *const c_char) -> *mut c_char {
    match parse_request::<BinaryCiphertextRequest>(request_json)
        .and_then(encrypt::homomorphic_add)
    {
        Ok(ok) => make_json_cstring(&ok),
        Err(err) => make_json_cstring(&err.to_error_response()),
    }
}

#[no_mangle]
pub extern "C" fn thfhe_homomorphic_sum(request_json: *const c_char) -> *mut c_char {
    match parse_request::<SumCiphertextsRequest>(request_json)
        .and_then(encrypt::homomorphic_sum)
    {
        Ok(ok) => make_json_cstring(&ok),
        Err(err) => make_json_cstring(&err.to_error_response()),
    }
}

#[no_mangle]
pub extern "C" fn thfhe_eval_compare(request_json: *const c_char) -> *mut c_char {
    match parse_request::<CompareRequest>(request_json).and_then(compare::eval_compare) {
        Ok(ok) => make_json_cstring(&ok),
        Err(err) => make_json_cstring(&err.to_error_response()),
    }
}

#[no_mangle]
pub extern "C" fn thfhe_eval_locate(request_json: *const c_char) -> *mut c_char {
    match parse_request::<LocateRequest>(request_json).and_then(compare::eval_locate) {
        Ok(ok) => make_json_cstring(&ok),
        Err(err) => make_json_cstring(&err.to_error_response()),
    }
}

#[no_mangle]
pub extern "C" fn thfhe_eval_select(request_json: *const c_char) -> *mut c_char {
    match parse_request::<SelectRequest>(request_json).and_then(compare::eval_select) {
        Ok(ok) => make_json_cstring(&ok),
        Err(err) => make_json_cstring(&err.to_error_response()),
    }
}

#[no_mangle]
pub extern "C" fn thfhe_partial_decrypt(request_json: *const c_char) -> *mut c_char {
    match parse_request::<PartialDecryptRequest>(request_json).and_then(decrypt::partial_decrypt) {
        Ok(ok) => make_json_cstring(&ok),
        Err(err) => make_json_cstring(&err.to_error_response()),
    }
}

#[no_mangle]
pub extern "C" fn thfhe_final_decrypt(request_json: *const c_char) -> *mut c_char {
    match parse_request::<FinalDecryptRequest>(request_json).and_then(decrypt::final_decrypt) {
        Ok(ok) => make_json_cstring(&ok),
        Err(err) => make_json_cstring(&err.to_error_response()),
    }
}

#[no_mangle]
pub extern "C" fn thfhe_free_cstring(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr as *mut c_char);
    }
}