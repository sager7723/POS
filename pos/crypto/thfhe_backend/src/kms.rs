use crate::error::BackendError;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;

/// 这一层严格切到 threshold-fhe / KMS 语义：
///
/// - key generation
/// - partial decrypt
/// - final decrypt
///
/// 都不再允许使用当前本地单机 TFHE-rs key 做伪门限实现。
///
/// 这里不直接硬编码某个 KMS 版本的命令行细节，而是通过环境变量注入
/// “真实 threshold 协议执行器命令模板”。
///
/// 必须配置：
/// - POS_KMS_KEYGEN_CMD
/// - POS_KMS_PARTIAL_DEC_CMD
/// - POS_KMS_FINAL_DEC_CMD
///
/// 命令模板中必须出现：
/// - __REQUEST_JSON__
/// - __RESPONSE_JSON__
///
/// 例如：
///   python /path/to/adapter.py keygen --request __REQUEST_JSON__ --response __RESPONSE_JSON__
///
/// adapter.py 内部再去调用你 checkout 的 KMS / core-client / gRPC 客户端。
///
/// 这样做的原因：
/// - 严格避免把单机 ClientKey 解密伪装成 threshold decrypt
/// - 强制门限操作走外部真实 threshold 协议执行器
#[derive(Debug, Clone)]
pub struct KmsCommandConfig {
    pub keygen_cmd: String,
    pub partial_dec_cmd: String,
    pub final_dec_cmd: String,
}

impl KmsCommandConfig {
    pub fn from_env() -> Result<Self, BackendError> {
        let keygen_cmd = env::var("POS_KMS_KEYGEN_CMD")
            .map_err(|_| BackendError::KmsNotConfigured("POS_KMS_KEYGEN_CMD".to_string()))?;
        let partial_dec_cmd = env::var("POS_KMS_PARTIAL_DEC_CMD")
            .map_err(|_| BackendError::KmsNotConfigured("POS_KMS_PARTIAL_DEC_CMD".to_string()))?;
        let final_dec_cmd = env::var("POS_KMS_FINAL_DEC_CMD")
            .map_err(|_| BackendError::KmsNotConfigured("POS_KMS_FINAL_DEC_CMD".to_string()))?;

        Ok(Self {
            keygen_cmd,
            partial_dec_cmd,
            final_dec_cmd,
        })
    }
}

fn temp_json_path(prefix: &str) -> PathBuf {
    let mut path = env::temp_dir();
    path.push(format!("{prefix}-{}.json", Uuid::new_v4()));
    path
}

fn run_template_command(template: &str, request_payload: &Value) -> Result<Value, BackendError> {
    let request_path = temp_json_path("thfhe-kms-request");
    let response_path = temp_json_path("thfhe-kms-response");

    let request_json = serde_json::to_string_pretty(request_payload)
        .map_err(|e| BackendError::Internal(format!("failed to serialize request payload: {e}")))?;

    fs::write(&request_path, request_json)
        .map_err(|e| BackendError::Internal(format!("failed to write request file: {e}")))?;

    let rendered = template
        .replace("__REQUEST_JSON__", request_path.to_string_lossy().as_ref())
        .replace("__RESPONSE_JSON__", response_path.to_string_lossy().as_ref());

    let output = Command::new("bash")
        .arg("-lc")
        .arg(&rendered)
        .output()
        .map_err(|e| BackendError::KmsCommandFailed(format!("failed to spawn command: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        return Err(BackendError::KmsCommandFailed(format!(
            "command exited with status {}. stdout={stdout} stderr={stderr}",
            output.status
        )));
    }

    if !response_path.exists() {
        return Err(BackendError::KmsResponseMissing(
            response_path.to_string_lossy().to_string(),
        ));
    }

    let response_json = fs::read_to_string(&response_path)
        .map_err(|e| BackendError::KmsResponseMissing(format!("failed to read response file: {e}")))?;

    let parsed: Value = serde_json::from_str(&response_json)
        .map_err(|e| BackendError::KmsResponseParseFailed(e.to_string()))?;

    let _ = fs::remove_file(&request_path);
    let _ = fs::remove_file(&response_path);

    Ok(parsed)
}

pub fn run_threshold_keygen(
    participant_ids: &[String],
    threshold: u32,
) -> Result<Value, BackendError> {
    let cfg = KmsCommandConfig::from_env()?;
    let request = json!({
        "op": "threshold_keygen",
        "participant_ids": participant_ids,
        "threshold": threshold
    });
    run_template_command(&cfg.keygen_cmd, &request)
}

pub fn run_threshold_partial_decrypt(
    keyset_reference: &str,
    participant_id: &str,
    share_handle: &str,
    ciphertext_json: &Value,
) -> Result<Value, BackendError> {
    let cfg = KmsCommandConfig::from_env()?;
    let request = json!({
        "op": "threshold_partial_decrypt",
        "keyset_reference": keyset_reference,
        "participant_id": participant_id,
        "share_handle": share_handle,
        "ciphertext": ciphertext_json
    });
    run_template_command(&cfg.partial_dec_cmd, &request)
}

pub fn run_threshold_final_decrypt(
    keyset_reference: &str,
    ciphertext_json: &Value,
    shares: &[String],
) -> Result<Value, BackendError> {
    let cfg = KmsCommandConfig::from_env()?;
    let request = json!({
        "op": "threshold_final_decrypt",
        "keyset_reference": keyset_reference,
        "ciphertext": ciphertext_json,
        "shares": shares
    });
    run_template_command(&cfg.final_dec_cmd, &request)
}