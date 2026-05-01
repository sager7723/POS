}

// -----------------------------------------------------------------------------
// External evaluator support: real TFHE euint8 comparison.
// -----------------------------------------------------------------------------
//
// This function reads two KMS-generated CipherWithParams files, verifies that
// they are SmallExpanded euint8 ciphertexts for the same key, deserializes the
// inner high-level FheUint8 ciphertexts, loads the real KMS ServerKey, evaluates
// left < right with tfhe-rs, and writes an ebool CipherWithParams file.
//
// No plaintext value is read from encoded_value or used for the comparison.





pub async fn eval_compare_euint8_external<P: AsRef<std::path::Path>>(
    left_path: P,
    right_path: P,
    server_key_path: P,
    output_path: P,
    expected_key_id: &str,
    expected_result: bool,
) -> anyhow::Result<ExternalCipherWithParamsView> {
    use std::io::Cursor;
    use tfhe::prelude::*;
    use tfhe::{FheUint8, ServerKey};

    const POS_SAFE_SER_SIZE_LIMIT: u64 = 1_000_000_000;

    let left: CipherWithParams = read_element(left_path.as_ref()).await?;
    let right: CipherWithParams = read_element(right_path.as_ref()).await?;

    if left.params.key_id.as_str() != expected_key_id {
        anyhow::bail!(
            "left key_id mismatch: got {}, expected {}",
            left.params.key_id.as_str(),
            expected_key_id
        );
    }

    if right.params.key_id.as_str() != expected_key_id {
        anyhow::bail!(
            "right key_id mismatch: got {}, expected {}",
            right.params.key_id.as_str(),
            expected_key_id
        );
    }

    if left.params.data_type != FheType::Euint8 {
        anyhow::bail!("left data_type must be euint8, got {}", left.params.data_type);
    }

    if right.params.data_type != FheType::Euint8 {
        anyhow::bail!("right data_type must be euint8, got {}", right.params.data_type);
    }

    if left.ct_format != "SmallExpanded" {
        anyhow::bail!("left ct_format must be SmallExpanded, got {}", left.ct_format);
    }

    if right.ct_format != "SmallExpanded" {
        anyhow::bail!("right ct_format must be SmallExpanded, got {}", right.ct_format);
    }

    if !left.params.no_compression || !right.params.no_compression {
        anyhow::bail!("eval_compare_euint8_external requires --no-compression inputs");
    }

    if !left.params.no_precompute_sns || !right.params.no_precompute_sns {
        anyhow::bail!("eval_compare_euint8_external requires --no-precompute-sns inputs");
    }

    let left_ct: FheUint8 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(left.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize left FheUint8: {err}"))?;

    let right_ct: FheUint8 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(right.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize right FheUint8: {err}"))?;

    let server_key_bytes = tokio::fs::read(server_key_path.as_ref()).await?;

    let high_level_server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(server_key_bytes.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize server key as tfhe::ServerKey: {err}"))?;

    tfhe::set_server_key(high_level_server_key);

    let compare_ct = left_ct.lt(&right_ct);

    let mut compare_buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(
        &compare_ct,
        &mut compare_buf,
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to serialize comparison FheBool: {err}"))?;

    let mut params = left.params.clone();

    // This field is only KMS core-client test metadata.
    // The actual homomorphic comparison above never reads this value.
    params.to_encrypt = if expected_result {
        "01".to_owned()
    } else {
        "00".to_owned()
    };

    params.data_type = FheType::Ebool;
    params.no_compression = true;
    params.no_precompute_sns = true;
    params.ciphertext_output_path = None;
    params.batch_size = 1;
    params.num_requests = 1;
    params.inter_request_delay_ms = 0;
    params.parallel_requests = 0;
    params.compressed_keys = false;
    params.extra_data = None;

    let out = CipherWithParams {
        params,
        ct_format: "SmallExpanded".to_owned(),
        cipher: compare_buf,
    };

    write_element(output_path.as_ref(), &out).await?;

    read_cipher_with_params_external_view(output_path).await
}





// -----------------------------------------------------------------------------
// External evaluator support: inspect KMS ServerKey serialization type.
// -----------------------------------------------------------------------------
//
// This is diagnostic only. It does not decrypt and does not evaluate.
// It helps determine the exact Rust type stored in PUB/ServerKey/<KEY_ID>.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExternalServerKeyDecodeAttempt {
    pub type_name: String,
    pub ok: bool,
    pub error: Option<String>,
}

pub async fn inspect_server_key_external<P: AsRef<std::path::Path>>(
    server_key_path: P,
) -> Vec<ExternalServerKeyDecodeAttempt> {
    let path = server_key_path.as_ref();

    let mut attempts = Vec::new();

    attempts.push(
        inspect_server_key_as::<tfhe::ServerKey>(
            path,
            "tfhe::ServerKey",
        )
        .await,
    );

    attempts.push(
        inspect_server_key_as::<tfhe::CompressedServerKey>(
            path,
            "tfhe::CompressedServerKey",
        )
        .await,
    );

    attempts.push(
        inspect_server_key_as::<tfhe::integer::ServerKey>(
            path,
            "tfhe::integer::ServerKey",
        )
        .await,
    );

    attempts.push(
        inspect_server_key_as::<tfhe::integer::CompressedServerKey>(
            path,
            "tfhe::integer::CompressedServerKey",
        )
        .await,
    );

    attempts
}

async fn inspect_server_key_as<T>(
    path: &std::path::Path,
    type_name: &str,
) -> ExternalServerKeyDecodeAttempt
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    match read_element::<T, _>(path).await {
        Ok(_) => ExternalServerKeyDecodeAttempt {
            type_name: type_name.to_owned(),
            ok: true,
            error: None,
        },
        Err(err) => ExternalServerKeyDecodeAttempt {
            type_name: type_name.to_owned(),
            ok: false,
            error: Some(err.to_string()),
        },
    }
}

// -----------------------------------------------------------------------------
// External evaluator support: real TFHE euint8 conditional select / CMUX.
// -----------------------------------------------------------------------------
//
// selector ? true_value : false_value
//
// Inputs:
// - selector: SmallExpanded ebool CipherWithParams
// - true_value: SmallExpanded euint8 CipherWithParams
// - false_value: SmallExpanded euint8 CipherWithParams
//
// Output:
// - SmallExpanded euint8 CipherWithParams
//
// No plaintext selector fallback is used. The selected ciphertext is produced
// by TFHE high-level FheBool::if_then_else.

pub async fn eval_select_euint8_external<P: AsRef<std::path::Path>>(
    selector_path: P,
    true_value_path: P,
    false_value_path: P,
    server_key_path: P,
    output_path: P,
    expected_key_id: &str,
    expected_result: u8,
) -> anyhow::Result<ExternalCipherWithParamsView> {
    use std::io::Cursor;
    use tfhe::prelude::*;
    use tfhe::{FheBool, FheUint8, ServerKey};

    const POS_SAFE_SER_SIZE_LIMIT: u64 = 1_000_000_000;

    let selector: CipherWithParams = read_element(selector_path.as_ref()).await?;
    let true_value: CipherWithParams = read_element(true_value_path.as_ref()).await?;
    let false_value: CipherWithParams = read_element(false_value_path.as_ref()).await?;

    for (label, item, expected_type) in [
        ("selector", &selector, FheType::Ebool),
        ("true_value", &true_value, FheType::Euint8),
        ("false_value", &false_value, FheType::Euint8),
    ] {
        if item.params.key_id.as_str() != expected_key_id {
            anyhow::bail!(
                "{label} key_id mismatch: got {}, expected {}",
                item.params.key_id.as_str(),
                expected_key_id
            );
        }

        if item.params.data_type != expected_type {
            anyhow::bail!(
                "{label} data_type mismatch: got {}, expected {}",
                item.params.data_type,
                expected_type
            );
        }

        if item.ct_format != "SmallExpanded" {
            anyhow::bail!(
                "{label} ct_format must be SmallExpanded, got {}",
                item.ct_format
            );
        }

        if !item.params.no_compression {
            anyhow::bail!("{label} requires --no-compression input");
        }

        if !item.params.no_precompute_sns {
            anyhow::bail!("{label} requires --no-precompute-sns input");
        }
    }

    let selector_ct: FheBool = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(selector.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize selector FheBool: {err}"))?;

    let true_ct: FheUint8 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(true_value.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize true_value FheUint8: {err}"))?;

    let false_ct: FheUint8 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(false_value.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize false_value FheUint8: {err}"))?;

    let server_key_bytes = tokio::fs::read(server_key_path.as_ref()).await?;

    let high_level_server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(server_key_bytes.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize server key as tfhe::ServerKey: {err}"))?;

    tfhe::set_server_key(high_level_server_key);

    let selected_ct: FheUint8 = selector_ct.if_then_else(&true_ct, &false_ct);

    let mut selected_buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(
        &selected_ct,
        &mut selected_buf,
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to serialize selected FheUint8: {err}"))?;

    let mut params = true_value.params.clone();

    // Test metadata only. The actual CMUX above never reads this value.
    params.to_encrypt = format!("{expected_result:02x}");
    params.data_type = FheType::Euint8;
    params.no_compression = true;
    params.no_precompute_sns = true;
    params.ciphertext_output_path = None;
    params.batch_size = 1;
    params.num_requests = 1;
    params.inter_request_delay_ms = 0;
    params.parallel_requests = 0;
    params.compressed_keys = false;
    params.extra_data = None;

    let out = CipherWithParams {
        params,
        ct_format: "SmallExpanded".to_owned(),
        cipher: selected_buf,
    };

    write_element(output_path.as_ref(), &out).await?;

    read_cipher_with_params_external_view(output_path).await
}

// -----------------------------------------------------------------------------
// External evaluator support: real TFHE euint8 locate / one-hot argmin.
// -----------------------------------------------------------------------------
//
// Given encrypted euint8 values [v0, v1, ...], this computes the index of the
// first minimum value and returns one-hot encrypted ebool flags.
//
// Tie policy:
// - strict less-than update
// - equal values keep the earlier winner
//
// No plaintext fallback is used. Expected index is only test metadata used by
// kms-core-client decrypt-from-file validation.

pub async fn eval_locate_min_euint8_external(
    value_paths: &[std::path::PathBuf],
    server_key_path: &std::path::Path,
    output_dir: &std::path::Path,
    expected_key_id: &str,
    expected_index: usize,
) -> anyhow::Result<Vec<ExternalCipherWithParamsView>> {
    use std::io::Cursor;
    use tfhe::prelude::*;
    use tfhe::{FheBool, FheUint8, ServerKey};

    const POS_SAFE_SER_SIZE_LIMIT: u64 = 1_000_000_000;

    if value_paths.is_empty() {
        anyhow::bail!("eval_locate_min_euint8_external requires at least one value");
    }

    if expected_index >= value_paths.len() {
        anyhow::bail!(
            "expected_index {} out of range for {} values",
            expected_index,
            value_paths.len()
        );
    }

    let mut values_with_params: Vec<CipherWithParams> = Vec::with_capacity(value_paths.len());
    let mut value_cts: Vec<FheUint8> = Vec::with_capacity(value_paths.len());

    for (idx, path) in value_paths.iter().enumerate() {
        let item: CipherWithParams = read_element(path).await?;

        if item.params.key_id.as_str() != expected_key_id {
            anyhow::bail!(
                "value[{idx}] key_id mismatch: got {}, expected {}",
                item.params.key_id.as_str(),
                expected_key_id
            );
        }

        if item.params.data_type != FheType::Euint8 {
            anyhow::bail!(
                "value[{idx}] data_type mismatch: got {}, expected euint8",
                item.params.data_type
            );
        }

        if item.ct_format != "SmallExpanded" {
            anyhow::bail!(
                "value[{idx}] ct_format must be SmallExpanded, got {}",
                item.ct_format
            );
        }

        if !item.params.no_compression {
            anyhow::bail!("value[{idx}] requires --no-compression input");
        }

        if !item.params.no_precompute_sns {
            anyhow::bail!("value[{idx}] requires --no-precompute-sns input");
        }

        let ct: FheUint8 = tfhe::safe_serialization::safe_deserialize(
            Cursor::new(item.cipher.as_slice()),
            POS_SAFE_SER_SIZE_LIMIT,
        )
        .map_err(|err| anyhow::anyhow!("failed to deserialize value[{idx}] FheUint8: {err}"))?;

        values_with_params.push(item);
        value_cts.push(ct);
    }

    let server_key_bytes = tokio::fs::read(server_key_path).await?;

    let high_level_server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(server_key_bytes.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize server key as tfhe::ServerKey: {err}"))?;

    tfhe::set_server_key(high_level_server_key);

    let false_flag: FheBool = value_cts[0].lt(&value_cts[0]);
    let true_flag: FheBool = value_cts[0].le(&value_cts[0]);

    let mut current_min = value_cts[0].clone();
    let mut flags: Vec<FheBool> = vec![false_flag.clone(); value_cts.len()];
    flags[0] = true_flag.clone();

    for i in 1..value_cts.len() {
        let is_new_winner: FheBool = value_cts[i].lt(&current_min);

        for flag in flags.iter_mut().take(i) {
            *flag = is_new_winner.if_then_else(&false_flag, flag);
        }

        flags[i] = is_new_winner.clone();
        current_min = is_new_winner.if_then_else(&value_cts[i], &current_min);
    }

    tokio::fs::create_dir_all(output_dir).await?;

    let mut outputs = Vec::with_capacity(flags.len());

    for (idx, flag) in flags.iter().enumerate() {
        let mut flag_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            flag,
            &mut flag_buf,
            POS_SAFE_SER_SIZE_LIMIT,
        )
        .map_err(|err| anyhow::anyhow!("failed to serialize locate flag[{idx}] FheBool: {err}"))?;

        let mut params = values_with_params[0].params.clone();

        // Test metadata only. The actual locate circuit above never reads this.
        params.to_encrypt = if idx == expected_index {
            "01".to_owned()
        } else {
            "00".to_owned()
        };

        params.data_type = FheType::Ebool;
        params.no_compression = true;
        params.no_precompute_sns = true;
        params.ciphertext_output_path = None;
        params.batch_size = 1;
        params.num_requests = 1;
        params.inter_request_delay_ms = 0;
        params.parallel_requests = 0;
        params.compressed_keys = false;
        params.extra_data = None;

        let out = CipherWithParams {
            params,
            ct_format: "SmallExpanded".to_owned(),
            cipher: flag_buf,
        };

        let output_path = output_dir.join(format!("onehot_{idx:02}.ebool.ct"));
        write_element(&output_path, &out).await?;

        outputs.push(read_cipher_with_params_external_view(&output_path).await?);
    }

    Ok(outputs)
}

// -----------------------------------------------------------------------------
// External evaluator support: real TFHE euint8 locate / one-hot argmin.
// -----------------------------------------------------------------------------
//
// Given encrypted euint8 values [v0, v1, ...], this computes the index of the
// first minimum value and returns one-hot encrypted ebool flags.
//
// Tie policy:
// - strict less-than update
// - equal values keep the earlier winner
//
// No plaintext fallback is used. Expected index is only test metadata used by
// kms-core-client decrypt-from-file validation.



// -----------------------------------------------------------------------------
// External evaluator support: real TFHE euint8 addition.
// -----------------------------------------------------------------------------
//
// Used by the patent step-18 path to build encrypted cumulative stake sums.
// expected_result is test metadata only for kms-core-client decrypt-from-file
// validation. The addition itself is computed by TFHE over ciphertexts.

pub async fn eval_add_euint8_external<P: AsRef<std::path::Path>>(
    left_path: P,
    right_path: P,
    server_key_path: P,
    output_path: P,
    expected_key_id: &str,
    expected_result: u8,
) -> anyhow::Result<ExternalCipherWithParamsView> {
    use std::io::Cursor;
    use tfhe::prelude::*;
    use tfhe::{FheUint8, ServerKey};

    const POS_SAFE_SER_SIZE_LIMIT: u64 = 1_000_000_000;

    let left: CipherWithParams = read_element(left_path.as_ref()).await?;
    let right: CipherWithParams = read_element(right_path.as_ref()).await?;

    for (label, item) in [("left", &left), ("right", &right)] {
        if item.params.key_id.as_str() != expected_key_id {
            anyhow::bail!(
                "{label} key_id mismatch: got {}, expected {}",
                item.params.key_id.as_str(),
                expected_key_id
            );
        }

        if item.params.data_type != FheType::Euint8 {
            anyhow::bail!("{label} data_type must be euint8, got {}", item.params.data_type);
        }

        if item.ct_format != "SmallExpanded" {
            anyhow::bail!("{label} ct_format must be SmallExpanded, got {}", item.ct_format);
        }

        if !item.params.no_compression {
            anyhow::bail!("{label} requires --no-compression input");
        }

        if !item.params.no_precompute_sns {
            anyhow::bail!("{label} requires --no-precompute-sns input");
        }
    }

    let left_ct: FheUint8 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(left.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize left FheUint8: {err}"))?;

    let right_ct: FheUint8 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(right.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize right FheUint8: {err}"))?;

    let server_key_bytes = tokio::fs::read(server_key_path.as_ref()).await?;

    let high_level_server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(server_key_bytes.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize server key as tfhe::ServerKey: {err}"))?;

    tfhe::set_server_key(high_level_server_key);

    let sum_ct: FheUint8 = left_ct + right_ct;

    let mut sum_buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(
        &sum_ct,
        &mut sum_buf,
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to serialize sum FheUint8: {err}"))?;

    let mut params = left.params.clone();

    // Test metadata only. The actual encrypted addition above never reads this.
    params.to_encrypt = format!("{expected_result:02x}");
    params.data_type = FheType::Euint8;
    params.no_compression = true;
    params.no_precompute_sns = true;
    params.ciphertext_output_path = None;
    params.batch_size = 1;
    params.num_requests = 1;
    params.inter_request_delay_ms = 0;
    params.parallel_requests = 0;
    params.compressed_keys = false;
    params.extra_data = None;

    let out = CipherWithParams {
        params,
        ct_format: "SmallExpanded".to_owned(),
        cipher: sum_buf,
    };

    write_element(output_path.as_ref(), &out).await?;

    read_cipher_with_params_external_view(output_path).await
}


// -----------------------------------------------------------------------------
// External evaluator support: real TFHE bool locate / one-hot first-true.
// -----------------------------------------------------------------------------
//
// Given encrypted ebool flags [b0, b1, ...], compute one-hot encrypted flags
// [b0, !b0 & b1, !b0 & !b1 & b2, ...].
// This matches the patent Clocate step over Ccompare output.

pub async fn eval_locate_first_true_ebool_external(
    flag_paths: &[std::path::PathBuf],
    server_key_path: &std::path::Path,
    output_dir: &std::path::Path,
    expected_key_id: &str,
    expected_index: usize,
) -> anyhow::Result<Vec<ExternalCipherWithParamsView>> {
    use std::io::Cursor;
    use tfhe::prelude::*;
    use tfhe::{FheBool, ServerKey};

    const POS_SAFE_SER_SIZE_LIMIT: u64 = 1_000_000_000;

    if flag_paths.is_empty() {
        anyhow::bail!("eval_locate_first_true_ebool_external requires at least one flag");
    }

    if expected_index >= flag_paths.len() {
        anyhow::bail!(
            "expected_index {} out of range for {} flags",
            expected_index,
            flag_paths.len()
        );
    }

    let mut flags_with_params: Vec<CipherWithParams> = Vec::with_capacity(flag_paths.len());
    let mut flag_cts: Vec<FheBool> = Vec::with_capacity(flag_paths.len());

    for (idx, path) in flag_paths.iter().enumerate() {
        let item: CipherWithParams = read_element(path).await?;

        if item.params.key_id.as_str() != expected_key_id {
            anyhow::bail!(
                "flag[{idx}] key_id mismatch: got {}, expected {}",
                item.params.key_id.as_str(),
                expected_key_id
            );
        }

        if item.params.data_type != FheType::Ebool {
            anyhow::bail!(
                "flag[{idx}] data_type mismatch: got {}, expected ebool",
                item.params.data_type
            );
        }

        if item.ct_format != "SmallExpanded" {
            anyhow::bail!(
                "flag[{idx}] ct_format must be SmallExpanded, got {}",
                item.ct_format
            );
        }

        if !item.params.no_compression {
            anyhow::bail!("flag[{idx}] requires --no-compression input");
        }

        if !item.params.no_precompute_sns {
            anyhow::bail!("flag[{idx}] requires --no-precompute-sns input");
        }

        let ct: FheBool = tfhe::safe_serialization::safe_deserialize(
            Cursor::new(item.cipher.as_slice()),
            POS_SAFE_SER_SIZE_LIMIT,
        )
        .map_err(|err| anyhow::anyhow!("failed to deserialize flag[{idx}] FheBool: {err}"))?;

        flags_with_params.push(item);
        flag_cts.push(ct);
    }

    let server_key_bytes = tokio::fs::read(server_key_path).await?;

    let high_level_server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(server_key_bytes.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize server key as tfhe::ServerKey: {err}"))?;

    tfhe::set_server_key(high_level_server_key);

    let false_flag: FheBool = flag_cts[0].clone() & !flag_cts[0].clone();
    let mut seen_true: FheBool = false_flag;

    let mut onehot: Vec<FheBool> = Vec::with_capacity(flag_cts.len());

    for flag in flag_cts.iter() {
        let is_first_true: FheBool = flag.clone() & !seen_true.clone();
        seen_true = seen_true | flag.clone();
        onehot.push(is_first_true);
    }

    tokio::fs::create_dir_all(output_dir).await?;

    let mut outputs = Vec::with_capacity(onehot.len());

    for (idx, flag) in onehot.iter().enumerate() {
        let mut flag_buf = Vec::new();

        tfhe::safe_serialization::safe_serialize(
            flag,
            &mut flag_buf,
            POS_SAFE_SER_SIZE_LIMIT,
        )
        .map_err(|err| anyhow::anyhow!("failed to serialize locate bool flag[{idx}] FheBool: {err}"))?;

        let mut params = flags_with_params[0].params.clone();

        // Test metadata only. The actual locate circuit above never reads this.
        params.to_encrypt = if idx == expected_index {
            "01".to_owned()
        } else {
            "00".to_owned()
        };

        params.data_type = FheType::Ebool;
        params.no_compression = true;
        params.no_precompute_sns = true;
        params.ciphertext_output_path = None;
        params.batch_size = 1;
        params.num_requests = 1;
        params.inter_request_delay_ms = 0;
        params.parallel_requests = 0;
        params.compressed_keys = false;
        params.extra_data = None;

        let out = CipherWithParams {
            params,
            ct_format: "SmallExpanded".to_owned(),
            cipher: flag_buf,
        };

        let output_path = output_dir.join(format!("first_true_{idx:02}.ebool.ct"));
        write_element(&output_path, &out).await?;

        outputs.push(read_cipher_with_params_external_view(&output_path).await?);
    }

    Ok(outputs)
}


// -----------------------------------------------------------------------------
// External evaluator support: real TFHE PRF scaling for patent step 17.
// -----------------------------------------------------------------------------
//
// Computes:
//   floor(prf_ciphertext * numerator / denominator)
//
// Current Stage-9 strict path uses euint8 ciphertext inputs and widens to
// FheUint16 inside the TFHE circuit before multiplying/dividing by public
// constants. expected_result is test metadata only for kms-core-client
// decrypt-from-file validation.

pub async fn eval_scale_prf_euint8_external<P: AsRef<std::path::Path>>(
    prf_path: P,
    server_key_path: P,
    output_path: P,
    expected_key_id: &str,
    numerator: u16,
    denominator: u16,
    expected_result: u8,
) -> anyhow::Result<ExternalCipherWithParamsView> {
    use std::io::Cursor;
    use tfhe::prelude::*;
    use tfhe::{FheUint8, FheUint16, ServerKey};

    const POS_SAFE_SER_SIZE_LIMIT: u64 = 1_000_000_000;

    if denominator == 0 {
        anyhow::bail!("denominator must be non-zero");
    }

    let prf: CipherWithParams = read_element(prf_path.as_ref()).await?;

    if prf.params.key_id.as_str() != expected_key_id {
        anyhow::bail!(
            "prf key_id mismatch: got {}, expected {}",
            prf.params.key_id.as_str(),
            expected_key_id
        );
    }

    if prf.params.data_type != FheType::Euint8 {
        anyhow::bail!("prf data_type must be euint8, got {}", prf.params.data_type);
    }

    if prf.ct_format != "SmallExpanded" {
        anyhow::bail!("prf ct_format must be SmallExpanded, got {}", prf.ct_format);
    }

    if !prf.params.no_compression {
        anyhow::bail!("prf requires --no-compression input");
    }

    if !prf.params.no_precompute_sns {
        anyhow::bail!("prf requires --no-precompute-sns input");
    }

    let prf_ct: FheUint8 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(prf.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize prf FheUint8: {err}"))?;

    let server_key_bytes = tokio::fs::read(server_key_path.as_ref()).await?;

    let high_level_server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(server_key_bytes.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize server key as tfhe::ServerKey: {err}"))?;

    tfhe::set_server_key(high_level_server_key);

    let prf16: FheUint16 = prf_ct.cast_into();
    let product16: FheUint16 = prf16 * numerator;
    let scaled16: FheUint16 = product16 / denominator;
    let scaled8: FheUint8 = scaled16.cast_into();

    let mut scaled_buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(
        &scaled8,
        &mut scaled_buf,
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to serialize scaled PRF FheUint8: {err}"))?;

    let mut params = prf.params.clone();

    // Test metadata only. The encrypted scaling circuit above never reads this.
    params.to_encrypt = format!("{expected_result:02x}");
    params.data_type = FheType::Euint8;
    params.no_compression = true;
    params.no_precompute_sns = true;
    params.ciphertext_output_path = None;
    params.batch_size = 1;
    params.num_requests = 1;
    params.inter_request_delay_ms = 0;
    params.parallel_requests = 0;
    params.compressed_keys = false;
    params.extra_data = None;

    let out = CipherWithParams {
        params,
        ct_format: "SmallExpanded".to_owned(),
        cipher: scaled_buf,
    };

    write_element(output_path.as_ref(), &out).await?;

    read_cipher_with_params_external_view(output_path).await
}

// -----------------------------------------------------------------------------
// External evaluator support: real TFHE euint32 comparison.
// -----------------------------------------------------------------------------
//
// Used by the strict patent path for Ccompare over scaled random and cumulative
// stake ciphertexts. No plaintext fallback is used.

pub async fn eval_compare_euint32_external<P: AsRef<std::path::Path>>(
    left_path: P,
    right_path: P,
    server_key_path: P,
    output_path: P,
    expected_key_id: &str,
    expected_result: bool,
) -> anyhow::Result<ExternalCipherWithParamsView> {
    use std::io::Cursor;
    use tfhe::prelude::*;
    use tfhe::{FheUint32, ServerKey};

    const POS_SAFE_SER_SIZE_LIMIT: u64 = 1_000_000_000;

    let left: CipherWithParams = read_element(left_path.as_ref()).await?;
    let right: CipherWithParams = read_element(right_path.as_ref()).await?;

    for (label, item) in [("left", &left), ("right", &right)] {
        if item.params.key_id.as_str() != expected_key_id {
            anyhow::bail!(
                "{label} key_id mismatch: got {}, expected {}",
                item.params.key_id.as_str(),
                expected_key_id
            );
        }

        if item.params.data_type != FheType::Euint32 {
            anyhow::bail!("{label} data_type must be euint32, got {}", item.params.data_type);
        }

        if item.ct_format != "SmallExpanded" {
            anyhow::bail!("{label} ct_format must be SmallExpanded, got {}", item.ct_format);
        }

        if !item.params.no_compression {
            anyhow::bail!("{label} requires --no-compression input");
        }

        if !item.params.no_precompute_sns {
            anyhow::bail!("{label} requires --no-precompute-sns input");
        }
    }

    let left_ct: FheUint32 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(left.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize left FheUint32: {err}"))?;

    let right_ct: FheUint32 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(right.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize right FheUint32: {err}"))?;

    let server_key_bytes = tokio::fs::read(server_key_path.as_ref()).await?;

    let high_level_server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(server_key_bytes.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize server key as tfhe::ServerKey: {err}"))?;

    tfhe::set_server_key(high_level_server_key);

    let compare_ct = left_ct.lt(&right_ct);

    let mut compare_buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(
        &compare_ct,
        &mut compare_buf,
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to serialize comparison FheBool: {err}"))?;

    let mut params = left.params.clone();
    params.to_encrypt = if expected_result {
        "01".to_owned()
    } else {
        "00".to_owned()
    };
    params.data_type = FheType::Ebool;
    params.no_compression = true;
    params.no_precompute_sns = true;
    params.ciphertext_output_path = None;
    params.batch_size = 1;
    params.num_requests = 1;
    params.inter_request_delay_ms = 0;
    params.parallel_requests = 0;
    params.compressed_keys = false;
    params.extra_data = None;

    let out = CipherWithParams {
        params,
        ct_format: "SmallExpanded".to_owned(),
        cipher: compare_buf,
    };

    write_element(output_path.as_ref(), &out).await?;

    read_cipher_with_params_external_view(output_path).await
}

// -----------------------------------------------------------------------------
// External evaluator support: real TFHE euint32 addition.
// -----------------------------------------------------------------------------
//
// Used by patent steps 12 and 16 to sum encrypted stakes and encrypted PRF
// shares in the election arithmetic domain.

pub async fn eval_add_euint32_external<P: AsRef<std::path::Path>>(
    left_path: P,
    right_path: P,
    server_key_path: P,
    output_path: P,
    expected_key_id: &str,
    expected_result: u32,
) -> anyhow::Result<ExternalCipherWithParamsView> {
    use std::io::Cursor;
    use tfhe::prelude::*;
    use tfhe::{FheUint32, ServerKey};

    const POS_SAFE_SER_SIZE_LIMIT: u64 = 1_000_000_000;

    let left: CipherWithParams = read_element(left_path.as_ref()).await?;
    let right: CipherWithParams = read_element(right_path.as_ref()).await?;

    for (label, item) in [("left", &left), ("right", &right)] {
        if item.params.key_id.as_str() != expected_key_id {
            anyhow::bail!(
                "{label} key_id mismatch: got {}, expected {}",
                item.params.key_id.as_str(),
                expected_key_id
            );
        }

        if item.params.data_type != FheType::Euint32 {
            anyhow::bail!("{label} data_type must be euint32, got {}", item.params.data_type);
        }

        if item.ct_format != "SmallExpanded" {
            anyhow::bail!("{label} ct_format must be SmallExpanded, got {}", item.ct_format);
        }

        if !item.params.no_compression {
            anyhow::bail!("{label} requires --no-compression input");
        }

        if !item.params.no_precompute_sns {
            anyhow::bail!("{label} requires --no-precompute-sns input");
        }
    }

    let left_ct: FheUint32 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(left.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize left FheUint32: {err}"))?;

    let right_ct: FheUint32 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(right.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize right FheUint32: {err}"))?;

    let server_key_bytes = tokio::fs::read(server_key_path.as_ref()).await?;

    let high_level_server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(server_key_bytes.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize server key as tfhe::ServerKey: {err}"))?;

    tfhe::set_server_key(high_level_server_key);

    let sum_ct: FheUint32 = left_ct + right_ct;

    let mut sum_buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(
        &sum_ct,
        &mut sum_buf,
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to serialize sum FheUint32: {err}"))?;

    let mut params = left.params.clone();
    params.to_encrypt = format!("{expected_result:08x}");
    params.data_type = FheType::Euint32;
    params.no_compression = true;
    params.no_precompute_sns = true;
    params.ciphertext_output_path = None;
    params.batch_size = 1;
    params.num_requests = 1;
    params.inter_request_delay_ms = 0;
    params.parallel_requests = 0;
    params.compressed_keys = false;
    params.extra_data = None;

    let out = CipherWithParams {
        params,
        ct_format: "SmallExpanded".to_owned(),
        cipher: sum_buf,
    };

    write_element(output_path.as_ref(), &out).await?;

    read_cipher_with_params_external_view(output_path).await
}

// -----------------------------------------------------------------------------
// External evaluator support: real TFHE euint16 conditional select / CMUX.
// -----------------------------------------------------------------------------
//
// Used by patent step 18 to select encrypted ticket-hash suffix chunks.

pub async fn eval_select_euint16_external<P: AsRef<std::path::Path>>(
    selector_path: P,
    true_value_path: P,
    false_value_path: P,
    server_key_path: P,
    output_path: P,
    expected_key_id: &str,
    expected_result: u16,
) -> anyhow::Result<ExternalCipherWithParamsView> {
    use std::io::Cursor;
    use tfhe::prelude::*;
    use tfhe::{FheBool, FheUint16, ServerKey};

    const POS_SAFE_SER_SIZE_LIMIT: u64 = 1_000_000_000;

    let selector: CipherWithParams = read_element(selector_path.as_ref()).await?;
    let true_value: CipherWithParams = read_element(true_value_path.as_ref()).await?;
    let false_value: CipherWithParams = read_element(false_value_path.as_ref()).await?;

    for (label, item, expected_type) in [
        ("selector", &selector, FheType::Ebool),
        ("true_value", &true_value, FheType::Euint16),
        ("false_value", &false_value, FheType::Euint16),
    ] {
        if item.params.key_id.as_str() != expected_key_id {
            anyhow::bail!(
                "{label} key_id mismatch: got {}, expected {}",
                item.params.key_id.as_str(),
                expected_key_id
            );
        }

        if item.params.data_type != expected_type {
            anyhow::bail!(
                "{label} data_type mismatch: got {}, expected {}",
                item.params.data_type,
                expected_type
            );
        }

        if item.ct_format != "SmallExpanded" {
            anyhow::bail!("{label} ct_format must be SmallExpanded, got {}", item.ct_format);
        }

        if !item.params.no_compression {
            anyhow::bail!("{label} requires --no-compression input");
        }

        if !item.params.no_precompute_sns {
            anyhow::bail!("{label} requires --no-precompute-sns input");
        }
    }

    let selector_ct: FheBool = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(selector.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize selector FheBool: {err}"))?;

    let true_ct: FheUint16 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(true_value.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize true_value FheUint16: {err}"))?;

    let false_ct: FheUint16 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(false_value.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize false_value FheUint16: {err}"))?;

    let server_key_bytes = tokio::fs::read(server_key_path.as_ref()).await?;

    let high_level_server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(server_key_bytes.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize server key as tfhe::ServerKey: {err}"))?;

    tfhe::set_server_key(high_level_server_key);

    let selected_ct: FheUint16 = selector_ct.if_then_else(&true_ct, &false_ct);

    let mut selected_buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(
        &selected_ct,
        &mut selected_buf,
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to serialize selected FheUint16: {err}"))?;

    let mut params = true_value.params.clone();
    params.to_encrypt = format!("{expected_result:04x}");
    params.data_type = FheType::Euint16;
    params.no_compression = true;
    params.no_precompute_sns = true;
    params.ciphertext_output_path = None;
    params.batch_size = 1;
    params.num_requests = 1;
    params.inter_request_delay_ms = 0;
    params.parallel_requests = 0;
    params.compressed_keys = false;
    params.extra_data = None;

    let out = CipherWithParams {
        params,
        ct_format: "SmallExpanded".to_owned(),
        cipher: selected_buf,
    };

    write_element(output_path.as_ref(), &out).await?;

    read_cipher_with_params_external_view(output_path).await
}

// -----------------------------------------------------------------------------
// External evaluator support: real TFHE euint32 PRF scaling.
// -----------------------------------------------------------------------------
//
// Computes floor(prf_ciphertext * numerator / denominator) in an internal
// euint64 circuit, then casts back to euint32. This is used by patent step 17.

pub async fn eval_scale_prf_euint32_external<P: AsRef<std::path::Path>>(
    prf_path: P,
    server_key_path: P,
    output_path: P,
    expected_key_id: &str,
    numerator: u64,
    denominator: u64,
    expected_result: u32,
) -> anyhow::Result<ExternalCipherWithParamsView> {
    use std::io::Cursor;
    use tfhe::prelude::*;
    use tfhe::{FheUint32, FheUint64, ServerKey};

    const POS_SAFE_SER_SIZE_LIMIT: u64 = 1_000_000_000;

    if denominator == 0 {
        anyhow::bail!("denominator must be non-zero");
    }

    let prf: CipherWithParams = read_element(prf_path.as_ref()).await?;

    if prf.params.key_id.as_str() != expected_key_id {
        anyhow::bail!(
            "prf key_id mismatch: got {}, expected {}",
            prf.params.key_id.as_str(),
            expected_key_id
        );
    }

    if prf.params.data_type != FheType::Euint32 {
        anyhow::bail!("prf data_type must be euint32, got {}", prf.params.data_type);
    }

    if prf.ct_format != "SmallExpanded" {
        anyhow::bail!("prf ct_format must be SmallExpanded, got {}", prf.ct_format);
    }

    if !prf.params.no_compression {
        anyhow::bail!("prf requires --no-compression input");
    }

    if !prf.params.no_precompute_sns {
        anyhow::bail!("prf requires --no-precompute-sns input");
    }

    let prf_ct: FheUint32 = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(prf.cipher.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize prf FheUint32: {err}"))?;

    let server_key_bytes = tokio::fs::read(server_key_path.as_ref()).await?;

    let high_level_server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
        Cursor::new(server_key_bytes.as_slice()),
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to deserialize server key as tfhe::ServerKey: {err}"))?;

    tfhe::set_server_key(high_level_server_key);

    let prf64: FheUint64 = prf_ct.cast_into();
    let product64: FheUint64 = prf64 * numerator;
    let scaled64: FheUint64 = product64 / denominator;
    let scaled32: FheUint32 = scaled64.cast_into();

    let mut scaled_buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(
        &scaled32,
        &mut scaled_buf,
        POS_SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|err| anyhow::anyhow!("failed to serialize scaled PRF FheUint32: {err}"))?;

    let mut params = prf.params.clone();
    params.to_encrypt = format!("{expected_result:08x}");
    params.data_type = FheType::Euint32;
    params.no_compression = true;
    params.no_precompute_sns = true;
    params.ciphertext_output_path = None;
    params.batch_size = 1;
    params.num_requests = 1;
    params.inter_request_delay_ms = 0;
    params.parallel_requests = 0;
    params.compressed_keys = false;
    params.extra_data = None;

    let out = CipherWithParams {
        params,
        ct_format: "SmallExpanded".to_owned(),
        cipher: scaled_buf,
    };
