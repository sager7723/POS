use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use kms_core_client::read_cipher_with_params_external_view;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "kms_tfhe_eval")]
#[command(about = "PoS native KMS/TFHE evaluator validation tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Decode {
        #[arg(long)]
        left: PathBuf,

        #[arg(long)]
        right: PathBuf,

        #[arg(long)]
        server_key: PathBuf,

        #[arg(long)]
        expected_key_id: String,

        #[arg(long, default_value = "euint8")]
        expected_data_type: String,

        #[arg(long, default_value = "SmallExpanded")]
        expected_ct_format: String,
    },
}

#[derive(Debug, Serialize)]
struct CipherReport {
    path: String,
    to_encrypt_hex: String,
    data_type: String,
    no_compression: bool,
    no_precompute_sns: bool,
    key_id: String,
    ct_format: String,
    cipher_len: usize,
    cipher_prefix_hex: String,
}

#[derive(Debug, Serialize)]
struct DecodeReport {
    ok: bool,
    expected_key_id: String,
    expected_data_type: String,
    expected_ct_format: String,
    server_key_path: String,
    server_key_len: usize,
    server_key_prefix_hex: String,
    left: CipherReport,
    right: CipherReport,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Decode {
            left,
            right,
            server_key,
            expected_key_id,
            expected_data_type,
            expected_ct_format,
        } => {
            let report = decode_command(
                left,
                right,
                server_key,
                expected_key_id,
                expected_data_type,
                expected_ct_format,
            )
            .await?;

            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }

    Ok(())
}

async fn decode_command(
    left_path: PathBuf,
    right_path: PathBuf,
    server_key_path: PathBuf,
    expected_key_id: String,
    expected_data_type: String,
    expected_ct_format: String,
) -> Result<DecodeReport> {
    let left = read_cipher_with_params_external_view(&left_path)
        .await
        .with_context(|| format!("failed to read left ciphertext {}", left_path.display()))?;

    let right = read_cipher_with_params_external_view(&right_path)
        .await
        .with_context(|| format!("failed to read right ciphertext {}", right_path.display()))?;

    validate_cipher("left", &left, &expected_key_id, &expected_data_type, &expected_ct_format)?;
    validate_cipher("right", &right, &expected_key_id, &expected_data_type, &expected_ct_format)?;

    let server_key_bytes = tokio::fs::read(&server_key_path)
        .await
        .with_context(|| format!("failed to read server key {}", server_key_path.display()))?;

    if server_key_bytes.is_empty() {
        bail!("server key file is empty: {}", server_key_path.display());
    }

    let prefix_len = std::cmp::min(server_key_bytes.len(), 32);

    Ok(DecodeReport {
        ok: true,
        expected_key_id,
        expected_data_type,
        expected_ct_format,
        server_key_path: server_key_path.display().to_string(),
        server_key_len: server_key_bytes.len(),
        server_key_prefix_hex: hex::encode(&server_key_bytes[..prefix_len]),
        left: CipherReport {
            path: left_path.display().to_string(),
            to_encrypt_hex: left.to_encrypt_hex,
            data_type: left.data_type,
            no_compression: left.no_compression,
            no_precompute_sns: left.no_precompute_sns,
            key_id: left.key_id,
            ct_format: left.ct_format,
            cipher_len: left.cipher_len,
            cipher_prefix_hex: left.cipher_prefix_hex,
        },
        right: CipherReport {
            path: right_path.display().to_string(),
            to_encrypt_hex: right.to_encrypt_hex,
            data_type: right.data_type,
            no_compression: right.no_compression,
            no_precompute_sns: right.no_precompute_sns,
            key_id: right.key_id,
            ct_format: right.ct_format,
            cipher_len: right.cipher_len,
            cipher_prefix_hex: right.cipher_prefix_hex,
        },
    })
}

fn validate_cipher(
    label: &str,
    cipher: &kms_core_client::ExternalCipherWithParamsView,
    expected_key_id: &str,
    expected_data_type: &str,
    expected_ct_format: &str,
) -> Result<()> {
    if cipher.key_id != expected_key_id {
        bail!(
            "{label} key_id mismatch: got {}, expected {}",
            cipher.key_id,
            expected_key_id
        );
    }

    if cipher.data_type != expected_data_type {
        bail!(
            "{label} data_type mismatch: got {}, expected {}",
            cipher.data_type,
            expected_data_type
        );
    }

    if cipher.ct_format != expected_ct_format {
        bail!(
            "{label} ct_format mismatch: got {}, expected {}",
            cipher.ct_format,
            expected_ct_format
        );
    }

    if !cipher.no_compression {
        bail!("{label} was not generated with --no-compression");
    }

    if !cipher.no_precompute_sns {
        bail!("{label} was not generated with --no-precompute-sns");
    }

    if cipher.cipher_len == 0 {
        bail!("{label} inner cipher is empty");
    }

    Ok(())
}
