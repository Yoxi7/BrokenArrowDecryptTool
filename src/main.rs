use aes::Aes256;
use cbc::cipher::{
    block_padding::Pkcs7,
    BlockDecryptMut,
    BlockEncryptMut,
    KeyIvInit,
};
use clap::{Parser, Subcommand};
use rand::RngCore;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;

const KEY: &[u8; 32] = b"09234237536700238099172758697347";
const MARKER: &[u8; 8] = b"fhk3s0g3";
const IV_SIZE: usize = 16;

#[derive(Parser)]
#[command(
    name = "broken-arrow-dek",
    version,
    about = "Encrypt/decrypt Broken Arrow .dek files"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decrypt .dek into JSON
    Decrypt {
        input: PathBuf,
        output: PathBuf,
    },

    /// Encrypt JSON into .dek
    Encrypt {
        input: PathBuf,
        output: PathBuf,

        /// Optional IV as 32 hexadecimal characters
        #[arg(long)]
        iv: Option<String>,

        /// Don't pretty-print JSON
        #[arg(long)]
        compact: bool,
    },
}

fn decrypt_file(input: &PathBuf, output: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input)?;

    if data.len() < MARKER.len() + IV_SIZE {
        return Err("File is too small".into());
    }

    if &data[..8] != MARKER {
        return Err("Invalid .dek marker".into());
    }

    let iv = &data[8..24];
    let ciphertext = &data[24..];

    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err("Invalid ciphertext length".into());
    }

    let mut buffer = ciphertext.to_vec();

    let plaintext = Aes256CbcDec::new(KEY.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| "AES decryption / PKCS#7 padding failed")?;

    let text = std::str::from_utf8(plaintext)
        .map_err(|_| "Decrypted data is not valid UTF-8")?;

    let json: Value = serde_json::from_str(text)
        .map_err(|e| format!("Decrypted data is not valid JSON: {e}"))?;

    let formatted = serde_json::to_string_pretty(&json)?;

    fs::write(output, formatted)?;

    println!("Decrypted successfully");
    println!("Input:  {}", input.display());
    println!("Output: {}", output.display());
    println!("IV:     {}", hex::encode(iv));

    Ok(())
}

fn encrypt_file(
    input: &PathBuf,
    output: &PathBuf,
    iv_arg: Option<String>,
    compact: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let input_data = fs::read_to_string(input)?;

    let json: Value = serde_json::from_str(&input_data)
        .map_err(|e| format!("Input is not valid JSON: {e}"))?;

    let plaintext = if compact {
        serde_json::to_vec(&json)?
    } else {
        serde_json::to_vec_pretty(&json)?
    };

    let iv: [u8; IV_SIZE] = match iv_arg {
        Some(hex_iv) => {
            let decoded = hex::decode(hex_iv)?;

            if decoded.len() != IV_SIZE {
                return Err("IV must be exactly 16 bytes (32 hex characters)".into());
            }

            decoded
                .try_into()
                .map_err(|_| "Invalid IV")?
        }

        None => {
            let mut iv = [0u8; IV_SIZE];
            rand::thread_rng().fill_bytes(&mut iv);
            iv
        }
    };

    let padded_len = ((plaintext.len() / 16) + 1) * 16;
    let mut buffer = vec![0u8; padded_len];

    buffer[..plaintext.len()].copy_from_slice(&plaintext);

    let ciphertext = Aes256CbcEnc::new(KEY.into(), (&iv).into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|_| "AES encryption failed")?;

    let mut output_data =
        Vec::with_capacity(MARKER.len() + IV_SIZE + ciphertext.len());

    output_data.extend_from_slice(MARKER);
    output_data.extend_from_slice(&iv);
    output_data.extend_from_slice(ciphertext);

    fs::write(output, output_data)?;

    println!("Encrypted successfully");
    println!("Input:  {}", input.display());
    println!("Output: {}", output.display());
    println!("IV:     {}", hex::encode(iv));

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Decrypt { input, output } => {
            decrypt_file(&input, &output)
        }

        Command::Encrypt {
            input,
            output,
            iv,
            compact,
        } => {
            encrypt_file(&input, &output, iv, compact)
        }
    };

    if let Err(error) = result {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}