use chacha20poly1305::aead::{Aead, OsRng};
use chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305, XNonce};
use clap::{Arg, ArgMatches};
use rand::RngCore;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use tar::Builder;

const NONCE_SIZE: usize = 24;
const SALT_SIZE: usize = 32;
const KEY_SIZE: usize = 32;

fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let matches = clap::Command::new("emerald")
        .bin_name("emerald")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            clap::command!("encrypt")
                .arg(
                    Arg::new("files")
                        .short('f')
                        .long("files")
                        .required(true)
                        .value_delimiter(','),
                )
                .arg(Arg::new("output").short('o').long("output").required(false)),
        )
        .subcommand(
            clap::command!("decrypt")
                .arg(Arg::new("input").short('i').long("input").required(true))
                .arg(Arg::new("output").short('o').long("output").required(false)),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            encrypt(sub_matches)?;
        }
        Some(("decrypt", sub_matches)) => {
            decrypt(sub_matches)?;
        }
        _ => unreachable!(),
    };

    Ok(())
}

fn decrypt(sub_matches: &ArgMatches) -> anyhow::Result<()> {
    let input = PathBuf::from(sub_matches.get_one::<String>("input").unwrap());

    let output = sub_matches
        .get_one::<String>("output")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut o = input.clone();
            o.set_extension("tar");
            o
        });

    let pass = prompt_pass();

    let mut input_file = File::open(&input)?;
    let mut bytes = Vec::new();

    input_file.read_to_end(&mut bytes)?;

    let nonce = XNonce::from_slice(&bytes[0..NONCE_SIZE]);
    let salt = &bytes[NONCE_SIZE..(NONCE_SIZE + SALT_SIZE)];
    let data = &bytes[(NONCE_SIZE + SALT_SIZE)..];

    let key = derive_key(pass, &salt);

    let cipher = XChaCha20Poly1305::new(&key);

    let mut output = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&output)?;

    let decrypted = cipher
        .decrypt(&nonce, data)
        .map_err(|e| anyhow::anyhow!(e))?;
    output.write_all(decrypted.as_slice())?;

    Ok(())
}

fn encrypt(sub_matches: &ArgMatches) -> anyhow::Result<()> {
    let files = sub_matches
        .get_many::<String>("files")
        .unwrap()
        .collect::<Vec<_>>();

    let output = sub_matches.get_one::<PathBuf>("output");

    let output = create_tarball(&files, output)?;

    let pass = prompt_pass();
    let salt = generate_salt();
    let key = derive_key(pass, &salt);

    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(&key);

    let mut archive = File::open(&output)?;
    let mut buf = Vec::new();
    archive.read_to_end(&mut buf).unwrap();
    let mut encrypted = cipher.encrypt(&nonce, buf.as_slice()).unwrap();

    let mut out_bytes = Vec::from(&nonce.as_slice()[..]);
    out_bytes.append(&mut salt.to_vec());
    out_bytes.append(&mut encrypted);

    let mut output_enc = output.clone();
    output_enc.set_extension("tar_enc");
    let mut output_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&output_enc)?;
    output_file.write_all(&out_bytes)?;

    std::fs::remove_file(&output)?;

    Ok(())
}

fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);

    salt
}

fn derive_key(pass: String, salt: &[u8]) -> chacha20poly1305::Key {
    let mut derived_key = [0u8; KEY_SIZE];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&pass.as_bytes(), &salt, 10000, &mut derived_key);

    let chacha_key = chacha20poly1305::Key::from_slice(&derived_key);

    *chacha_key
}

fn prompt_pass() -> String {
    loop {
        let pass: String = rpassword::prompt_password("Enter key: ").unwrap();
        let pass_repeat: String = rpassword::prompt_password("Repeat key: ").unwrap();

        if pass == pass_repeat {
            return pass;
        }

        println!("WARNING: Provided passwords did not match.")
    }
}

fn create_tarball(files: &Vec<&String>, output: Option<&PathBuf>) -> anyhow::Result<PathBuf> {
    let archive_path = output.unwrap_or(&PathBuf::from("archive.tar")).to_owned();
    let mut tarball = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&archive_path)?;

    let mut builder = Builder::new(&mut tarball);

    for file_path in files {
        // Add the file to the tarball
        builder.append_path_with_name(&file_path, PathBuf::from(file_path).file_name().unwrap())?;
    }

    builder.finish()?;

    Ok(archive_path)
}
