# emerald

Basic command line utility to encrypt / decrypt files using XChaCha20Poly1305 with Argon2 key derivation.

## Usage

To encrypt files:
```bash
cargo run -- encrypt --files ./file1.txt,./file2.txt
# if built:
emerald encrypt --files ./file1.txt,./file2.txt
```
To decrypt files:
```bash
cargo run -- decrypt --input ./archive.tar_enc
# if built:
emerald decrypt --input ./archive.tar_enc
```