# Crypto Project (SC – Year 3 IR, 2025)

## Overview
This repository contains an individual implementation **from scratch** (no external cryptographic libraries) of:

* Two modern symmetric-key algorithms  
  * **AES-128** – block cipher (ECB, CBC & CTR modes)  
  * **TEA** – Tiny Encryption Algorithm (ECB & CBC modes)

* One modern asymmetric-key algorithm  
  * **RSA** – 1024-bit keys

## Directory structure
```text
├── src/                # C sources & headers
├── keys/               # sample RSA + symmetric keys
├── test/              # test vectors
├── Makefile            # build script
```

## Building
Requires **GCC** (or Clang) and GNU Make.
```bash
gcc -std=c11 -O2 -Wall -Wextra src/*.c -o crypto.exe -lgmp
```
## Usage
### Symmetric encryption/decryption (AES or TEA)
```bash
# encrypt with AES in CBC mode
./crypto -e -a aes -m cbc -i plaintext.bin -k keys/aes.key -o ciphertext.bin

# decrypt with TEA in CBC mode
./crypto -d -a tea -m cbc -i ciphertext.bin -k keys/tea.key -o decrypted.bin
```
* `-e | -d`   encrypt / decrypt  
* `-a`         `aes` or `tea`  
* `-m`         `ecb`, `cbc`, `ctr` (cbc only for now)  
* `-i`         input file  
* `-k`         key file (hex-encoded)  
* `-o`         output file  

### Asymmetric encryption/decryption (RSA)
```bash
# encrypt (public key)
./crypto -e -a rsa -i message.bin -k keys/rsa_pub.key -o enc.bin

# decrypt (private key)
./crypto -d -a rsa -i enc.bin -k keys/rsa_priv.key -o msg_out.bin
```
RSA key files are simple text:
```text
n=<hex modulus>
e=<hex exponent>
d=<hex private exponent>    # only in private key
```

