# Sonorus
Simple AES256 CLI encrypt/decrypt tool with configurable low memory overhead limits

## Setup
Due to the lightweight design, there is only one library required (cryptography):
```
pip install cryptography
```
If your terminal does not support ANSI colors, you may run into formatting issues when using the tool. The script is cross-platform due to it's usage of the OS library.

## Usage
The script is run from the command line. If you need to see all the possible flags, you can run the tool with -h, which will return the following:
```
usage: sonorus.py [-h] [--encrypt] [--decrypt] [--target TARGET] [--keyfile KEYFILE] [--store STORE] [--delete]
                  [--chunksize CHUNKSIZE]

options:
  -h, --help            show this help message and exit
  --encrypt             Encrypts the items within the directory.
  --decrypt             Decrypts the items within the store.
  --target TARGET       Sets the encryption target
  --keyfile KEYFILE     Specs the location of the key file
  --store STORE         Specifies store directory name.
  --delete              Deletes old data once encrypted/decrypted (respectively, unencrypted and store file)
  --chunksize CHUNKSIZE How much of the file will be stored in memory before being flushed, in megabytes.
```
This tool is designed to be as simple as possible and to make the process of encrypting and decrypting your data extremely easy, and therefore is designed very intuitively, however the parameters are described below.

### Parameters
* **--chunksize** The size of the 'chunks' as shown in the [schema](#how-it-works) below. This is specified in megabytes (MB) and is very important. This is about the maximum amount of data that will be handled at one point in memory, so if you are on a low memory device, set this lower. Additionally, it does have some vague security implications, read [recommendations](#recommendations) for more information. Finally, the chunksize does not need to be the same for encryption and decryption. You can encrypt with a 25MB chunksize and decrypt with a 2MB chunksize.
* **--store** The name of the file that is generated. For instance, if you chose 'crypt' then you would end up with a file named 'crypt.snr' in your target directory.
* **--delete** In the case of encryption, deletes the unencrypted files. In the case of decryption, deletes the store file once done.
* **--target** Directory of where you are encrypting/decrypting
* **--keyfile** Location of the keyfile to pull the key from.
* **--encrypt** and **--decrypt** specifies whether we are encrypting or decrypting

An example of a command to encrypt a directory named 'test' into 'crypt.snr' using a key stored in 'keyfile.key' with a chunk size of 25MB is the following:
```terminal
python sonorus.py --target test --store crypt --keyfile keyfile.key --chunksize 25 --delete --encrypt
```
## How it works
This script was designed in order to be as simple as possible without exposing complex parameters. An overview of the structure is as follows:
![sonorus drawio](https://github.com/DiscordJim/sonorus/assets/75649204/784a7ac5-c0a3-497a-9f03-d30c720e733f)
It is not as complicated as it looks. You would read it as follows:
1. Read the last 8 bytes of the file. Convert it to a long long (using the definition specified in the struct library in python) and jump back number of indexes * 8.
2. Read the empty directories out.
3. Iterating through the indexes, jump to that point in the file and read out the distance between your current index and the next index. In case of last index, read out the rest minus the index information.
4. Decrypt this data using the 12 byte nonce, then read out the file length and name length, then using that read name and file data.

The encryption process starts by pulling the key from the keyfile. The key is read out and turned into a 256-bit encryption key with a memory usage of 2<sup>20</sup> recommended by the Scrypt paper[^1] for long term storage. For the other parameters, the RFC 7914 specification was followed, giving a block size of 8 and parallelization value of 1. As we write the file, we write the 'header' data first (file data length, name length, and name) and then we check if the bytes remaining in the buffer are bigger than the chunk size, if they are, read out the chunk size and then 'flush' the data until the remaining bytes are less than the chunk size. Once the remaining bytes are less than the chunk size, read the rest of the bytes out. This helps us to ensure that we are only managing around our chunk size in memory. A flush consists of encrypting the data with AES-256 in GCM mode and then writing this to the store file. Once the files are written, we write the indexes to the file, and then finally how many indexes we have.

The nonce was chosen to be 12 bytes according to NIST300-38D[^2] and was generated with `os.urandom` in order to access the underlying operating system's cryptographically secure random number generator.

## Recommendations
* The chunk size should be under 2<sup>32</sup> - 36 bytes[^3]. This is one advantage of the methods here as it prevents single chunks from being over that amount under a single key and nonce pair. Too low of a chunksize could lead to the randomly generated nonces colliding which causes a strong vulnerability if a nonce is used twice. About after 2<sup>48</sup> chunks, the chance of a notch collision is about 50%[^3].
* To mitigate this, you should only encrypt about 2<sup>32</sup> chunks under a single key. This results in about a one in four billion safety margin against the key 'wearing out'.[^4]
* The total data that should be encrypted with one key is about 2<sup>68</sup> bytes.[^4]

*Note: This can be chunks spread over several encryptions with the same key.*

[^1]: STRONGER KEY DERIVATION VIA SEQUENTIAL MEMORY-HARD FUNCTIONS (C. Percival, Ed.) [Review of STRONGER KEY DERIVATION VIA SEQUENTIAL MEMORY-HARD FUNCTIONS]. Retrieved May 20, 2023, from https://www.tarsnap.com/scrypt/scrypt.pdf
[^2]: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC (M. Dworkin, Ed.) [Review of Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC]. National Institute of Standards and Technology. https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
[^3]: Why AES-GCM Sucks (Soatok, Ed.) [Review of Why AES-GCM Sucks]. https://soatok.blog/2020/05/13/why-aes-gcm-sucks/
[^4]: Cryptographic Wear-Out for Symmetric Encryption (Soatok, Ed.) [Review of Cryptographic Wear-Out for Symmetric Encryption]. https://soatok.blog/2020/12/24/cryptographic-wear-out-for-symmetric-encryption/
