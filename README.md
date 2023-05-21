# Sonorus
Simple AES256 CLI encrypt/decrypt tool with configurable low memory overhead limits

## Setup
This tool is designed to be as lightweight as possible, so there is only one library required 'cryptography':
```
pip install cryptography
```
If your terminal does not support ANSI colors, you may run into formatting issues when using the tool. Additionally, it was designed to use the OS library to enable the script to work cross-platform.

## Usage
Besides from that, the command can be run from the command line. If you need to see all the possible flags, you can run the tool with -h, which will return the following:
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
This tool is designed to be as simple as possible and to make the process of encrypting and decrypting your data extremely easy.

**Parameters**
* **--chunksize** The size of the encryption chunks. This is specified in megabytes (MB) and is very important. This is about the maximum amount of data that will be handled at one point in memory, so if you are on a low memory device, set this lower. Additionally, it does have some vague security implications, read [Recommendations](#recommendations)
* **--store** The name of the file that is generated. For instance, if you chose 'crypt' then you would end up with a file named 'crypt.snr' in your target directory.
* **--delete** In the case of encryption, deletes the unencrypted files. In the case of decryption, deletes the store file once done.
* **--target** Directory of where you are encrypting/decrypting
* **--encrypt** and **--decrypt** specifies whether we are encrypting or decrypting

## How it works

## Recommendations

liability thing

## References
