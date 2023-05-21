'''
MIT License

Copyright (c) 2023 Homer Riva-Cambrin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Sonorus
Robust AES256 CLI encrypt/decrypt with configurable low-memory overhead
Author: Homer Riva-Cambrin
Version: May 20th, 2023
'''

import os
import argparse
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import struct
from io import BytesIO
from functools import reduce

MB_TO_BYTES = 10**6
NONCE_SIZE = 12
BYTES_IN_LONG = 8 # Note, this is not configurable
PROGRESS_BAR_LENGTH = 48

class colors: # Borrowed from blender's colors
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'

def print_with_header(msg, header=''):
    print(f'{header}[{colors.GREEN}SONORUS{colors.RESET}] {msg}',end='')
    
def error_print(msg):
    print(f'[{colors.GREEN}SONORUS{colors.RESET}] [{colors.FAIL}ERROR{colors.RESET}] {msg}',end='') 

def long_to_bytes(val):
    return struct.pack(">Q", val)

def bytes_to_long(val):
    return struct.unpack('>Q', val)[0]

def safe_delete_dir(dir):
    for file in dir:
        safe_delete_file(file)
        
def safe_delete_file(file):
    if os.path.exists(file):
        os.remove(file)

def walk(array, empty_dirs, directory):
    for f in os.listdir(directory):
        full_name = f'{directory}/{f}'
        path = os.path.relpath(full_name)
        if os.path.isdir(path):
            if len(os.listdir(full_name)) == 0:
                empty_dirs.append(full_name)
            walk(array, empty_dirs, full_name)
        else:
            array.append(full_name)

def create_key(password: str, length=32, n=2**20, r=8, p=1) -> bytes:
    return Scrypt(salt=b'', length=length, n=n, r=r, p=p).derive(password.encode())

def draw_progress_bar(count, max):
    progress = round(PROGRESS_BAR_LENGTH * (count / float(max)))
    print(f"\r[{colors.GREEN}SONORUS{colors.RESET}] Progress [{colors.GREEN}{'#'*progress}{colors.WARNING}{'-'*(PROGRESS_BAR_LENGTH-progress)}{colors.RESET}]", end='')

class ChainCryptEditor(object):
    
    def __init__(self, max_bytes, key) -> None:
        self.max_bytes = max_bytes
        self.bytes_processed = 0
        self.key = key
        self.data_buffer = BytesIO(b'')
    
    def write_bytes(self, data, count=True):
        if count: self.bytes_processed += len(data)
        self.data_buffer.write(data)
        draw_progress_bar(self.bytes_processed, self.max_bytes)

class ChainCryptWriter(ChainCryptEditor):
    
    def __init__(self, args, max_chunk_size, key, max_bytes: int): # TO-DO add minimum max chunk size of 48
        super().__init__(max_bytes, key)
        self.max_chunk_size = max_chunk_size
        self.file_handle = open(args.target + '/' + args.store + '.snr', 'ab')
        self.indexes = []
        self.index_offset = 0

    def write_empty_dirs(self, dirs):
        # [ DIRECTORY COUNT ] [ [ NAME LENGTH ] [ NAME ] ]
        self.write_bytes(long_to_bytes(len(dirs)), count=False)
        for dir in dirs:
            name_encoded = dir.encode()
            data = long_to_bytes(len(name_encoded)) + name_encoded
            self.write_bytes(data, count=False)
            self.index_offset += len(data)
        
    def write_file(self, name: bytes, file_name) -> None:
        file_size = os.path.getsize(file_name)
        buffer = open(file_name, 'rb')
        
        # [ FILE SIZE ] [ NAME LENGTH ] [ NAME ] [ DATA ]
        self.write_bytes(long_to_bytes(file_size))
        self.write_bytes(long_to_bytes(len(name)))
        self.write_bytes(name)
        
        # The tell is where we currently are, so by subtracting from the total we
        # find out how many bytes we have left.
        while file_size - buffer.tell() > self.max_chunk_size:
            # Write bytes and flush this out to a new file
            self.write_bytes(buffer.read(self.max_chunk_size))
            self.flush()

        self.write_bytes(buffer.read()) # Write the remainder.
        buffer.close()

    def flush(self):
        if len(self.data_buffer.getbuffer()) == 0: return # No empty files.
        current_data = self.data_buffer.getbuffer()
        self.data_buffer = BytesIO(b'')
                
        # Run the data through encryption
        nonce = os.urandom(NONCE_SIZE)
        current_data = AESGCM(self.key).encrypt(nonce, current_data, b'')

        # Advance the index and add it to our index list
        self.indexes.append(self.index_offset)
        self.index_offset += len(nonce) + len(current_data)

        self.file_handle.write(nonce + current_data)

    
    def finalize(self):
        self.flush() # Flush any remaining data to disk
        # [ [ INDEX ] ] [ INDEX COUNT ] 
        for val in self.indexes:
            self.file_handle.write(long_to_bytes(val))
        self.file_handle.write(long_to_bytes(len(self.indexes)))
        self.file_handle.close()
    
    
class ChainCryptReader(ChainCryptEditor):
    
    def __init__(self, args, max_chunk_size, key, max_bytes) -> None:
        super().__init__(max_bytes, key)
        self.args = args
        self.max_chunk_size = max_chunk_size
        
        self.file_len = -1
        self.cur_file_name = ''
        self.bytes_to_flush = 0
    
    def finish_file(self):
        if self.cur_file_name == '': return # No empty files.  
        self.data_buffer.close()
            
        # Reset file reading buffer
        self.file_len = -1
        self.cur_file_name = ''
        self.bytes_to_flush = 0
        
    def process_files(self, temp_buffer: BytesIO): # THIS BUFFER IS CLOSED IN THE READ_STORE METHOD!
        buffer_length = len(temp_buffer.getbuffer())
        
        while buffer_length - temp_buffer.tell():
            if self.file_len == -1:
                # READ FILE DETAILS [ FILE LENGTH ] [ FILE NAME LENGTH ] [ FILE NAME ] [ DATA ]
                self.file_len = bytes_to_long(temp_buffer.read(BYTES_IN_LONG))
                name_len = bytes_to_long(temp_buffer.read(BYTES_IN_LONG))
                self.cur_file_name = temp_buffer.read(name_len).decode()
                
                os.makedirs(os.path.dirname(self.cur_file_name), exist_ok=True)
                self.data_buffer = open(self.cur_file_name, 'wb')
                
                # If the file is empty, this will make sure we still get it to preserve the file structure
                if self.file_len == 0:
                    self.finish_file()
                    continue  
            
            # The tell is how many bytes we are currently at, so taking the difference tells us how 
            # many we have to go.
            remaining_bytes = buffer_length - temp_buffer.tell()
            
            if remaining_bytes > self.file_len: # If there are more bytes remaining then left in the file, consume the necessary bytes and close the file.
                self.write_bytes(temp_buffer.read(self.file_len))
                self.finish_file()
            else: # Else just subtract and keep eating away at the stores until we have mined out the files
                self.file_len -= remaining_bytes
                self.write_bytes(temp_buffer.read(remaining_bytes))
                self.bytes_to_flush += remaining_bytes

            if self.bytes_to_flush > self.max_chunk_size: # Prevents us from having more than this amount in the memory at one given time
                self.bytes_to_flush = 0
                self.data_buffer.flush()
        
    def read_store(self):
        with open(f'{self.args.target}/{self.args.store}.snr', 'rb') as file:
            # Get the indexes
            file.seek(-BYTES_IN_LONG, 2) # Read the index count
            index_count = bytes_to_long(file.read(BYTES_IN_LONG))
            file.seek(-BYTES_IN_LONG + (-BYTES_IN_LONG)*index_count, 2)
            indexes = [bytes_to_long(file.read(BYTES_IN_LONG)) for i in range(index_count)] # Get the list of indexes
            
            for i in range(index_count):
                file.seek(indexes[i])
                nonce = file.read(NONCE_SIZE) # Read out 12-byte nonce
                
                if i == index_count - 1:
                    raw_data = file.read()[:(-BYTES_IN_LONG + (-BYTES_IN_LONG)*index_count)] # If we are the last section, we just want to read
                    # the rest except for the indexes.
                else:
                    raw_data = file.read((indexes[i + 1] - indexes[i]) - NONCE_SIZE) # Read the rest of this section's data
                
                # Process the data
                buffer = BytesIO(AESGCM(self.key).decrypt(nonce, raw_data, b''))
                
                if i == 0: # If this is our first section, we need to extract our empty directories
                    dir_count = bytes_to_long(buffer.read(BYTES_IN_LONG))
                    for i in range(dir_count):
                        os.makedirs(buffer.read(bytes_to_long(buffer.read(BYTES_IN_LONG))).decode(), exist_ok=True) 
                self.process_files(buffer)
                
                buffer.close()
        self.data_buffer.close()
    
def obtain_key(args):
    if not os.path.exists(args.keyfile):
            error_print(f'Could not find keyfile {colors.WARNING}{args.keyfile}{colors.RESET}. Please check the name and try again.\n')
            return None
    else:
        with open(args.keyfile, 'r') as file:
            raw_key = file.read()
    # Generate actual key
    key = create_key(raw_key) 
    return key 

def verify_args(command, parser, args):
    if args.target is None:
            parser.error(f'{command} requires --target to be specified.')
    if args.store is None:
            parser.error(f'{command} requires --store to be specified.')
    if args.keyfile is None:
        parser.error(f'{command} requires --keyfile to be specified.')

def encrypt_partitions(parser: argparse.ArgumentParser, args, chunksize):
    verify_args('--encrypt', parser, args)    
        
    print_with_header(f'You are about to encrypt{colors.CYAN} {args.target}{colors.RESET}. Are you sure you want to proceed? {colors.WARNING}(y/n) {colors.RESET}')
    choice = input()
    if choice.lower() == 'y':
        if os.path.exists(args.target + "/" + args.store + '.snr'):
            error_print(f'There already exists a file in that destination with the specified store name. Please move or re-name this file to prevent data corruption.\n')
            error_print(f'Additionally, keep in mind that encrypting things multiple times does not necesarily enhance security.\n')
            return
        
        key = obtain_key(args)
        if key is None: return       
        print_with_header("Succesfully obtained the encryption key from the keyfile.\n")
        
        locations = []
        empty_dirs = []
        walk(locations, empty_dirs, args.target)
        print_with_header("Succesfully scanned directory.\n")
        
        # Reduce the list of the locations by reducing them with a summing function
        total_size = sum([os.path.getsize(x) for x in locations])   
        chain = ChainCryptWriter(args, chunksize, key, total_size)    
        chain.write_empty_dirs(empty_dirs)
        safe_delete_dir(empty_dirs)
        for loc in locations:
            chain.write_file(loc.encode(), loc)
            safe_delete_file(loc)      
        chain.finalize()
        print_with_header("Finished encrypting data.\n", header='\n')
    else:
        print_with_header('Cancelling...')
        
def decrypt_partitions(parser: argparse.ArgumentParser, args, chunksize):
    # Catch missing parameters
    verify_args('--decrypt', parser, args)
    full_path = args.target + '/' + args.store + '.snr'
    if not os.path.exists(full_path):
        error_print(f'Could not find a {colors.WARNING}{args.store}.snr{colors.RESET} in {colors.CYAN}{full_path}{colors.RESET}. Please check your store name and try again.')
        return
          
    key = obtain_key(args)
    if key is None: return
    print_with_header("Obtained key from keystore...\n")    
    print_with_header(f'Beginning decryption of {colors.CYAN}{full_path}{colors.RESET}...\n')
    
    # Read out the encrypted fileset
    total_size = os.path.getsize(full_path)
    reader = ChainCryptReader(args, chunksize, key, total_size)
    reader.read_store()
    print_with_header(f'Finished decrypting.\n', header='\n')
    
    if args.delete:
        safe_delete_file(full_path)
    
    

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--encrypt', help='Encrypts the items within the directory.', action='store_true')
    parser.add_argument('--decrypt', help='Decrypts the items within the store.', action='store_true')
    parser.add_argument('--target', help='Sets the encryption target')
    parser.add_argument('--keyfile', help='Specs the location of the key file')
    parser.add_argument('--store', help='Specifies store directory name.')
    parser.add_argument('--delete', help='Deletes old data once encrypted.', action='store_true')
    parser.add_argument('--chunksize', help='How much of the file will be stored in memory before being flushed, in megabytes.')
    args = parser.parse_args()
    
    if args.chunksize is None:
        parser.error("--chunksize must be specified. Remember it is given in megabytes (MB)")
    
    try: # Get chunksize and verify that it is correct.
        chunksize = int(args.chunksize) * MB_TO_BYTES
    except:
        parser.error("--chunksize must be a positive integer.")
        
    if chunksize <= 0: parser.error("--chunksize must be a positive integer.")
    
    if not args.encrypt and not args.decrypt:
        error_print('You must specify either --encrypt or --decrypt')
        return
    
    if args.encrypt:
        encrypt_partitions(parser, args, chunksize)
    if args.decrypt:
        try:
            decrypt_partitions(parser, args, chunksize)
        except:
            error_print("Failed to decrypt! This could be due to several reasons, including that your data was tampered\n")
            error_print("or was compressed, or the format was modified. Make sure this is an actual .snr file.\n")
    

if __name__ == "__main__":
    main()
