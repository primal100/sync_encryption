import sys

from utils import timing
import logging
import subprocess
import hashlib
from pathlib import Path
import os
from cryptography.fernet import Fernet


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


size = int(1024*1024*1024)
num_gb = 10
bin_fpath = Path('data.bin')
enc_bin_fpath = Path('data.enc')
key_path = Path('key.key')


def write_large_binary_file():
    data = os.urandom(size)
    with bin_fpath.open('wb') as f:
        for i in range(0, num_gb):
            f.write(data)


def write_key() -> None:
    """
    Generates a key and save it into a file
    """
    if not key_path.exists():
        key = Fernet.generate_key()
        key_path.write_bytes(key)


def load_key() -> bytes:
    """
    Loads the key from the current directory named `key.key`
    """
    return key_path.read_bytes()


@timing
def encrypt_binary_file(key: bytes, fpath: Path, block_size=2 ** 20):
    f = Fernet(key)
    print('Fernet Loaded')
    with fpath.open("rb") as fin, enc_bin_fpath.open("wb") as fout:
        while True:
            block = fin.read(block_size)
            if not block:
                break
            output = f.encrypt(block)
            fout.write(output)


@timing
def decrypt_binary_file(key: bytes, fpath: Path, block_size=2 ** 20):
    f = Fernet(key)
    print('Fernet loaded')
    with enc_bin_fpath.open("rb") as fin, fpath.open("wb") as fout:
        while True:
            block = fin.read(block_size)
            if not block:
                break
            print('Decrypting')
            output = f.decrypt(block)
            fout.write(output)


def compare_directories(source: Path, dest: Path):
    logger.debug('Walking')
    for subdir, dirs, files in os.walk(source):
        logger.debug('Walking complete')
        for file in files:
            path = Path(os.path.join(source, subdir, file))
            dst_path = Path(os.path.join(dest, subdir, file))
            logger.debug('Comparing %s with %s', path, dst_path)
            md5sum = get_md5sum_binaryfile(path)
            if dst_path.exists():
                dst_md5sum = get_md5sum_binaryfile(dst_path)
                if md5sum == dst_md5sum:
                    logger.debug('%s md5sum matches', path)
                else:
                    logger.error('%s md5sum does not match', path)
            else:
                logger.error('%s does not exist', path)


if __name__ == "__main__":
    write_large_binary_file()
    print('file written')
    write_key()
    key = load_key()
    print('key loaded')

    # compare_directories(Path(sys.argv[1]), Path(sys.argv[2]))

    """md5sum = get_md5sum_subprocess(bin_fpath)

    print(f'Linux md5sum of binary file {bin_fpath} is {md5sum}')

    md5sum = result = get_md5sum_binaryfile(bin_fpath)

    print(f'Python md5sum of binary file {bin_fpath} is {md5sum}')"""

    print('Encrypting')
    encrypt_binary_file(key, bin_fpath)
    print(f'Encrypted {bin_fpath} to {enc_bin_fpath} done')

    print('Decrypting')
    decrypt_binary_file(key, bin_fpath)
    print(f'Decrypted {bin_fpath} verified')

    bin_fpath.unlink()
    enc_bin_fpath.unlink()
