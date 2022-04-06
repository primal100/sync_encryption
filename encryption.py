import os
from pathlib import Path
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import time
import struct
import hashlib
from cryptography.fernet import Fernet
from typing import Optional


class KeyOrPasswordRequired(BaseException):
    pass


def pack_int(num: int) -> bytes:
    return struct.pack('I', num)


def pack_float(num: float) -> bytes:
    return struct.pack('f', num)


def pack_variable_len(data: bytes) -> bytes:
    return pack_int(len(data)) + data


def pack_current_time() -> bytes:
    return pack_float(time.time())


def pack_path(path: Path) -> bytes:
    return pack_variable_len(str(path).encode())


md5_placeholder = b''.join([b'0' for i in range(0, 32)])   #   32 bytes


iv = os.urandom(16)



def write_encrypted_file(password: Optional[str], key: Optional[bytes], src_file: Path, dst_dir: Path, block_size=2 ** 20):
    salt = os.urandom(16)
    algorithm_name = 'AES'
    cipher_mode = "CBC"
    key_hash_algorithm = hashes.SHA256()
    key_hash_algorithm_name = "sha256"
    key_length = 32
    key_hash_iterations = 390000

    if password and not key:
        kdf = PBKDF2HMAC(
            algorithm=key_hash_algorithm,
            length=key_length,
            salt=salt,
            iterations=key_hash_iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    elif not password and not key:
        raise KeyOrPasswordRequired('Please supply either a password or a key')

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    dst_file = dst_dir / src_file.name
    md5 = hashlib.md5()
    enc_md5 = hashlib.md5()
    header = md5_placeholder + pack_current_time() + pack_path(src_file) + pack_path(dst_file)   # H
    header = pack_variable_len(header)
    src_md5sum_position = 4
    dst_md5sum_position = 20
    with src_file.open("rb") as fin, dst_file.open("wb") as fout:
        fout.write(header)
        while True:
            data = fin.read(block_size)
            if not data:
                break
            md5.update(data)
            output = encryptor.update(data) + encryptor.finalize()
            enc_md5.update(output)
            fout.write(output)
        fout.seek(src_md5sum_position)
        fout.write(md5.digest())
        fout.seek(dst_md5sum_position)
        fout.write(md5.digest())


    data = header + pack_variable_len(encrypted_data)
    dst_file.write_bytes(data)

