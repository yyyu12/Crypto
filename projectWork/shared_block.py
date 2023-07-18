#SHARED BLOCK

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA512, SHA1, HMAC
from Crypto.Signature import PKCS1_PSS
from Crypto.Signature import pkcs1_15
from sage.crypto.util import bin_to_ascii
import binascii
import secrets
import hashlib

def binary_to_string(binary_string):
    # Split the binary string into chunks of 8 characters
    chunks = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    
    # Convert each chunk to its corresponding ASCII character
    ascii_chars = [chr(int(chunk, 2)) for chunk in chunks]
    
    # Join the ASCII characters to form the resulting string
    result = ''.join(ascii_chars)
    
    return result

def xor_bytes(lhs, rhs):
    return bytes(map(lambda x: x[0] ^^ x[1], zip(lhs, rhs)))

def prf(hash_func, secret: bytes, label: bytes, orig_seed: bytes, N):
    seed = label + orig_seed
    random_bytes = b''
    a = seed
    while len(random_bytes) < N:
        a = hmac(hash_func, secret, a)
        random_bytes += hmac(hash_func, secret, a + seed)
    return random_bytes[:N]

def hmac(hash_func, key: bytes, message: bytes):
    digest_size = hash_func().digest_size
    
    key_with_digest_size = key
    if len(key) < digest_size:
        key_with_digest_size += bytes(digest_size - len(key))
    elif len(key) > digest_size:
        key_with_digest_size = hash_func(key).digest()
    
    ipad = bytes([0x36 for _ in range(digest_size)])
    opad = bytes([0x5c for _ in range(digest_size)])
    
    key_with_ipad = xor_bytes(key_with_digest_size, ipad)
    key_with_opad = xor_bytes(key_with_digest_size, opad)
    
    return hash_func(key_with_opad + hash_func(key_with_ipad + message).digest()).digest()

def encrypt_long_message(plaintext, client_public_enc_key):
    chunk_size = 214
    cipher = PKCS1_OAEP.new(client_public_enc_key.publickey(), hashAlgo=SHA1)

    encrypted_chunks = []

    for i in range(0, len(plaintext), chunk_size):
        chunk = plaintext[i : i + chunk_size]
        print("[Encrypt] Size chunk_block = ", len(chunk))
        encrypted_ = cipher.encrypt(chunk)
        encrypted_chunks.append(encrypted_)

    return b"".join(encrypted_chunks)

def decrypt_long_message(encrypted_blocks, client_private_dec_key):
    chunk_size = 256
    cipher = PKCS1_OAEP.new(client_private_dec_key, hashAlgo=SHA1)

    decrypted_chunks = []

    for i in range(0, len(encrypted_blocks), chunk_size):
        chunk = encrypted_blocks[i : i + chunk_size]
        print("[Decrypt] Size chunk_block = ", len(chunk))
        assert len(chunk) == 256
        decrypted_ = cipher.decrypt(chunk)
        decrypted_chunks.append(decrypted_)
        
    return b"".join(decrypted_chunks)


def pad_input_string(input_string, block_size=16):
    pad_len = block_size - (len(input_string) % block_size)
    return input_string + chr(pad_len) * (pad_len)

def unpad_input_string(padded_string):
    pad_len = ord(padded_string[-1])
    return padded_string[:-pad_len]


def encrypt_mini_aes(plain_text, key):
    maes = MiniAES()
    bin = BinaryStrings()
    
    key_binary_string = bin(key.decode())
    
    print("Bits of Key Binary String = ", key_binary_string)
    print("Number of bits of Key Binary = ", len(key_binary_string))
        
    plain_text_string = pad_input_string(plain_text)
    P = bin.encoding(plain_text_string);
    
    C = maes(P, key_binary_string, algorithm="encrypt");
    
    return C
    
def decrypt_mini_aes(cipher, key):
    maes = MiniAES()
    bin = BinaryStrings()

    key_binary_string = bin(key.decode())

    print("[Decrypt] Bits of Key Binary String = ", key_binary_string)
    print("[Decrypt] Number of bits of Key Binary = ", len(key_binary_string))

    decrypted_text_padded = maes(cipher, key_binary_string, algorithm="decrypt")
    to_string = str(decrypted_text_padded)
    
    return unpad_input_string(to_string)

def add_extra_dollar(string_intput):
    string_intput = string_intput.strip()
    len_extra = 16
    for i in range(len_extra):
        string_intput += '$'
    return string_intput
        
def remove_extra_dollar(text):
    index = text.find('$')
    rem = len(text) - index
    text = text[:-rem]
    #print("Index = ", index)
    return text