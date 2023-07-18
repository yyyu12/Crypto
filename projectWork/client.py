class Client:
    def __init__(self):
        self.rsa_length_bits = 2048
        self.hash_func = SHA512

        # Enc and sign
        self.client_rsa_enc_key = RSA.generate(2048)
        self.client_rsa_sign_key = RSA.generate(2048)

        self.signature = None
        self.client_private_key = None
        
        self.server_rsa_enc_key_public = None
        self.server_rsa_sign_key_public = None
        
        self.num_rand_bytes = 32
        self.private_num_rand_bytes = 48
        self.premaster_secret = None
        self.master_secret = None
        self.server_private_random = None
        self.server_public_random = None
        
        self.client_write_mac_key = None
        self.server_write_mac_key = None
        self.client_write_key = None
        self.server_write_key = None
        
        self.block = None
        self.client_public_random = secrets.token_bytes(self.num_rand_bytes)
        self.client_private_random = secrets.token_bytes(self.private_num_rand_bytes)

    def generate_keys_client_side(self):
        client_rsa_enc_key = self.client_rsa_enc_key.e, self.client_rsa_enc_key.n
        client_rsa_sign_key = self.client_rsa_sign_key.e, self.client_rsa_sign_key.n

        print("Client RSA Public Enc Key = ", client_rsa_enc_key) # Public key, n
        print("Client RSA Public Sign Key = ", client_rsa_sign_key) # Public key, n

        return self.client_rsa_enc_key, self.client_rsa_sign_key

    def generate_public_random_32_bytes(self):
        # Generate 32 random bytes on both sides (client_public_random, server_public_random)
        print("Client Public 32 random bytes = ", self.client_public_random)
        print("Client Public [number of bytes -> 32]: ", len(self.client_public_random))
        return self.client_public_random

    def generate_private_random_48_bytes(self):
        print("Client Private 48 random bytes = ", self.client_private_random)
        print("Client Private [number of bytes -> 48]: ", len(self.client_private_random))

    def sign_and_send(self, server_rsa_enc_key_public):
        self.server_rsa_enc_key_public = server_rsa_enc_key_public
        
        hash = SHA512.new(self.client_private_random)
        client_signature = pkcs1_15.new(self.client_rsa_sign_key).sign(hash) # 256 bytes
        
        print("[From client] Signature: ", client_signature)
        
        signed_client_signature = client_signature + self.client_private_random # 256 + 48 bytes = 304 bytes
        encrypted_signature_chunk = encrypt_long_message(signed_client_signature, server_rsa_enc_key_public)

        return encrypted_signature_chunk
    
    
    def receive_signature_from_server_and_verify(self, encrypted_signature_chunk, server_rsa_sign_key_public):
        self.server_rsa_sign_key_public = server_rsa_sign_key_public
        print("Process decrypted -- orignal encrypted_signature_chunk: ", len(encrypted_signature_chunk)) # 512 bytes
        decrypted_signature = decrypt_long_message(encrypted_signature_chunk, self.client_rsa_enc_key)
        print("Client side the decrypted signature bytes: ", len(decrypted_signature)) # 304 bytes 
        
        signature = decrypted_signature[:256]

        private_random_bytes = decrypted_signature[256:]
        
        print("[From client] Decrypted private random = ", private_random_bytes)
        print("[From client] Decrypted signature = ", signature)

        hash = SHA512.new(private_random_bytes) # 
        verifier = pkcs1_15.new(server_rsa_sign_key_public) # <- server_rsa_enc_key_public

        try:
            verifier.verify(hash, signature)
            print("", end="\n")
            print("The signature is authentic.")
            print("", end="\n")
            self.server_private_random = private_random_bytes
            print("Decrypted server private random = ", self.server_private_random)
            print("Server Private random [number of bytes -> 48]: ", len(self.server_private_random))
            print("Client random [number of bytes -> 48]: ", len(self.client_private_random))
        except:
            print("The signature is not authentic.")
            
    def get_server_public_random(self, server_public_random):
        self.server_public_random = server_public_random

    def generate_with_prf(self):
        total_bytes = 68
        
        seed = self.client_public_random + self.server_public_random
        self.block = prf(hashlib.sha256, self.master_secret, b'key expansion', seed, total_bytes)

        self.client_write_mac_key = self.block[0:32]
        self.server_write_mac_key = self.block[32:64]
        self.client_write_key = self.block[64:66]
        self.server_write_key = self.block[66:68]
        
        print("Number of bytes: ", len(self.client_write_key))
    
        print("Block = ", self.block)
        print("client_write_mac_key = ", self.client_write_mac_key)
        print("server_write_mac_key = ", self.server_write_mac_key)
        print("client_write_key = ", self.client_write_key)
        print("server_write_key = ", self.server_write_key)
        
        return self.client_write_mac_key, self.server_write_mac_key, self.client_write_key, self.server_write_key
    
    def get_master_secret(self, master_secret):
        self.master_secret = master_secret
    
    def send_message_from_client(self, message):
        padded_message = add_extra_dollar(message)
        key_binary = ''.join(format(byte, '08b') for byte in self.client_write_key)
        key_binary = key_binary.encode()
        encrypted = encrypt_mini_aes(padded_message, key_binary)
        
        key_bytes = self.client_write_mac_key
        authenticated = hmac(hashlib.sha256, key_bytes, padded_message.encode())
        
        print("[From client - Mini AES] Encrypted = ", encrypted)
        print("[From client - Mini AES] Authenticated = ", authenticated)
        
        return encrypted, authenticated

    def receive_and_verify_message(self, message, authentication_code):
        key_binary = ''.join(format(byte, '08b') for byte in self.server_write_key)
        key_binary = key_binary.encode()
        decrypted_padded = decrypt_mini_aes(message, key_binary)
        
        print("[From client - Mini AES] Decrypted = ", decrypted_padded)

        decrypted = remove_extra_dollar(binary_to_string(decrypted_padded))
        padded_message = add_extra_dollar(decrypted)
        
        key_bytes = self.server_write_mac_key
        authenticated = hmac(hashlib.sha256, key_bytes, padded_message.encode())
        
        print("[From client - Mini AES] Authentication to check = ", authenticated)
        
        print("", end="\n")
        if authentication_code == authenticated:
            print("Verified sucessfully!")
        else:
            print("Failed to verify!")
        print("", end="\n")
        
        return decrypted