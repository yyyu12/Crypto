class Server:
    def __init__(self):
        self.rsa_length_bits = 2048
        self.hash_func = SHA512
        
        # Enc and sign
        self.server_rsa_enc_key = RSA.generate(2048)
        self.server_rsa_sign_key = RSA.generate(2048)
        
        self.signature = None
        self.server_private_key = None
        
        self.client_rsa_enc_key_public = None
        self.client_rsa_sign_key_public = None
        
        self.num_rand_bytes = 32
        self.private_num_rand_bytes = 48
        self.premaster_secret = None
        self.master_secret = None
        self.client_private_random = None
        self.client_public_random = None
        
        self.client_write_mac_key = None
        self.server_write_mac_key = None
        self.client_write_key = None
        self.server_write_key = None
        
        self.block = None
        self.server_public_random = secrets.token_bytes(self.num_rand_bytes)
        self.server_private_random = secrets.token_bytes(self.private_num_rand_bytes)
        
    #sha512(message).digest()
    def generate_keys_server_side(self):
        server_rsa_enc_key = self.server_rsa_enc_key.e, self.server_rsa_enc_key.n
        server_rsa_sign_key = self.server_rsa_sign_key.e, self.server_rsa_sign_key.n
        
        print("Server RSA Public Enc Key = ", server_rsa_enc_key) # Public key, n
        print("Server RSA Public Sign Key = ", server_rsa_sign_key) # Public key, n
        
        return self.server_rsa_enc_key, self.server_rsa_sign_key
        
    def generate_public_random_32_bytes(self):
        # Generate 32 random bytes on both sides (client_public_random, server_public_random)
        print("Server Public 32 random bytes = ", self.server_public_random)
        
        print("Server Public [number of bytes -> 32]: ", len(self.server_public_random))
        
        return self.server_public_random
    
    def generate_private_random_48_bytes(self):
        print("Server Private 48 random bytes = ", self.server_private_random)
        print("Server Private [number of bytes -> 48]: ", len(self.server_private_random))

        
    def sign_and_send(self, client_rsa_enc_key):
        self.client_rsa_enc_key_public = client_rsa_enc_key

        hash = SHA512.new(self.server_private_random)
        server_signature = pkcs1_15.new(self.server_rsa_sign_key).sign(hash)
        
        print("[From client] Signature: ", server_signature)
        
        signed_server_signature = server_signature + self.server_private_random # Total = 512 + 48 = 760
        encrypted_signature_chunk = encrypt_long_message(signed_server_signature, client_rsa_enc_key)
        
        return encrypted_signature_chunk

    def receive_signature_from_client_and_verify(self, encrypted_signature_chunk, client_rsa_sign_key_public):
        self.client_rsa_sign_key_public = client_rsa_sign_key_public

        decrypted_signature = decrypt_long_message(encrypted_signature_chunk, self.server_rsa_enc_key)
        print("Server side the decrypted signature bytes: ", len(decrypted_signature))
        signature = decrypted_signature[:256]
        
        private_random_bytes = decrypted_signature[256:] # 64*8
        
        print("[From server] Decrypted private random = ", private_random_bytes)
        print("[From server] Decrypted signature = ", signature)
        
        hash = SHA512.new(private_random_bytes)
        verifier = pkcs1_15.new(client_rsa_sign_key_public)

        try:
            verifier.verify(hash, signature)
            
            print("", end="\n")
            print("The signature is authentic.")
            print("", end="\n")

            self.client_private_random = private_random_bytes
            
            print("Decrypted server private random = ", private_random_bytes)
            print("Client private random [number of bytes -> 48]: ", len(self.client_private_random))
            print("Server private random [number of bytes -> 48]: ", len(self.server_private_random))
            
        except:
            print("The signature is not authentic.")
    
        
    def combine_private_randoms(self):
        self.premaster_secret = self.client_private_random + self.server_private_random
        print("Pre master secret = ", self.premaster_secret)
        
        print("Pre master [number of bytes -> 96]: ", len(self.premaster_secret))

    
    def generate_master_secret(self):
        self.concat_public_random = self.client_public_random + self.server_public_random
                
        self.master_secret = prf(hashlib.sha256, self.premaster_secret, b'master secret', self.concat_public_random, self.private_num_rand_bytes)
                
        print("Master secret = ", self.master_secret)
        
        return self.master_secret
        
    def get_client_public_random(self, client_public_random):
        self.client_public_random = client_public_random
        
    def generate_with_prf(self):
        total_bytes = 68
        
        seed = self.client_public_random + self.server_public_random
        self.block = prf(hashlib.sha256, self.master_secret, b'key expansion', seed, total_bytes)

        self.client_write_mac_key = self.block[0:32]
        self.server_write_mac_key = self.block[32:64]
        self.client_write_key = self.block[64:66]
        self.server_write_key = self.block[66:68]
              
        print("Number of bytes: ", len(self.server_write_key))
    
        print("Block = ", self.block)
        print("client_write_mac_key = ", self.client_write_mac_key)
        print("server_write_mac_key = ", self.server_write_mac_key)
        print("client_write_key = ", self.client_write_key)
        print("server_write_key = ", self.server_write_key)
        
        return self.client_write_mac_key, self.server_write_mac_key, self.client_write_key, self.server_write_key

    def send_message_from_server(self, message):
        padded_message = add_extra_dollar(message)
        key_binary = ''.join(format(byte, '08b') for byte in self.server_write_key)
        key_binary = key_binary.encode()
        encrypted = encrypt_mini_aes(padded_message, key_binary)
        
        key_bytes = self.server_write_mac_key
        authenticated = hmac(hashlib.sha256, key_bytes, padded_message.encode())
        
        print("[From server - Mini AES] Encrypted = ", encrypted)
        print("[From server - Mini AES] Authenticated = ", authenticated)
        
        return encrypted, authenticated

    def receive_and_verify_message(self, message, authentication_code):
        key_binary = ''.join(format(byte, '08b') for byte in self.client_write_key)
        key_binary = key_binary.encode()
        decrypted_padded = decrypt_mini_aes(message, key_binary)
        
        print("[From server - Mini AES] Decrypted = ", decrypted_padded)

        decrypted = remove_extra_dollar(binary_to_string(decrypted_padded))
        padded_message = add_extra_dollar(decrypted)
        
        key_bytes = self.client_write_mac_key
        authenticated = hmac(hashlib.sha256, key_bytes, padded_message.encode())
        
        print("[From server - Mini AES] Authentication to check = ", authenticated)
        
        print("", end="\n")
        if authentication_code == authenticated:
            print("Verified sucessfully!")
        else:
            print("Failed to verify!")
        print("", end="\n")
        
        return decrypted
