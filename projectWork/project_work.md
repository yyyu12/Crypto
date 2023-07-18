# General information

Messages shall be sent on Teams chat in hexadecimal string encoding.
True random bytes can be created with secrets.token_bytes().
RSA size shall be 2048 bits, MGF hash function for RSA-OAEP shall be SHA1. HMAC hash function shall be SHA256.
RSA digital signature hash function shall be SHA512. The digital signature shall fit into RSA-OAEP-2048 payload together with the payload, see 6-7-8.

# Steps to perform

1. Form groups of two students and agree on roles, i.e. who is the client and who is the server server.

2. Generate RSA keys on both sides (client_rsa_enc_key, server_rsa_enc_key) for encryption and (client_rsa_sign_key, server_rsa_sign_key) for signature
3. Generate 32 random bytes on both sides (client_public_random, server_public_random)

4. Send client_rsa_enc_key.public, client_rsa_sign_key.public and client_public_random from client to server
5. Send server_rsa_enc_key.public, server_rsa_sign_key.public and server_public_random from server to client

6. Generate 48 private random bytes on both sides (client_private_random, server_private_random)

7. Sign client_private_random with RSA and send it from client to server with RSA-OAEP. Decrypt the received message on server side and verify the signature.
8. Sign server_private_random with RSA and send it from server to client with RSA-OAEP. Decrypt the received message on client side and verify the signature.

9. Combine private randoms into premaster_secret = client_private_random + server_private_random, where +  is concatenation of bytes

10. Generate master secret with PRF(premaster_secret, "master secret", client_public_random + server_public_random). The length of the master secret shall be 48 bytes.

11. Both sites generate the following keys with PRF(master_secret, "key expansion", client_public_random + server_public_random)
    - client_write_mac_key: 32 bytes
    - server_write_mac_key: 32 bytes
    - client_write_key: 2 bytes
    - server_write_key: 2 bytes

12. Send message from client to server with MiniAES(client_write_key) and HMAC(client_write_mac_key). Decrypt the message and verify the authentication code
13. Send message from server to client with MiniAES(server_write_key) and HMAC(server_write_mac_key). Decrypt the message and verify the authentication code
