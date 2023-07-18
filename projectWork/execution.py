server = Server()
client = Client()

server_rsa_enc_key, server_rsa_sign_key = server.generate_keys_server_side()
client_rsa_enc_key, client_rsa_sign_key = client.generate_keys_client_side()

server_public_random = server.generate_public_random_32_bytes()
client_public_random = client.generate_public_random_32_bytes()

server.generate_private_random_48_bytes()
client.generate_private_random_48_bytes()

encrypted_signature_chunk_server = server.sign_and_send(client_rsa_enc_key.publickey())
encrypted_signature_chunk_client = client.sign_and_send(server_rsa_enc_key.publickey()) # server_rsa_enc_key

print("Client chunk: ", encrypted_signature_chunk_server)
print("Server chunk: ", encrypted_signature_chunk_client)

print("", end="\n")
print("", end="\n")

server.receive_signature_from_client_and_verify(encrypted_signature_chunk_client, client_rsa_sign_key.publickey())
client.receive_signature_from_server_and_verify(encrypted_signature_chunk_server, server_rsa_sign_key.publickey()) # server_rsa_sign_key


print("", end="\n")
print("", end="\n")

server.get_client_public_random(client_public_random)
client.get_server_public_random(server_public_random)

server.combine_private_randoms()
master_secret = server.generate_master_secret()
client.get_master_secret(master_secret)

print("", end="\n")
print("", end="\n")

server.generate_with_prf()
message_from_server = "Hi, Client!"
encrypted_from_server, authenticated_from_server = server.send_message_from_server(message_from_server)

print("", end="\n")

client.generate_with_prf()
message_from_client = "Hi, Server!"
encrypted_from_client, authenticated_from_client = client.send_message_from_client(message_from_client)

print("", end="\n")
print("", end="\n")

server.receive_and_verify_message(encrypted_from_client, authenticated_from_client)
client.receive_and_verify_message(encrypted_from_server, authenticated_from_server)

i = 3
assert(i == 3)