from secrets import token_bytes

def xor_bytes(lhs, rhs):
    return bytes([l ^ r for l, r in zip(lhs, rhs)])

message = 'attack at dawn'.encode()
key = token_bytes(len(message))
cipher = xor_bytes(message, key)
print(xor_bytes(cipher, key).decode())


message = 'you owe me 100$'.encode()
print(message[11:14])
part_to_alter = [0 for _ in range(len(message))]
part_to_alter[11:14] = message[11:14]
part_to_alter = bytes(part_to_alter)

alter_to = [0 for _ in range(len(message))]
alter_to[11:14] = b'999'
alter_to = bytes(alter_to)

key = token_bytes(len(message))
cipher = xor_bytes(message, key)
cipher = xor_bytes(cipher, part_to_alter)
cipher = xor_bytes(cipher, alter_to)
print(xor_bytes(cipher, key).decode())

class RC4:
    def _swap(self, i, j):
        tmp = self.box[i]
        self.box[i] = self.box[j]
        self.box[j] = tmp

    def __init__(self, key): # ksa
        self.box = [i for i in range(256)]
        j = 0
        for i in range(256):
            j = (j + self.box[i] + key[i % len(key)]) % 256
            self.swap(i, j)
    
    def randbytes(self, n):
        i = 0
        j = 0
        
        bs = []
        for _ in range(n):
            i = (i + 1) % 256
            j = (j + self.box[i]) % 256
            self.swap(i, j)
            bs.append(self.box[(self.box[i] + self.box[j]) % 256])
    
        return bs