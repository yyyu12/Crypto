import unittest

# convert the letters to the list of numbers
def encode(text, alphabet):
    return list(
        map(
            lambda char: alphabet.find(char), text
        )
    )

# print(encode('deadbeef', 'abcdef')) # [3, 4, 0, 3, 1, 4, 4, 5]

# convert the list of numbers to the letters
def decode(encoded_text, alphabet):
    return ''.join(
        map(
            lambda n: alphabet[n], encoded_text
        )
    )

def vigenere_encrypt(text, key, alphabet):
    #convert the letters to the number
    list_of_textNum = encode(text, alphabet)
    list_of_keyNum = encode(key, alphabet)

    # the length of the key and alphabet
    p = len(list_of_keyNum)
    l = len(alphabet)

    # to get the cipher of numbers
    C = []
    for i in range(len(list_of_textNum)):
        C.append((list_of_textNum[i] + list_of_keyNum[i % p]) % l)

    # conver it back to the letters
    return decode(C, alphabet)

# result must be: ecdefbfd
print(vigenere_encrypt('deadbeef', 'bed', 'abcdef'))

def vigenere_decrypt(cipher, key, alphabet):
    # convert the letters to number
    list_of_cipherNum = encode(cipher, alphabet)
    list_of_keyNum = encode(key, alphabet)

    # the length of the key and alphabet
    p = len(list_of_keyNum)
    l = len(alphabet)

    # to get the orignal text of numbers
    M = []
    for i in range(len(cipher)):
        M.append((list_of_cipherNum[i] - list_of_keyNum[i % p]) % l)

    # convert it back to letters
    return decode(M, alphabet)

# result must be: deadbeef
print(vigenere_decrypt(vigenere_encrypt('deadbeef', 'bed', 'abcdef'), 'bed', 'abcdef'))

class Vigenere_test(unittest.TestCase):
    def __init__(self, *args, **kw_args):
        super(Vigenere_test, self).__init__(*args, **kw_args)

        self.alphabet = 'abcdefghijklmnopqrstuvwxyz, '
        self.text = 'egy aprocska kalapocska, benne csacska macska mocska'
        self.key = 'lusta dick'
        self.key2 = 'grabowsky'
        self.cipher = 'p,osaouweavurbakdxqmbcsr ahvpokwitcrnibwlwiba,pweavu'
    
    def test_encrypt(self):
        self.assertEqual(vigenere_encrypt(self.text, self.key, self.alphabet), self.cipher)
        self.assertNotEqual(vigenere_encrypt(self.text, self.key2, self.alphabet), self.cipher)

    def test_decrypt(self):
        self.assertEqual(vigenere_decrypt(self.cipher, self.key, self.alphabet), self.text)
        self.assertNotEqual(vigenere_decrypt(self.cipher, self.key2, self.alphabet), self.text)

    def test_end2end(self):
        self.assertEqual(vigenere_decrypt(vigenere_encrypt(self.text, self.key, self.alphabet), self.key, self.alphabet), self.text)

if __name__ == '__main__':
    unittest.main()
