alphabet_dict = dict()

count = 0
with open('moby10b.txt', 'rt') as f:
    while True:
        ch = f.read(1).lower()
        if not ch:
            break

        count += 1
        if ch not in alphabet_dict:
            alphabet_dict.update({ch: 1})
        else:
            alphabet_dict[ch] += 1

alphabet = list(alphabet_dict.keys())
frequencies = list(map(lambda x: x / count, alphabet_dict.values()))

def encode(text, alphabet):
    return list(
        map(
            lambda char: alphabet.index(char),
            text
        )
    )

def decode(encoded_text, alphabet):
    return ''.join(
        map(
            lambda n: alphabet[n],
            encoded_text
        )
    )

def vigenere_encrypt(text, key, alphabet):
    encoded_text = encode(text, alphabet)
    encoded_key = encode(key, alphabet)
    
    key_length = len(key)
    text_length = len(text)
    alphabet_size = len(alphabet)
    
    encoded_cipher = [0 for _ in range(text_length)]
    for i in range(text_length):
        encoded_cipher[i] = (encoded_text[i] + encoded_key[i % key_length]) % alphabet_size

    return decode(encoded_cipher, alphabet)

vigenere_text = '''Now having a night, a day, and still another night following before
me in New Bedford, ere I could embark for my destined port, it
became a matter of concernment where I was to eat and sleep
meanwhile.  It was a very dubious-looking, nay, a very dark and
dismal night, bitingly cold and cheerless.  I knew no one in the
place.  With anxious grapnels I had sounded my pocket, and only
brought up a few pieces of silver,--So, wherever you go, Ishmael,
said I to myself, as I stood in the middle of a dreary street
shouldering my bag, and comparing the gloom towards the north with
the darkness towards the south--wherever in your wisdom you may
conclude to lodge for the night, my dear Ishmael, be sure to inquire
the price, and don't be too particular.'''.lower()

vigenere_key = 'bikini'
vigenere_cipher = vigenere_encrypt(vigenere_text, vigenere_key, alphabet)

s = 'aBCDefabchijaBCD'.lower()
# find_distance_of_all_substrings(s, 3)
# (0, 6) -> 6
# (0, 12) -> 12
# (6, 12) -> 6
# (1, 13) -> 12
# return [6, 12, 6, 12]

# 'bababababa' 'baba'
# (0, 4), (0, 6)

from math import gcd
from functools import reduce

def find_distance_of_all_substrings(s, length):
    distances = []
    for i in range(len(s) - length):
        current_distances = []
        substr = s[i:i+length]
        k = i+length
        j = s.find(substr, k)
        while j != -1:
            current_distances.append(j-i)
            k = j + 1
            j = s.find(substr, k)

            distances += current_distances

    return distances

distances = []
for length in [3, 4, 8]:
    distances += find_distance_of_all_substrings(vigenere_cipher, length)

min_key_length = 2
max_key_length = 10

key_length_candidates = []
for key_length_candidate in range(min_key_length, max_key_length + 1):
    count = 0
    for distance in distances:
        if distance % key_length_candidate == 0:
            count += 1
    
    key_length_candidates.append((key_length_candidate, count))

print(key_length_candidates)

strong_candicates = [2, 3, 4, 6]

# 'abcdefgh', length = 3
#  01234567
# 'adg', 'beh', 'cf'
def break_text(text, length):
    pass