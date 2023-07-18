alphabet = 'abcdef'

def convert_letters_to_numbers(list_of_letters):
    return list(
        map(
            lambda x: alphabet.index(x),
            list_of_letters
        )
    )

def convert_numbers_to_letters(list_of_numbers):
    return ''.join(list(
        map(
            lambda x: alphabet[x],
            list_of_numbers
        )
    ))

def shift_encrypt(message, key):
    k = alphabet.index(key)
    return convert_numbers_to_letters(list(
        map(
            lambda x: (x + k) % len(alphabet),
            convert_letters_to_numbers(message)
        )
    ))

def shift_decrypt(cipher, key):
    k = alphabet.index(key)
    return convert_numbers_to_letters(list(
        map(
            lambda x: (x - k) % len(alphabet),
            convert_letters_to_numbers(cipher)
        )
    ))

print(
    shift_decrypt(
        shift_encrypt('deadbeef', 'c'),
        'c'
    )
)
