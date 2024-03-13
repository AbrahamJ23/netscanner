from base64 import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad


def repeating_key_xor(text, key):
    """Takes two bytestrings and XORs them, returning a bytestring.
    Extends the key to match the text length.
    
    Parameters
    ----------
    text : bytes
        bytes-object to be xor'd w/ key
    key : bytes
        bytes-object to be xor'd w/ text
        
    Returns
    -------
    bytes
        binary XOR of text & key
    """

    extended_key = key * (len(text) // len(key)) + key[:len(text) % len(key)]                           # Breid de sleutel uit door deze zovaak te herhalen als nodig zodat deze even lang wordt als de text, als deze niet exacct past, slice hem dan.

    xor_output = bytes([text_byte ^ key_byte for text_byte, key_byte in zip(text, extended_key)])       # Voer een XOR uit tussen elke tekstbyte en keybyte


    return xor_output

# Laat deze asserts onaangetast!
assert type(repeating_key_xor(b'all too many words',b'bar')) == bytes
assert b64encode(repeating_key_xor(b'all too many words',b'bar'))\
   == b'Aw0eQhUdDUEfAw8LQhYdEAUB'

def ECB_decrypt(ciphertext, key):
    """Accepts a ciphertext in byte-form,
    as well as 16-byte key, and returns 
    the corresponding plaintext.

    Parameters
    ----------
    ciphertext : bytes
        ciphertext to be decrypted
    key : bytes
        key to be used in decryption

    Returns
    -------
    bytes
        decrypted plaintext
    """

    plaintext = AES.new(key, AES.MODE_ECB)          # Maak een AES object met 'key' in ECB mode

    return plaintext.decrypt(ciphertext)            # Geef de plaintekst weer door de ciphertekst te decoderen


# Laat deze asserts onaangetast & onderaan je code!
ciphertext = b64decode('86ueC+xlCMwpjrosuZ+pKCPWXgOeNJqL0VI3qB59SSY=')
key = b'SECRETSAREHIDDEN'
assert ECB_decrypt(ciphertext, key)[:28] == \
    b64decode('SGFzdCBkdSBldHdhcyBaZWl0IGZ1ciBtaWNoPw==')


def CBC_decrypt(ciphertext, key, IV):
    """Decrypts a given plaintext in CBC mode.
    First splits the ciphertext into keylength-size blocks,
    then decrypts them individually w/ ECB-mode AES
    and XOR's each result with either the IV
    or the previous ciphertext block.
    Appends decrypted blocks together for the output.

    Parameters
    ----------
    ciphertext : bytes
        ciphertext to be decrypted
    key : bytes
        Key to be used in decryption
    IV : bytes
        IV to be used for XOR in first block

    Returns
    -------
    bytes
        Decrypted plaintext
        """

    plaintext = b""                                                         # Initialiseer plaintext als byte object
    previous_block = IV

    for i in range(0, len(ciphertext), 16):                                 # Scan door blokken van 16 bytes (128 bits)
        block = a_ciphertext[i:i+16]                                        # Deel de ciphertext op in blokken van 16 bytes
        decrypted_block = ECB_decrypt(block, key)                           # Maak gebruik van de ECB_decrypt functie met de key
        plaintext += repeating_key_xor(decrypted_block, previous_block)     # Xor het decrypted block met de previous block 
        previous_block = block                                              # Update het previous block voor de volgende iteration

    return plaintext


# Laat dit blok code onaangetast & onderaan je code!
a_ciphertext = b64decode('e8Fa/QnddxdVd4dsL7pHbnuZvRa4OwkGXKUvLPoc8ew=')
a_key = b'SECRETSAREHIDDEN'
a_IV = b'WE KNOW THE GAME'
assert CBC_decrypt(a_ciphertext, a_key, a_IV)[:18] == \
    b64decode('eW91IGtub3cgdGhlIHJ1bGVz')

print(CBC_decrypt(a_ciphertext, a_key, a_IV)[:18])
