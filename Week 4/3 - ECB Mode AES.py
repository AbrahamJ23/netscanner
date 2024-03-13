from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad


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

    plaintext = AES.new(key, AES.MODE_ECB)

    return plaintext.decrypt(ciphertext) # use 16 bytes key to create new cipherblock 


# Laat deze asserts onaangetast & onderaan je code!
ciphertext = b64decode('86ueC+xlCMwpjrosuZ+pKCPWXgOeNJqL0VI3qB59SSY=')
key = b'SECRETSAREHIDDEN'
assert ECB_decrypt(ciphertext, key)[:28] == \
    b64decode('SGFzdCBkdSBldHdhcyBaZWl0IGZ1ciBtaWNoPw==')