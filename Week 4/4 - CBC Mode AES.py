from base64 import b64decode

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

    return(plaintext)


# Laat dit blok code onaangetast & onderaan je code!
a_ciphertext = b64decode('e8Fa/QnddxdVd4dsL7pHbnuZvRa4OwkGXKUvLPoc8ew=')
a_key = b'SECRETSAREHIDDEN'
a_IV = b'WE KNOW THE GAME'
assert CBC_decrypt(a_ciphertext, a_key, a_IV)[:18] == \
    b64decode('eW91IGtub3cgdGhlIHJ1bGVz')