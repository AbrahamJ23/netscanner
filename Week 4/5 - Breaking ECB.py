from base64 import b64decode
from Crypto.Cipher import AES
from secrets import token_bytes

# Random key 
sleutel = b"AAAAAAAAAAAAAAAA"

def pkcs7_pad(plaintext, blocksize):
    """Appends the plaintext with n bytes,
    making it an even multiple of blocksize.
    Byte used for appending is byteform of n.

    Parameters
    ----------
    plaintext : bytes
        plaintext to be appended
    blocksize : int
        blocksize to conform to

    Returns
    -------
    plaintext : bytes
        plaintext appended with n bytes
    """

    # Determine how many bytes to append
    n = blocksize - len(plaintext)%blocksize
    # Append n*(byteform of n) to plaintext
    # n is in a list as bytes() expects iterable
    plaintext += (n*bytes([n]))
    return plaintext

def ECB_oracle(plaintext, key):
    """Appends a top-secret identifier to the plaintext
    and encrypts it under AES-ECB using the provided key.

    Parameters
    ----------
    plaintext : bytes
        plaintext to be encrypted
    key : bytes
        16-byte key to be used in decryption

    Returns
    -------
    ciphertext : bytes
        encrypted plaintext
    """
    plaintext += b64decode('U2F5IG5hIG5hIG5hCk9uIGEgZGFyayBkZXNlcnRlZCB3YXksIHNheSBuYSBuYSBuYQpUaGVyZSdzIGEgbGlnaHQgZm9yIHlvdSB0aGF0IHdhaXRzLCBpdCdzIG5hIG5hIG5hClNheSBuYSBuYSBuYSwgc2F5IG5hIG5hIG5hCllvdSdyZSBub3QgYWxvbmUsIHNvIHN0YW5kIHVwLCBuYSBuYSBuYQpCZSBhIGhlcm8sIGJlIHRoZSByYWluYm93LCBhbmQgc2luZyBuYSBuYSBuYQpTYXkgbmEgbmEgbmE=')
    plaintext = pkcs7_pad(plaintext, len(key))
    cipher = cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

# Genereer een willekeurige key
key = token_bytes(16)

#####################################
###  schrijf hieronder jouw code  ###
### verander code hierboven niet! ###
#####################################




# Opdracht 5 A.

def find_block_length():
    """Finds the block length used by the ECB oracle.

    Returns
    -------
    blocksize : integer
        blocksize used by ECB oracle
    """
    starting_length = len(ECB_oracle(b'', key))                   # Startlengte van de cipher tekst als deze leeg is

    padding = b'A'                                                # Padding is bytestring 'A'
    
    while True:                                                   # Voeg meer padding toe en blijf de lengte van de cipherkey controleren

        padded_length = len(ECB_oracle(padding, key))

        if padded_length != starting_length:                      # Als de lengte van de ciphertekst veranderd is, is er sprake van een nieuw blok

            block_size = padded_length - starting_length          # Oorspronkelijke lengte - cipherlengte = blokgrootte

            return block_size
        
        padding += b'A'                                           # Voeg nieuwe padding toe en itereer opnieuw

block_length = find_block_length()
print("Block length:", block_length)

# Opdracht 5 C.

def doelciphertext():

    padding = b'A' * (block_length - 1)                           # Padding is "A" * block_length (16) - 1 = 15. Dit is ééntje minder dan het volledige byteblok

    target_ciphertext = ECB_oracle(padding, key)                  # Gooi deze padding in het orakel om vervolgens de eerste letter van de sleutel in het blok te trekken

    return target_ciphertext

target_ciphertext = doelciphertext()
print("Target ciphertext:", target_ciphertext)

#Opdracht 5 E.

def find_first_byte(target_ciphertext):

    padding = b'A' * (block_length - 1)                                         # Padding is "A" * block_length (16) - 1 = 15. Dit is ééntje minder dan het volledige byteblok

    for byte_value in range(256):                                               # Probeer elke mogelijke bytewaarde als laatste byte van de plaintext

        plaintext = padding + bytes([byte_value])                               # Creeër de plaintekst door de padding samen te voegen met de laatste byte
      
        ciphertext = ECB_oracle(plaintext, key)                                 # Encrypt de plaintext om de ciphertext te krijgen
        
        if ciphertext[:block_length] == target_ciphertext[:block_length]:       # Controleer of het eerste blok van de ciphertekst overeenkomt met het eerste blok van de doelciphertekst
            
            return bytes([byte_value])                                          # Als deze blokken overeen komen is de eerste byte van de geheime text gevonden


first_byte = find_first_byte(target_ciphertext)
print("First byte of the secret text:", first_byte)

#Opdracht 5 F.


def find_secret(block_length, block_size):
    """
    Vindt de geheime tekst door een aanval op de ECB-versleuteling uit te voeren.

    Parameters:
        - block_length: De lengte van een enkel blok in bytes.
        - block_size: Het aantal blokken in de geheime tekst.

    Returns:
        - De geheime tekst die is gevonden.
    """
    counter = 0  # Initialiseer de teller
    secret = []  # Lijst om de gevonden tekens op te slaan
    I = ''  # Variabele voor het laatst gevonden teken

    # Bereken de totale lengte van de geheime tekst in bytes
    block_length = block_length * block_size

    # Voer een lus uit totdat alle blokken van de geheime tekst zijn gevonden
    while counter != block_length:
        padding = b'A' * (block_length - counter - 1)  # Genereer de padding

        if I != "":
            new_ciphertext = padding + ''.join(secret).encode("ascii")  # Voeg de gevonden tekens toe aan het ciphertext
        else:
            new_ciphertext = padding

        final_ciphertext = ECB_oracle(padding, sleutel)  # Versleutel de padding

        # Loop door alle mogelijke tekens om het laatste teken van de geheime tekst te vinden
        for I in range(256):

            I = bytes([I])  # Zet het teken om in bytes
            cipher = ECB_oracle(new_ciphertext + I, sleutel)  # Versleutel de nieuwe ciphertext

            # Controleer of het eerste blok van de cijfertekst overeenkomt met het eerste blok van de doelcijfertekst
            if final_ciphertext[:block_length] == cipher[:block_length]:
                I = I.decode("ascii")  # Converteer het gevonden teken naar een karakter
                print("Character gevonden: ", I)  # Geef het gevonden teken weer
                secret.append(I)  # Voeg het gevonden teken toe aan de lijst met geheime tekens
        counter += 1  # Verhoog de teller

    return "".join(secret)  # Geef de gevonden geheime tekst terug

# Roep de functie aan
block_length = find_block_length()
block_count = len(ECB_oracle(b"", sleutel)) // block_length

# gevonden secret uitprinten
secret = find_secret(block_length, block_count)
print("Secret text:", secret)





