from base64 import b64encode

def fixed_length_xor(text, key):
    """
    Performs a binary XOR of two equal-length strings. 
    
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

    if len(text) != len(key):                                   # Zorg ervoor dat de lengte van de key overeenkomt met die van de tekst

        raise ValueError("Input moet even lang zijn!")         
    
    xor_output = b''                                            # Maak een leeg byteobject

    for bit1, bit2 in zip(text, key):                           # Itereer over de elementen van text en key, gebruik vervolgens zip om deze twee te combineren

        xor_output += bytes([bit1 ^ bit2])                      # Voor elk paar bits word een XOR gedaan, hier komt een byte uit die toegevoegd word aan de XOR output. Uiteindelijk word deze gebruikt om het resultaat om te zetten in een byteobject
    
    return xor_output

# Laat deze asserts onaangetast!
assert type(fixed_length_xor(b'foo', b'bar')) == bytes
assert b64encode(fixed_length_xor(b'foo', b'bar')) == b'BA4d'

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