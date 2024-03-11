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

    if len(text) != len(key):
        raise ValueError("Input moet even lang zijn!")
    
    xor_output = ''
    for bit1, bit2 in zip(text, key):
        xor_output += str(int(bit1)) ^ str(int(bit2))
    
    return xor_output

# Laat deze asserts onaangetast!
assert type(fixed_length_xor(b'foo',b'bar')) == bytes
assert b64encode(fixed_length_xor(b'foo',b'bar')) == b'BA4d'

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

    extended_key = key * (len(text) // len(key)) + key[:len(text) % len(key)]

    xor_output = bytes([text_byte ^ key_byte for text_byte, key_byte in zip(text, extended_key)])


    return xor_output

# Laat deze asserts onaangetast!
assert type(repeating_key_xor(b'all too many words',b'bar')) == bytes
assert b64encode(repeating_key_xor(b'all too many words',b'bar'))\
   == b'Aw0eQhUdDUEfAw8LQhYdEAUB'
