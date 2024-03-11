import base64

def string_to_b64(asciiString):
    """
    Converts a given ASCII-string to its b64-encoded equivalent.

    Parameters
    ----------
    asciiString : string
        string to be converted

    Returns
    -------
    bytes
        b64-encoded bytes-object representing the original string
    """

    # Convert de ASCII string naar bytes object
    asciiBytes = asciiString.encode('ascii')

    # Encode de bytes naar b64 bytes object
    b64String = base64.b64encode(asciiBytes)

    return b64String

# Laat deze asserts onaangetast!
assert type(string_to_b64("foo")) == bytes
assert string_to_b64("Hello World") == b'SGVsbG8gV29ybGQ='

def b64_to_string(b64String):
    """
    Converts a given b64-string to its ASCII equivalent.

    Parameters
    ----------
    b64String : bytes
        b64-encoded bytesobject to be converted

    Returns
    -------
    string
        ASCII string
    """

    # Decodeer het b64-gecodeerde bytes-object naar ASCII-string
    asciiBytes = base64.b64decode(b64String)

    # Converteer de bytes naar string
    asciiString = asciiBytes.decode('ascii')

    return asciiString

# Laat deze asserts onaangetast!
assert type(b64_to_string(b'SGVsbG8gV29ybGQ=')) == str
assert b64_to_string(b'SGVsbG8gV29ybGQ=') == "Hello World"


print(string_to_b64("Hello world"))
print(b64_to_string(b'SGVsbG8gd29ybGQ='))