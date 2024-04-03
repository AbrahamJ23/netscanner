def find_secret(block_length, block_size):
    counter = 0 
    secret = []
    I = ''
    sleutel = b"AAAAAAAAAAAAAAAA"

    block_length = block_length * block_size

    while counter != block_length:
        padding = b'A' * (block_length - counter - 1) 

        if I != "":
            new_ciphertext = padding + ''.join(secret).encode("ascii")
        else:
            new_ciphertext = padding
        
        final_ciphertext = ECB_oracle(padding, sleutel)

        for I in range(256):

            I = bytes([I])
            cipher = ECB_oracle(new_ciphertext + I, sleutel)
            if final_ciphertext[:block_length] == cipher[:block_length]:
                I = I.decode("ascii")
                print("Character gevonden: ", I)
                secret.append(I)
        counter += 1
    return "".join(secret)