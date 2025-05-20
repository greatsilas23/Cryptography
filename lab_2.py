from Crypto.Cipher import AES
import binascii

def hex_to_bytes(hex_string):
    """Convert a hex string to bytes."""
    return binascii.unhexlify(hex_string)

def bytes_to_hex(byte_data):
    """Convert bytes to a hex string."""
    return binascii.hexlify(byte_data).decode('ascii')

def xor_bytes(a, b):
    """XOR two byte arrays."""
    return bytes(x ^ y for x, y in zip(a, b))

def pkcs5_unpad(data):
    """Remove PKCS5 padding."""
    padding_len = data[-1]
    return data[:-padding_len]

def decrypt_cbc(ciphertext_hex, key_hex):
    """
    Decrypt using AES in CBC mode.
    
    Args:
        ciphertext_hex: hex string of ciphertext (including IV at the beginning)
        key_hex: hex string of the AES key
    
    Returns:
        plaintext as a string
    """
    # Convert hex to bytes
    ciphertext = hex_to_bytes(ciphertext_hex)
    key = hex_to_bytes(key_hex)
    
    # Extract IV (first 16 bytes) and ciphertext
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    
    # Set up AES cipher in ECB mode (we'll implement CBC manually)
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Initialize plaintext array
    plaintext = bytearray()
    
    # Process each block
    prev_block = iv
    for i in range(0, len(ciphertext), 16):
        # Get current ciphertext block
        curr_block = ciphertext[i:i+16]
        
        # Decrypt block
        decrypted_block = cipher.decrypt(curr_block)
        
        # XOR with previous ciphertext block (or IV for first block)
        plaintext_block = xor_bytes(decrypted_block, prev_block)
        plaintext.extend(plaintext_block)
        
        # Current block becomes previous for next iteration
        prev_block = curr_block
    
    # Remove padding
    plaintext = pkcs5_unpad(plaintext)
    
    # Convert to string
    return plaintext.decode('utf-8')

def decrypt_ctr(ciphertext_hex, key_hex):
    """
    Decrypt using AES in CTR mode.
    
    Args:
        ciphertext_hex: hex string of ciphertext (including nonce at the beginning)
        key_hex: hex string of the AES key
    
    Returns:
        plaintext as a string
    """
    # Convert hex to bytes
    ciphertext = hex_to_bytes(ciphertext_hex)
    key = hex_to_bytes(key_hex)
    
    # Extract nonce (first 16 bytes) and ciphertext
    nonce = ciphertext[:16]
    ciphertext = ciphertext[16:]
    
    # Set up AES cipher in ECB mode (we'll implement CTR manually)
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Initialize plaintext array
    plaintext = bytearray()
    
    # Process each block
    for i in range(0, len(ciphertext), 16):
        # Calculate current block number
        block_num = i // 16
        
        # Create counter value
        # This time let's create an initial counter with zeros and just copy nonce
        counter = bytearray(16)  # All zeros
        
        # Copy just the first part of the nonce (assumed to be fixed)
        # Usually in CTR mode, part of the block is nonce, part is counter
        for j in range(8):  # Use first 8 bytes as nonce
            counter[j] = nonce[j]
        
        # Set the counter value in last 8 bytes
        counter[8] = (block_num >> 56) & 0xFF
        counter[9] = (block_num >> 48) & 0xFF
        counter[10] = (block_num >> 40) & 0xFF
        counter[11] = (block_num >> 32) & 0xFF
        counter[12] = (block_num >> 24) & 0xFF
        counter[13] = (block_num >> 16) & 0xFF
        counter[14] = (block_num >> 8) & 0xFF
        counter[15] = block_num & 0xFF
        
        # Encrypt counter to get keystream
        keystream = cipher.encrypt(bytes(counter))
        
        # Get current ciphertext segment
        current_segment = ciphertext[i:i+16]
        
        # XOR keystream with ciphertext segment to get plaintext
        plaintext_segment = xor_bytes(keystream[:len(current_segment)], current_segment)
        plaintext.extend(plaintext_segment)
    
    # Try multiple decoding methods
    try:
        return plaintext.decode('utf-8')
    except UnicodeDecodeError:
        try:
            return plaintext.decode('latin-1')  # Latin-1 can decode any byte value
        except Exception:
            # Last resort: just return a printable representation
            return ''.join(chr(c) if 32 <= c < 127 else '.' for c in plaintext)

# Question 1
cbc_key_1 = "140b41b22a29beb4061bda66b6747e14"
cbc_ciphertext_1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
plaintext_1 = decrypt_cbc(cbc_ciphertext_1, cbc_key_1)
print("Question 1 - CBC plaintext:", plaintext_1)

# Question 2
cbc_key_2 = "140b41b22a29beb4061bda66b6747e14"
cbc_ciphertext_2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
plaintext_2 = decrypt_cbc(cbc_ciphertext_2, cbc_key_2)
print("Question 2 - CBC plaintext:", plaintext_2)

# Question 3
ctr_key_1 = "36f18357be4dbd77f050515c73fcf9f2"
ctr_ciphertext_1 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"

# Implement a simpler CTR decryption directly using library's CTR mode
def decrypt_ctr_simple(ciphertext_hex, key_hex):
    ciphertext = hex_to_bytes(ciphertext_hex)
    key = hex_to_bytes(key_hex)
    
    # Extract nonce (first 16 bytes)
    nonce = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    
    # Create AES-CTR cipher using the extracted nonce
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce[:8], initial_value=int.from_bytes(nonce[8:16], byteorder='big'))
    
    # Decrypt
    plaintext = cipher.decrypt(actual_ciphertext)
    
    # Try to decode
    try:
        return plaintext.decode('utf-8')
    except UnicodeDecodeError:
        return plaintext.decode('latin-1')  # Latin-1 can decode any byte values

try:
    plaintext_3 = decrypt_ctr_simple(ctr_ciphertext_1, ctr_key_1)
    print("Question 3 - CTR plaintext:", plaintext_3)
except Exception as e:
    print(f"Error in Question 3: {e}")

# Question 4
ctr_key_2 = "36f18357be4dbd77f050515c73fcf9f2"
ctr_ciphertext_2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
try:
    plaintext_4 = decrypt_ctr_simple(ctr_ciphertext_2, ctr_key_2)
    print("Question 4 - CTR plaintext:", plaintext_4)
except Exception as e:
    print(f"Error in Question 4: {e}")