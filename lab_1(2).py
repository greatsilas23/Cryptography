import string
import collections
from itertools import combinations

# Allowed printable characters
allowed = string.ascii_letters + string.digits + ' .,!?:;\'"()-_'

# Check if the byte is a printable character in the allowed set
def is_readable(b):
    try:
        return chr(b) in allowed
    except:
        return False

# Count readable characters in a byte string when interpreted as text
def readability_score(byte_string):
    score = 0
    for b in byte_string:
        try:
            if chr(b) in allowed:
                # Spaces and common characters get higher scores
                if chr(b) == ' ':
                    score += 2
                elif chr(b) in string.ascii_letters:
                    score += 1
                else:
                    score += 0.5
        except:
            pass
    return score / max(1, len(byte_string))

# XOR two byte strings
def xor_bytes(b1, b2):
    return bytes([x ^ y for x, y in zip(b1, b2)])

# Convert hex to bytes
def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

# Ciphertexts as hexadecimal strings
ciphertexts_hex = [
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83"
]

# Target ciphertext (the one we need to decrypt)
target_hex = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"

# Convert target to bytes
target = hex_to_bytes(target_hex)

# Convert all ciphertexts to bytes
ciphertexts = [hex_to_bytes(ct) for ct in ciphertexts_hex]
# Add target to the list of ciphertexts for analysis
all_ciphertexts = ciphertexts + [target]

# Find the maximum length among all ciphertexts
max_len = max(len(ct) for ct in all_ciphertexts)

# Initialize key with default value None (unknown)
key_guess = [None] * max_len

# Common words and phrases in English, sorted by length (longer first for better key recovery)
common_words = [
    'the ', 'and ', 'that ', 'have ', 'with ', 'this ', 'from ', 'they ', 'will ',
    'would ', 'there ', 'their ', 'what ', 'about ', 'which ', 'when ', 'your ',
    'said ', 'could ', 'people ', 'because ', 'message ', 'security ', 'encryption ',
    'cryptography', ' the ', ' and ', ' to ', ' of ', ' a ', ' in ', ' is ', ' it ',
    ' you ', ' that ', ' he ', ' was ', ' for ', ' on ', ' are ', ' with ', ' as ',
    ' I ', ' his ', ' they ', ' be ', ' at ', ' one ', ' have ', ' this ', ' from ',
    ' or ', ' had ', ' by ', ' hot ', ' but ', ' some ', ' what ', ' there ',
    'The ', 'This ', 'We ', 'I ', 'You ', 'He ', 'She ', 'They ', 'It ', 'One ',
    'Here ', 'There '
]

# Extended common words for deeper analysis
extended_words = [
    'secret', 'cipher', 'crypto', 'encrypted', 'confidential', 'private',
    'classified', 'secure', 'code', 'key', 'password', 'message', 'information',
    'system', 'access', 'control', 'protocol', 'algorithm', 'network', 'data',
    'computer', 'security', 'privacy', 'protection', 'authentication'
]

# Add extended words to common words
common_words += extended_words

# Add common starting phrases
common_phrases = [
    'The secret ', 'We have ', 'Please send ', 'The message ', 'I need ', 
    'You must ', 'Remember to ', 'Do not ', 'We need to ', 'The following ',
    'Encryption key', 'Secret message', 'Confidential information'
]
common_words += common_phrases

# Calculate score for a potential decryption based on character frequency and readability
def score_text(text):
    if not text:
        return 0
    
    # Basic readability score
    read_score = readability_score(text)
    
    # Letter frequency score
    english_freq = {
        'e': 0.1202, 't': 0.0910, 'a': 0.0812, 'o': 0.0768, 'i': 0.0731,
        'n': 0.0695, 's': 0.0628, 'r': 0.0602, 'h': 0.0592, 'd': 0.0432,
        'l': 0.0398, 'u': 0.0288, 'c': 0.0271, 'm': 0.0261, 'f': 0.0230,
        'y': 0.0211, 'w': 0.0209, 'g': 0.0203, 'p': 0.0182, 'b': 0.0149,
        'v': 0.0111, 'k': 0.0069, 'x': 0.0017, 'q': 0.0011, 'j': 0.0010, 'z': 0.0007
    }
    
    # Count letters in text
    try:
        text_lower = text.lower() if isinstance(text, str) else ''.join(chr(b) for b in text if is_readable(b)).lower()
        letters = [c for c in text_lower if c in english_freq]
        if not letters:
            return read_score
            
        letter_count = collections.Counter(letters)
        total = sum(letter_count.values())
        
        # Calculate frequency score
        if total > 0:
            freq_score = sum(letter_count[c] * english_freq.get(c, 0) for c in letter_count) / total
        else:
            freq_score = 0
            
        # Word pattern score - check if common English word patterns exist
        word_pattern_score = 0
        if isinstance(text, str):
            words = text.lower().split()
            for word in words:
                if len(word) > 2:
                    # Common English word endings
                    if word.endswith(('ing', 'ed', 'ly', 'tion', 's')):
                        word_pattern_score += 0.1
                    # Common English vowel patterns
                    vowel_count = sum(1 for c in word if c in 'aeiou')
                    if 0.3 <= vowel_count / len(word) <= 0.6:
                        word_pattern_score += 0.1
            word_pattern_score = min(1.0, word_pattern_score)
        
        return read_score * 0.5 + freq_score * 0.3 + word_pattern_score * 0.2
    except:
        return read_score

# Apply statistical analysis to find spaces in plaintext
def find_spaces(ciphertexts):
    space_candidates = {}
    
    # For each pair of ciphertexts
    for idx1, idx2 in combinations(range(len(ciphertexts)), 2):
        ct1 = ciphertexts[idx1]
        ct2 = ciphertexts[idx2]
        
        # For each position that exists in both ciphertexts
        for pos in range(min(len(ct1), len(ct2))):
            # XOR the bytes at this position
            xor_result = ct1[pos] ^ ct2[pos]
            
            # If the XOR result is in the range of uppercase and lowercase letters (case difference)
            # it's likely that one of the plaintexts has a space at this position
            if 65 <= xor_result <= 90 or 97 <= xor_result <= 122:
                # Record this position as a possible space in one of the plaintexts
                if pos not in space_candidates:
                    space_candidates[pos] = 0
                space_candidates[pos] += 1
    
    # Sort positions by how often they appeared as candidates
    sorted_candidates = sorted(space_candidates.items(), key=lambda x: x[1], reverse=True)
    
    # Return the positions that are most likely to be spaces in some plaintexts
    threshold = max(space_candidates.values()) * 0.7 if space_candidates else 0
    return [pos for pos, count in sorted_candidates if count >= threshold]

# Function to extract key bytes using the space character (0x20)
def extract_key_from_spaces(ciphertexts, space_positions):
    key_bytes = {}
    
    for ct_idx, ct in enumerate(ciphertexts):
        for pos in space_positions:
            if pos < len(ct):
                # Try assuming there's a space at this position
                key_byte = ct[pos] ^ ord(' ')
                
                # Check if this key byte makes sense for other ciphertexts
                valid = True
                for other_idx, other_ct in enumerate(ciphertexts):
                    if other_idx != ct_idx and pos < len(other_ct):
                        decrypted = other_ct[pos] ^ key_byte
                        if not is_readable(decrypted):
                            valid = False
                            break
                
                if valid:
                    if pos not in key_bytes:
                        key_bytes[pos] = []
                    key_bytes[pos].append(key_byte)
    
    # For each position, take the most common key byte
    for pos in key_bytes:
        counter = collections.Counter(key_bytes[pos])
        most_common = counter.most_common(1)
        if most_common:
            key_guess[pos] = most_common[0][0]
    
    return key_guess

# Function to drag a crib (word) through the ciphertexts and try to guess the key
def crib_drag(ciphertexts, word, key_guess):
    word_bytes = word.encode() if isinstance(word, str) else word
    best_key = key_guess.copy()
    best_score = -1
    
    # Try each ciphertext
    for ct_idx, ct in enumerate(ciphertexts):
        # Try each position in the ciphertext
        for pos in range(max(0, len(ct) - len(word_bytes))):
            # Get potential key bytes by XORing the ciphertext with the word
            potential_key = [ct[pos+i] ^ word_bytes[i] for i in range(len(word_bytes))]
            
            # Check if these key bytes produce readable text for all other ciphertexts
            temp_key = key_guess.copy()
            for i, key_byte in enumerate(potential_key):
                if pos+i < len(temp_key):
                    temp_key[pos+i] = key_byte
            
            # Score this potential key by decrypting all ciphertexts
            total_score = 0
            valid = True
            
            for test_idx, test_ct in enumerate(ciphertexts):
                if test_idx == ct_idx:  # Skip the ciphertext we're currently using for the crib
                    continue
                    
                decrypted_segment = []
                for i in range(min(len(test_ct), len(temp_key))):
                    if temp_key[i] is not None and i < len(test_ct):
                        dec = test_ct[i] ^ temp_key[i]
                        if not is_readable(dec):
                            valid = False
                            break
                        decrypted_segment.append(dec)
                
                if not valid:
                    break
                
                segment_score = score_text(bytes(decrypted_segment))
                total_score += segment_score
            
            if valid and total_score > best_score:
                best_score = total_score
                best_key = temp_key.copy()
                # Print progress to show promising finds
                if word == word_bytes:
                    word_str = word
                else:
                    word_str = word_bytes.decode('utf-8', errors='replace')
                print(f"[+] Found good match for '{word_str}' at position {pos} in ciphertext {ct_idx}")
                # Show a sample of the decryption
                sample_ct = ciphertexts[(ct_idx + 1) % len(ciphertexts)]
                sample_dec = decrypt_with_key(sample_ct, temp_key)
                print(f"    Sample decryption: '{sample_dec[:40]}{'...' if len(sample_dec) > 40 else ''}'")
    
    # Return the best key found
    return best_key

# Function to decrypt the ciphertext with the current key guess
def decrypt_with_key(ciphertext, key):
    # Decrypt and handle None values in key_guess
    decrypted = []
    for i, c in enumerate(ciphertext):
        if i < len(key) and key[i] is not None:
            decrypted.append(chr(c ^ key[i]))
        else:
            decrypted.append('_')  # Use underscore for unknown characters
    return ''.join(decrypted)

# Check what percentage of the key we've guessed
def key_completion_percentage(key):
    if not key:
        return 0
    return sum(1 for k in key if k is not None) / len(key) * 100

# Find potential spaces in the plaintexts
print("[*] Finding potential spaces in the plaintexts...")
space_positions = find_spaces(all_ciphertexts)
print(f"[+] Found {len(space_positions)} potential space positions")

# Extract key bytes using space positions
print("[*] Extracting key bytes from potential spaces...")
key_guess = extract_key_from_spaces(all_ciphertexts, space_positions)
completion = key_completion_percentage(key_guess)
print(f"[+] Initial key completion: {completion:.2f}%")

# Try common words, longest first for better key recovery
print("[*] Starting crib dragging with common words...")
common_words.sort(key=len, reverse=True)
for word in common_words:
    key_guess = crib_drag(all_ciphertexts, word, key_guess)
    completion = key_completion_percentage(key_guess)
    print(f"[+] Current key completion: {completion:.2f}%")
    
    # If we've discovered most of the key, try to decrypt the target
    if completion > 80:
        print("[*] High key completion achieved, attempting to decrypt target...")
        break

# Try to fill in remaining key bytes using frequency analysis
print("[*] Filling in gaps with frequency analysis...")
for i in range(len(key_guess)):
    if key_guess[i] is None:
        # Try each possible key byte and see which produces the most readable text
        best_byte = None
        best_score = -1
        
        for b in range(256):
            temp_key = key_guess.copy()
            temp_key[i] = b
            
            # Check how well this byte works across all ciphertexts
            total_score = test_samples = 0
            
            for ct in all_ciphertexts:
                if i < len(ct):
                    # Get a window of text around this position
                    start = max(0, i - 5)
                    end = min(len(ct), i + 6)
                    
                    segment = []
                    for j in range(start, end):
                        if j < len(temp_key) and temp_key[j] is not None and j < len(ct):
                            segment.append(ct[j] ^ temp_key[j])
                    
                    if segment:
                        segment_score = score_text(bytes(segment))
                        total_score += segment_score
                        test_samples += 1
            
            if test_samples > 0:
                avg_score = total_score / test_samples
                if avg_score > best_score:
                    best_score = avg_score
                    best_byte = b
        
        if best_byte is not None:
            key_guess[i] = best_byte

# Final decryption of the target
print("\n[*] Final key recovery complete")
completion = key_completion_percentage(key_guess)
print(f"[+] Final key completion: {completion:.2f}%")

# Decrypt the target with our best key guess
decrypted_message = decrypt_with_key(target, key_guess)
print(f"\nDecrypted target message:\n{decrypted_message}")

# For manual analysis - list key bytes in hex format
print("\nKey in hex (? for unknown bytes):")
key_hex = ''.join([f"{b:02x}" if b is not None else "??" for b in key_guess[:len(target)]])
print(key_hex)

# Also provide decryptions of all ciphertexts for cross-referencing
print("\nAll decrypted messages (for cross-referencing):")
for i, ct in enumerate(all_ciphertexts):
    print(f"\nMessage {i+1}:")
    print(decrypt_with_key(ct, key_guess)) 