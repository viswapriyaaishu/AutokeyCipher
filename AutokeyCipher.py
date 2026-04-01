def hashfxn1(message: str) -> str:
    """Generates a 64-bit hash and returns it as a 16-character Hex string."""
    MOD = (1 << 61) - 1
    BASE = 131
    h = 0
    for ch in message:
        h = (h * BASE + ord(ch)) % MOD
    return format(h, '016X')

def map_hash_to_alpha(hex_hash: str) -> str:
    """Maps 0-9 to A-J and keeps A-F as is (returns uppercase)."""
    mapping = {
        '0':'A', '1':'B', '2':'C', '3':'D', '4':'E', 
        '5':'F', '6':'G', '7':'H', '8':'I', '9':'J',
        'A':'A', 'B':'B', 'C':'C', 'D':'D', 'E':'E', 'F':'F'
    }
    return "".join(mapping[c] for c in hex_hash)

def vigenere_math(char_msg, char_key, encrypt=True):
    """
    Performs Vigenere math. 
    If char_msg is not a letter, it returns it unchanged (preserving spaces/symbols).
    """
    if not char_msg.isalpha():
        return char_msg
    
    is_lower = char_msg.islower()
    p = ord(char_msg.upper()) - 65
    k = ord(char_key.upper()) - 65
    
    if encrypt:
        res_val = (p + k) % 26
    else:
        res_val = (p - k) % 26
    
    res_char = chr(res_val + 65)
    return res_char.lower() if is_lower else res_char

def main():
    print("=== Autokey Cipher (Case & Special Char Preservation) ===\n")
    
    # 1. Input
    raw_input = input("Enter original message: ")
    secret_key = input("Enter secret key: ")

    # --- SENDER SIDE ---
    print("\n--- 📤 SENDER SIDE ---")
    
    # 2. Apply Hash
    raw_hash = hashfxn1(raw_input)
    print(f"1️⃣ Applying Hash... \n    Raw Hash: {raw_hash}")
    
    # 3. Map Numbers to Letters
    mapped_hash = map_hash_to_alpha(raw_hash)
    print(f"2️⃣ Mapping Hash (0-9 -> A-J): \n    Mapped: {mapped_hash}")
    
    # 4. Create New Message
    new_msg = raw_input + mapped_hash
    print(f"3️⃣ New Message (Original + Hash): \n    {new_msg}")
    
    # 5. Generate Autokey Keystream 
    # Special characters in the message contribute to the keystream for the next letters
    keystream = (secret_key + new_msg)[:len(new_msg)]
    print(f"4️⃣ Keystream: \n    {keystream}")

    # 6. Encryption Process
    print("\n5️⃣ Encryption (Vigenere Table Logic):")
    print(f"    {'Msg Char':<10} | {'Key Char':<10} | {'Cipher'}")
    print("    " + "-"*35)
    
    cipher_text = ""
    for i in range(len(new_msg)):
        c = vigenere_math(new_msg[i], keystream[i], encrypt=True)
        cipher_text += c
        
        # Display logic
        if i < 8 or i >= len(new_msg) - 2:
            m_char = new_msg[i]
            k_char = keystream[i]
            m_val = ord(m_char.upper()) - 65 if m_char.isalpha() else "SYM"
            k_val = ord(k_char.upper()) - 65 if k_char.isalpha() else "SYM"
            
            # Show spaces clearly in log
            m_disp = f"'{m_char}'" if m_char == " " else m_char
            print(f"    {m_disp:<5}({m_val:>3})  +  {k_char:<5}({k_val:>3})  ->  {c}")
        elif i == 8:
            print("    ...")

    print(f"\nFinal Ciphertext: {cipher_text}")

    # --- RECEIVER SIDE ---
    print("\n--- 📥 RECEIVER SIDE ---")
    
    # 1. Decryption (Autokey Recovery)
    print("1️⃣ Decrypting while preserving special characters...")
    decrypted_full = ""
    current_ks = list(secret_key)
    
    for i in range(len(cipher_text)):
        k_char = current_ks[i]
        p_char = vigenere_math(cipher_text[i], k_char, encrypt=False)
        decrypted_full += p_char
        # The key for an autokey cipher is the previous PLAINTEXT character
        current_ks.append(p_char)
        
    print(f"    Decrypted Full String: {decrypted_full}")

    # 2. Split Message and Hash
    extracted_msg = decrypted_full[:-16]
    extracted_hash = decrypted_full[-16:]
    
    print(f"2️⃣ Extracted Message: {extracted_msg}")
    print(f"3️⃣ Extracted Hash:    {extracted_hash}")

    # 3. Verify Integrity
    recomputed_mapped_hash = map_hash_to_alpha(hashfxn1(extracted_msg))
    print(f"4️⃣ Re-computed Hash:  {recomputed_mapped_hash}")
    
    if extracted_hash == recomputed_mapped_hash:
        print("\n✅ VERIFICATION SUCCESSFUL: Integrity Intact (Spaces/Symbols/Case preserved).")
    else:
        print("\n❌ VERIFICATION FAILED: Tampering detected!")

if __name__ == "__main__":
    main()
