def hashfxn1(message: str) -> str:
    MOD = (1 << 61) - 1
    BASE = 131
    h = 0
    for ch in message:
        h = (h * BASE + ord(ch)) % MOD
    # Return as hex string
    return format(h, '016X')

def autokey_encrypt_raw(plaintext, key):
    key_stream = (key + plaintext)[:len(plaintext)]
    cipher = ""
    for p, k in zip(plaintext, key_stream):
        # Shift using ASCII values
        val = (ord(p) + ord(k)) % 256
        cipher += chr(val)
    return cipher

def autokey_decrypt_raw(ciphertext, key):
    plaintext = ""
    key_stream = key
    
    for i in range(len(ciphertext)):
        k = key_stream[i]
        val = (ord(ciphertext[i]) - ord(k)) % 256
        p = chr(val)
        plaintext += p
        key_stream += p
        
    return plaintext

# ================= SENDER =================
def encrypt_message(original_msg, key):
    # 1. Compute hash
    msg_hash = hashfxn1(original_msg)
    
    # 2. Append hash to original (preserving spaces/case)
    combined_msg = original_msg + "|" + msg_hash # Use a separator
    
    # 3. Encrypt
    cipher = autokey_encrypt_raw(combined_msg, key)
    return cipher

# ================= RECEIVER =================
def decrypt_message(ciphertext, key):
    # 1. Decrypt full string
    full_decrypted = autokey_decrypt_raw(ciphertext, key)
    
    # 2. Split by the separator we added
    if "|" in full_decrypted:
        original_msg, received_hash = full_decrypted.rsplit("|", 1)
        # 3. Verify
        computed_hash = hashfxn1(original_msg)
        is_authentic = (received_hash == computed_hash)
        return original_msg, is_authentic
    
    return full_decrypted, False


def main():
    print("\n=== Autokey Cipher (v2: Space & Case Preserved) ===\n")

    message = input("Enter original message: ") 
    key = input("Enter secret key: ")

    cipher = encrypt_message(message, key)

    print("\n--- SENDER SIDE ---")
    print(f"Original Message : '{message}'")
 
    print(f"Cipher (Hex)     : {cipher.encode().hex().upper()[:40]}...")

    decrypted_msg, status = decrypt_message(cipher, key)

    print("\n--- RECEIVER SIDE ---")
    print(f"Decrypted Message: '{decrypted_msg}'")

    if status:
        print("Verification     : ✅ AUTHENTIC")
    else:
        print("Verification     : ❌ TAMPERED")

if __name__ == "__main__":
    main()