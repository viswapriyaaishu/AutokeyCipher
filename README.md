# 📘 Autokey Cipher with Message Integrity Verification using Custom Hash Function
## 📌 Overview

This project implements a secure message transmission mechanism by combining:

A custom polynomial rolling hash function for integrity verification
The Autokey Cipher (Vigenère-based) for encryption
A verification mechanism to detect tampering
✔ Guarantees
- Confidentiality → via encryption
- Integrity → via hash verification


## ⚙️ System Workflow
## 🔄 Flowchart Diagram

<p align="center">
  <img src="AutoKeyBlockDiagram.png" width="500"/>
</p>

## 🔹 Sender Side

```
msg1 = hashfxn1(M)
new_msg = M || msg1
C = Autokey_Encrypt(new_msg, key)
```

## 🔹 Receiver Side
```
new_msg = Autokey_Decrypt(C, key)

original_msg = first N characters
msg1 = remaining

msg2 = hashfxn1(original_msg)

if msg1 == msg2 → authentic
else → tampered
```

## Hash Function Design
📌 Definition

`h=(h×BASE+ord(char))mod(261−1)`

## 🔍 Base Selection (31 vs 131)
✔ Base = 31
Efficient: (h << 5) - h
Common in practice
Fast computation
✔ Base = 131 (Used)
Better distribution
Lower collision probability
Less predictable patterns
✅ Justification

131 is chosen to prioritize collision resistance and better hash distribution over computational optimization. 

## 🔑 Autokey Cipher
Keystream
`Keystream = KEY || PLAINTEXT`

## Encryption
C[i]=(P[i]+K[i])mod26


## Decryption
P[i]=(C[i]−K[i])mod26 



### CODE:

```python
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
```

## Sample Testcases
```
=== Autokey Cipher (Case & Special Char Preservation) ===

Enter original message: hi from chandigarh
Enter secret key: rolex

--- 📤 SENDER SIDE ---
1️⃣ Applying Hash... 
    Raw Hash: 0D974FBC5F6C88EF
2️⃣ Mapping Hash (0-9 -> A-J): 
    Mapped: ADJHEFBCFFGCIIEF
3️⃣ New Message (Original + Hash): 
    hi from chandigarhADJHEFBCFFGCIIEF
4️⃣ Keystream: 
    rolexhi from chandigarhADJHEFBCFFG

5️⃣ Encryption (Vigenere Table Logic):
    Msg Char   | Key Char   | Cipher
    -----------------------------------
    h    (  7)  +  r    ( 17)  ->  y
    i    (  8)  +  o    ( 14)  ->  w
    ' '  (SYM)  +  l    ( 11)  ->   
    f    (  5)  +  e    (  4)  ->  j
    r    ( 17)  +  x    ( 23)  ->  o
    o    ( 14)  +  h    (  7)  ->  v
    m    ( 12)  +  i    (  8)  ->  u
    ' '  (SYM)  +       (SYM)  ->   
    ...
    E    (  4)  +  F    (  5)  ->  J
    F    (  5)  +  G    (  6)  ->  L

Final Ciphertext: yw jovu hyozwknaekIJJYLFELMJLDKNJL

--- 📥 RECEIVER SIDE ---
1️⃣ Decrypting while preserving special characters...
    Decrypted Full String: hi from chandigarhADJHEFBCFFGCIIEF
2️⃣ Extracted Message: hi from chandigarh
3️⃣ Extracted Hash:    ADJHEFBCFFGCIIEF
4️⃣ Re-computed Hash:  ADJHEFBCFFGCIIEF

✅ VERIFICATION SUCCESSFUL: Integrity Intact (Spaces/Symbols/Case preserved).
```



```
=== Autokey Cipher (Case & Special Char Preservation) ===

Enter original message: This is vanilla icecream
Enter secret key: tubelight

--- 📤 SENDER SIDE ---
1️⃣ Applying Hash... 
    Raw Hash: 1378EA0F970429AD
2️⃣ Mapping Hash (0-9 -> A-J): 
    Mapped: BDHIEAAFJHAECJAD
3️⃣ New Message (Original + Hash): 
    This is vanilla icecreamBDHIEAAFJHAECJAD
4️⃣ Keystream: 
    tubelightThis is vanilla icecreamBDHIEAA

5️⃣ Encryption (Vigenere Table Logic):
    Msg Char   | Key Char   | Cipher
    -----------------------------------
    T    ( 19)  +  t    ( 19)  ->  M
    h    (  7)  +  u    ( 20)  ->  b
    i    (  8)  +  b    (  1)  ->  j
    s    ( 18)  +  e    (  4)  ->  w
    ' '  (SYM)  +  l    ( 11)  ->   
    i    (  8)  +  i    (  8)  ->  q
    s    ( 18)  +  g    (  6)  ->  y
    ' '  (SYM)  +  h    (  7)  ->   
    ...
    A    (  0)  +  A    (  0)  ->  A
    D    (  3)  +  A    (  0)  ->  D

Final Ciphertext: Mbjw qy otuqdei bxepzplmULJMGREFVIDLKNAD

--- 📥 RECEIVER SIDE ---
1️⃣ Decrypting while preserving special characters...
    Decrypted Full String: This is vanilla icecreamBDHIEAAFJHAECJAD
2️⃣ Extracted Message: This is vanilla icecream
3️⃣ Extracted Hash:    BDHIEAAFJHAECJAD
4️⃣ Re-computed Hash:  BDHIEAAFJHAECJAD

✅ VERIFICATION SUCCESSFUL: Integrity Intact (Spaces/Symbols/Case preserved).

```

## To Run it Locally do
`python AutokeyCipher.py`

## 🔐 Security Analysis
✔ Strengths

Ensures message integrity
Avoids repeating-key weakness
Simple and efficient

⚠ Limitations

Not secure for modern cryptography
Vulnerable to classical attacks
Hash is not collision-resistant

🚀 Improvements

Use SHA-256 instead of custom hash
Replace with HMAC
Use AES encryption instead of Autokey

## Prompts Used

```
1. I want to implement the Autokey cipher in Python using the standard Vigenère approach (not XOR). Can you provide clean encryption and decryption functions?

2. I am planning to add an integrity check to the message. Suggest a suitable custom hash function for strings that is simple but has good distribution and low collision probability.

3. I initially considered using a hash of the form (31*h + ord(char)) mod M. Is this a good choice? What are better alternatives in terms of base and modulus?

4. Based on the hash function, I want to design a system where I compute hash(M), append it to the original message, and then encrypt the combined message using Autokey cipher. Help me structure this properly.

5. Now for the receiver side: after decryption, I will know the original message length. I want to split the decrypted text into the original message and the hash, recompute the hash, and verify integrity. Provide the correct logic for this.

6. Give me a complete Python implementation that integrates hashing, Autokey encryption, decryption, and verification in a clean and modular way.

7. Help me format the entire project into a proper README with explanation, design choices (like base selection in hashing), and workflow diagram.

```
