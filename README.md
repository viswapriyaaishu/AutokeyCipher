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

![image](AutokeyBlockDiagram.png)

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

```python
# ================= HASH FUNCTION =================
def hashfxn1(message: str) -> str:
    MOD = (1 << 61) - 1
    BASE = 131

    h = 0
    for ch in message:
        h = (h * BASE + ord(ch)) % MOD

    return format(h, '016X')


# ================= AUTOKEY =================
def generate_autokey(plaintext, key):
    key = key.upper()
    plaintext = plaintext.upper().replace(" ", "")
    return (key + plaintext)[:len(plaintext)]


def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.upper().replace(" ", "")
    key_stream = generate_autokey(plaintext, key)

    cipher = ""
    for p, k in zip(plaintext, key_stream):
        val = (ord(p) - 65 + ord(k) - 65) % 26
        cipher += chr(val + 65)

    return cipher


def vigenere_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()

    plaintext = ""
    key_stream = key

    for i in range(len(ciphertext)):
        k = key_stream[i]
        val = (ord(ciphertext[i]) - 65 - (ord(k) - 65)) % 26
        p = chr(val + 65)

        plaintext += p
        key_stream += p

    return plaintext


# ================= SENDER =================
def encrypt_message(original_msg, key):
    msg1 = hashfxn1(original_msg)
    new_msg = original_msg + msg1

    cipher = vigenere_encrypt(new_msg, key)
    return cipher, len(original_msg)


# ================= RECEIVER =================
def decrypt_message(ciphertext, key, original_length):
    new_msg = vigenere_decrypt(ciphertext, key)

    original_msg = new_msg[:original_length]
    msg1 = new_msg[original_length:]

    msg2 = hashfxn1(original_msg)

    return original_msg, (msg1 == msg2)

```

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
