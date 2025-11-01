# Quick Start Guide

## Run the Demo

The fastest way to see everything in action:

```bash
python3 demo.py
```

This demonstrates:
- Custom 2-stage cipher encryption/decryption
- Individual cipher components (Vigenere, Playfair, Caesar)
- Cipher breaking methods
- Time complexity comparison

## Basic Usage

### Custom Cipher (Vigenere + Playfair)

```python
from custom_cipher import CustomCipher

# Create cipher with key (minimum 10 characters)
cipher = CustomCipher("MYSECRETKEYWITHATLEASTTENCHARS")

# Encrypt
plaintext = "HELLOWORLD"
ciphertext = cipher.encrypt(plaintext)
print(f"Encrypted: {ciphertext}")  # Output: IYFDXHKLQL

# Decrypt
decrypted = cipher.decrypt(ciphertext)
print(f"Decrypted: {decrypted}")  # Output: HELLOWORLD
```

### Individual Ciphers

```python
from vigenere_cipher import VigenereCipher
from playfair_cipher import PlayfairCipher
from caesar_cipher import CaesarCipher

# Vigenere
vigenere = VigenereCipher("SECRETKEY")
encrypted = vigenere.encrypt("HELLO")

# Playfair
playfair = PlayfairCipher("PLAYFAIRKEY")
encrypted = playfair.encrypt("HELLO")

# Caesar
caesar = CaesarCipher(3)  # Shift by 3
encrypted = caesar.encrypt("HELLO")
```

### Breaking Ciphers

```python
from cipher_breaker import VigenereBreaker, KnownPlaintextAttack

# Frequency Analysis (requires longer ciphertext)
ciphertext = "ENCRYPTED_TEXT_HERE" * 10
recovered_key, decrypted = VigenereBreaker.break_with_frequency(ciphertext)

# Known Plaintext Attack
known_plain = "HELLOWORLD"
known_cipher = "ZINCSPYVJV"
recovered_key = KnownPlaintextAttack.break_vigenere(known_plain, known_cipher)
```

## Time Complexity Analysis

Run detailed analysis of encryption and decryption performance:

```bash
# Analyze encryption complexity
python3 encryption_complexity_analysis.py

# Analyze decryption complexity
python3 decryption_complexity_analysis.py
```

Both scripts will:
- Test various input sizes (100 to 10,000 characters)
- Measure actual execution times
- Calculate growth rates
- Verify O(n) complexity

## Key Requirements

- **Custom Cipher**: Minimum 10 alphabetical characters
- **Input**: Alphabetical characters only (A-Z, case insensitive)
- **Output**: Uppercase alphabetical characters

## Files Overview

| File | Purpose |
|------|---------|
| `custom_cipher.py` | Main custom cipher (Vigenere → Playfair) |
| `vigenere_cipher.py` | Vigenere cipher component |
| `playfair_cipher.py` | Playfair cipher component |
| `caesar_cipher.py` | Caesar cipher for comparison |
| `cipher_breaker.py` | Frequency analysis & attacks |
| `encryption_complexity_analysis.py` | Encryption time analysis |
| `decryption_complexity_analysis.py` | Decryption time analysis |
| `demo.py` | Comprehensive demonstration |

## Expected Results

### Time Complexity
All ciphers: **O(n)** where n is input length

### Relative Performance (100 iterations)
- Caesar: 1.0x (baseline - fastest)
- Vigenere: 1.6x
- Playfair: 2.8x
- Custom: 3.5x (slowest but most secure)

### Security Level
- Caesar: Very Weak (26 possible keys)
- Vigenere: Moderate (26^k keys, breakable with frequency analysis)
- Playfair: Moderate (digraph substitution)
- Custom: Strong (2-stage encryption)

## Common Issues

**"Key must contain at least 10 alphabetical characters"**
- Solution: Use a key with at least 10 letters

**Non-alphabetical characters in input**
- Solution: They are automatically filtered out

**Playfair adds 'X' padding**
- This is normal behavior for Playfair cipher
- It pads between duplicate letters and for odd-length inputs

## For More Details

See [CIPHER_DOCUMENTATION.md](CIPHER_DOCUMENTATION.md) for comprehensive documentation.
