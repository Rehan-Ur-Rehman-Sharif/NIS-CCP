# Custom Cipher Implementation

## Overview

This project implements a custom cipher that combines Vigenere and Playfair ciphers for enhanced security through 2-stage encryption. It also includes methods to break the cipher using frequency analysis and known plaintext attacks, along with comprehensive time complexity analysis.

## Files

### Core Cipher Implementations

1. **vigenere_cipher.py** - Vigenere cipher implementation
2. **playfair_cipher.py** - Playfair cipher implementation
3. **custom_cipher.py** - Custom 2-stage cipher combining Vigenere and Playfair
4. **caesar_cipher.py** - Caesar (Shift) cipher for comparison

### Analysis Tools

5. **cipher_breaker.py** - Frequency analysis and known plaintext attack methods
6. **encryption_complexity_analysis.py** - Encryption time complexity analysis
7. **decryption_complexity_analysis.py** - Decryption time complexity analysis

## Custom Cipher Design

### Encryption Process (2 Stages)

```
Plaintext → [Stage 1: Vigenere] → Intermediate → [Stage 2: Playfair] → Ciphertext
```

1. **Stage 1**: Apply Vigenere cipher encryption
2. **Stage 2**: Apply Playfair cipher encryption to Vigenere output

### Decryption Process (Reverse Order)

```
Ciphertext → [Stage 1: Playfair^-1] → Intermediate → [Stage 2: Vigenere^-1] → Plaintext
```

1. **Stage 1**: Apply Playfair cipher decryption
2. **Stage 2**: Apply Vigenere cipher decryption to Playfair output

### Key Requirements

- Minimum 10 alphabetical characters
- Only alphabetical characters are used (non-alpha characters are filtered)
- Key is shared between both cipher stages

### Input Requirements

- Plaintext: Alphabetical characters only
- Handles varying lengths (any positive length)
- Automatic filtering of non-alphabetical characters

## Usage Examples

### Basic Encryption/Decryption

```python
from custom_cipher import CustomCipher

# Initialize with key (min 10 characters)
key = "MYSECRETKEYWITHATLEASTTENCHARS"
cipher = CustomCipher(key)

# Encrypt
plaintext = "HELLOWORLD"
ciphertext = cipher.encrypt(plaintext)
print(f"Encrypted: {ciphertext}")

# Decrypt
decrypted = cipher.decrypt(ciphertext)
print(f"Decrypted: {decrypted}")
```

### Breaking Vigenere Cipher (Frequency Analysis)

```python
from cipher_breaker import VigenereBreaker
from vigenere_cipher import VigenereCipher

# Create cipher and encrypt text
key = "SECRETKEY"
cipher = VigenereCipher(key)
ciphertext = cipher.encrypt("THEQUICKBROWNFOX" * 10)

# Break cipher using frequency analysis
recovered_key, decrypted = VigenereBreaker.break_with_frequency(ciphertext)
print(f"Recovered key: {recovered_key}")
print(f"Decrypted text: {decrypted}")
```

### Known Plaintext Attack

```python
from cipher_breaker import KnownPlaintextAttack

# Given known plaintext-ciphertext pair
plaintext = "HELLOWORLD"
ciphertext = cipher.encrypt(plaintext)

# Recover key
recovered_key = KnownPlaintextAttack.break_vigenere(plaintext, ciphertext)
print(f"Recovered key: {recovered_key}")
```

## Time Complexity Analysis

### Theoretical Complexity

| Cipher | Encryption | Decryption | Explanation |
|--------|-----------|-----------|-------------|
| Caesar | O(n) | O(n) | Single pass with constant time shift |
| Vigenere | O(n) | O(n) | Single pass with modulo operations |
| Playfair | O(n) | O(n) | Single pass with matrix lookups |
| Custom | O(n) | O(n) | Two sequential O(n) passes |

Where n is the length of input text.

### Space Complexity

All ciphers use O(n) space for storing the output text.

### Key Insights

1. **Asymptotic Complexity**: All ciphers have O(n) time complexity
2. **Constant Factors**: Custom cipher is slower due to:
   - Two sequential encryption/decryption stages
   - More complex operations (matrix lookups, key-based modulo)
   - Playfair digraph processing overhead
3. **Practical Performance**: Custom cipher is 2-3x slower than Caesar cipher despite same O(n) complexity

### Running Complexity Analysis

```bash
# Analyze encryption complexity
python3 encryption_complexity_analysis.py

# Analyze decryption complexity
python3 decryption_complexity_analysis.py
```

Both scripts will:
- Test various input sizes (100, 500, 1000, 2000, 5000, 10000 characters)
- Measure actual execution times
- Calculate growth rates
- Generate comparison graphs
- Provide detailed analysis

## Comparison with Caesar Cipher

### Security

- **Caesar**: Very weak, only 26 possible keys
- **Vigenere**: Stronger, key space is 26^k where k is key length
- **Playfair**: Moderate, uses digraph substitution
- **Custom**: Strong, combines both methods for 2-stage encryption

### Complexity

- **Caesar**: O(n) with minimal constant factors
- **Custom**: O(n) with higher constant factors (2-3x slower)

Both have linear time complexity, but Custom cipher trades performance for security.

### Breaking Difficulty

- **Caesar**: Trivial (brute force or frequency analysis)
- **Vigenere**: Moderate (Index of Coincidence + frequency analysis)
- **Playfair**: Difficult (requires larger ciphertext samples)
- **Custom**: Very Difficult (requires breaking through two layers)

## Cipher Breaking Methods

### 1. Frequency Analysis (Vigenere)

Uses Index of Coincidence to:
1. Determine key length
2. Split ciphertext by key position
3. Apply frequency analysis to each position
4. Reconstruct key

**Requirements**: Sufficient ciphertext length (typically 100+ characters)

### 2. Known Plaintext Attack

Given matching plaintext-ciphertext pairs:
1. Calculate key values for each position
2. Identify repeating pattern
3. Extract key

**Requirements**: Known plaintext-ciphertext pair

### 3. Custom Cipher Breaking

Breaking the custom cipher is significantly harder because:
- Must work through two encryption layers
- Playfair adds padding that complicates analysis
- Requires larger samples and more sophisticated techniques

## Implementation Notes

### Vigenere Cipher

- Uses repeating key for polyalphabetic substitution
- Key is repeated to match plaintext length
- Each character shifted by corresponding key character

### Playfair Cipher

- Uses 5x5 matrix generated from key
- Encrypts digraphs (character pairs)
- I and J are treated as same letter
- Adds 'X' padding between duplicate letters and for odd length

### Custom Cipher

- Applies Vigenere first, then Playfair
- Key validation ensures minimum 10 characters
- Handles varying input lengths automatically
- Filters non-alphabetical characters

## Testing

Run individual cipher files to see examples:

```bash
python3 vigenere_cipher.py
python3 playfair_cipher.py
python3 caesar_cipher.py
python3 custom_cipher.py
python3 cipher_breaker.py
```

## Dependencies

- Python 3.x
- matplotlib (optional, for complexity analysis graphs)

Install matplotlib for visualization:
```bash
pip3 install matplotlib
```

## Security Considerations

This implementation is for educational purposes. For production use:

1. Use modern cryptographic libraries (e.g., cryptography, PyCrypto)
2. Never implement custom cryptography without expert review
3. Classical ciphers are not secure against modern cryptanalysis
4. Use authenticated encryption (e.g., AES-GCM) for real applications

## Author

Network Information Security (NIS) Computing Project
