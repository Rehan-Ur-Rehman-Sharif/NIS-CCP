# NIS-CCP
Computing Project for Network Information Security (NIS)

Team Members:
Rehan Ur Rehman Sharif | CT-84 | Maha Jameel | CT-55 | Fukeyha Rizwan | CT-65 | 

## Custom Cipher Implementation

This project implements a custom cipher combining **Vigenere** and **Playfair** ciphers with 2-stage encryption, along with cipher breaking methods and comprehensive time complexity analysis.

### Features

✅ **2-Stage Custom Cipher**: Vigenere → Playfair encryption
✅ **Minimum 10-character key** requirement
✅ **Handles varying length alphabetical inputs**
✅ **Cipher Breaking Methods**: Frequency analysis and known plaintext attacks
✅ **Time Complexity Analysis**: O(n) encryption and decryption
✅ **Caesar Cipher Comparison**: Baseline for complexity analysis

### Quick Start

Run the comprehensive demo:
```bash
python3 demo.py
```

### Files

- `custom_cipher.py` - Main custom cipher (Vigenere + Playfair)
- `vigenere_cipher.py` - Vigenere cipher component
- `playfair_cipher.py` - Playfair cipher component
- `caesar_cipher.py` - Caesar cipher for comparison
- `cipher_breaker.py` - Frequency analysis & known plaintext attacks
- `encryption_complexity_analysis.py` - Encryption time analysis
- `decryption_complexity_analysis.py` - Decryption time analysis
- `demo.py` - Comprehensive demonstration script
- `CIPHER_DOCUMENTATION.md` - Detailed documentation

### Usage Example

```python
from custom_cipher import CustomCipher

# Initialize with key (min 10 characters)
cipher = CustomCipher("MYSECRETKEYWITHATLEASTTENCHARS")

# Encrypt
ciphertext = cipher.encrypt("HELLOWORLD")
print(f"Encrypted: {ciphertext}")

# Decrypt
plaintext = cipher.decrypt(ciphertext)
print(f"Decrypted: {plaintext}")
```

### Time Complexity

All ciphers implement **O(n)** time complexity for both encryption and decryption:

| Cipher | Encryption | Decryption | Notes |
|--------|-----------|-----------|-------|
| Caesar | O(n) | O(n) | Baseline - simplest |
| Vigenere | O(n) | O(n) | Key-based modulo |
| Playfair | O(n) | O(n) | Matrix lookups |
| Custom | O(n) | O(n) | Two sequential stages |

Run detailed analysis:
```bash
python3 encryption_complexity_analysis.py
python3 decryption_complexity_analysis.py
```

### Documentation

See [CIPHER_DOCUMENTATION.md](CIPHER_DOCUMENTATION.md) for comprehensive documentation including:
- Detailed cipher descriptions
- Breaking methods explained
- Complexity analysis
- Security considerations
