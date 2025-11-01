"""
Comprehensive Demo of Custom Cipher Implementation

This script demonstrates:
1. Custom cipher encryption/decryption
2. Individual cipher components (Vigenere, Playfair, Caesar)
3. Cipher breaking methods
4. Time complexity verification
"""

from custom_cipher import CustomCipher
from vigenere_cipher import VigenereCipher
from playfair_cipher import PlayfairCipher
from caesar_cipher import CaesarCipher
from cipher_breaker import CustomCipherBreaker, KnownPlaintextAttack


def print_header(title):
    """Print formatted header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def demo_custom_cipher():
    """Demonstrate custom cipher encryption and decryption."""
    print_header("CUSTOM CIPHER DEMO (2-Stage: Vigenere + Playfair)")
    
    key = "MYSECRETKEYWITHATLEASTTENCHARS"
    cipher = CustomCipher(key)
    
    print(f"Key: {key}")
    print(f"Key length: {len(key)} characters (minimum required: 10)")
    
    # Test various lengths
    test_cases = [
        "HELLO",
        "HELLOWORLD",
        "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
        "THISISMYLONGTEXTMESSAGE"
    ]
    
    print("\n--- Encryption/Decryption Examples ---\n")
    
    for plaintext in test_cases:
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        
        print(f"Plaintext:  {plaintext}")
        print(f"Encrypted:  {encrypted}")
        print(f"Decrypted:  {decrypted}")
        print(f"Length:     {len(plaintext)} -> {len(encrypted)} chars")
        print()


def demo_vigenere_cipher():
    """Demonstrate Vigenere cipher."""
    print_header("VIGENERE CIPHER DEMO")
    
    key = "SECRETKEY"
    cipher = VigenereCipher(key)
    
    plaintext = "HELLOWORLD"
    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)
    
    print(f"Key:        {key}")
    print(f"Plaintext:  {plaintext}")
    print(f"Encrypted:  {encrypted}")
    print(f"Decrypted:  {decrypted}")
    print(f"Match:      {plaintext == decrypted}")


def demo_playfair_cipher():
    """Demonstrate Playfair cipher."""
    print_header("PLAYFAIR CIPHER DEMO")
    
    key = "PLAYFAIREXAMPLE"
    cipher = PlayfairCipher(key)
    
    plaintext = "HELLOWORLD"
    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)
    
    print(f"Key:        {key}")
    print(f"Plaintext:  {plaintext}")
    print(f"Encrypted:  {encrypted}")
    print(f"Decrypted:  {decrypted}")
    print(f"Note: Playfair adds 'X' padding between duplicate letters")
    
    # Show matrix
    print("\n5x5 Playfair Matrix:")
    for row in cipher.matrix:
        print("  " + " ".join(row))


def demo_caesar_cipher():
    """Demonstrate Caesar cipher."""
    print_header("CAESAR CIPHER DEMO")
    
    shift = 3
    cipher = CaesarCipher(shift)
    
    plaintext = "HELLOWORLD"
    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)
    
    print(f"Shift:      {shift}")
    print(f"Plaintext:  {plaintext}")
    print(f"Encrypted:  {encrypted}")
    print(f"Decrypted:  {decrypted}")
    print(f"Match:      {plaintext == decrypted}")


def demo_custom_cipher_breaking():
    """Demonstrate custom cipher breaking with known plaintext and frequency analysis."""
    print_header("CUSTOM CIPHER BREAKING (Vigenere + Playfair)")
    
    # Test 1: Known Plaintext Attack
    print("\n--- Known Plaintext Attack ---")
    print("Scenario: Intercepted message with known content\n")
    
    key = "SECRETKEYWORD"
    cipher = CustomCipher(key)
    plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    ciphertext = cipher.encrypt(plaintext)
    
    print(f"Original Key:    {key}")
    print(f"Known Plaintext: {plaintext}")
    print(f"Ciphertext:      {ciphertext}")
    print(f"\nAttempting dictionary-based known plaintext attack...")
    
    recovered_key = KnownPlaintextAttack.break_custom_cipher(plaintext, ciphertext, 10, 15)
    
    if recovered_key:
        print(f"\n✓ Recovered Key: {recovered_key}")
        print(f"✓ Success: {recovered_key == key}")
        
        # Verify
        verify_cipher = CustomCipher(recovered_key)
        if verify_cipher.encrypt(plaintext) == ciphertext:
            print("✓ Verification: Key produces correct ciphertext")
    else:
        print("\n✗ Could not recover key")
    
    # Test 2: Frequency Analysis (if time permits)
    print("\n--- Frequency Analysis Attack ---")
    print("Scenario: Ciphertext-only attack\n")
    
    longer_text = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 3
    longer_ciphertext = cipher.encrypt(longer_text)
    
    print(f"Ciphertext length: {len(longer_ciphertext)} characters")
    print(f"Attempting frequency analysis...")
    
    freq_key, decrypted = CustomCipherBreaker.break_with_frequency(longer_ciphertext, 10, 15)
    
    if freq_key:
        print(f"\n⚠ Potential key found: {freq_key}")
        print(f"  Match with original: {freq_key == key}")
    else:
        print("\n✗ Frequency analysis unsuccessful")
        print("  (Custom cipher's dual encryption is resistant to this attack)")


def demo_known_plaintext_attack():
    """Demonstrate known plaintext attack."""
    print_header("KNOWN PLAINTEXT ATTACK")
    
    key = "ATTACKKEY"
    cipher = VigenereCipher(key)
    
    known_plaintext = "THISISKNOWNPLAINTEXT"
    ciphertext = cipher.encrypt(known_plaintext)
    
    print(f"Original Key: {key}")
    print(f"Known Plaintext: {known_plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"\nAttempting known plaintext attack...")
    
    recovered_key = KnownPlaintextAttack.break_vigenere(known_plaintext, ciphertext)
    
    print(f"Recovered Key: {recovered_key}")
    print(f"Success: {recovered_key == key}")


def demo_complexity_comparison():
    """Demonstrate time complexity comparison."""
    print_header("TIME COMPLEXITY COMPARISON")
    
    import time
    
    key = "SECURITYKEY"
    test_text = "A" * 1000
    
    results = {}
    
    # Caesar
    caesar = CaesarCipher(3)
    start = time.time()
    for _ in range(100):
        caesar.encrypt(test_text)
    results['Caesar'] = time.time() - start
    
    # Vigenere
    vigenere = VigenereCipher(key)
    start = time.time()
    for _ in range(100):
        vigenere.encrypt(test_text)
    results['Vigenere'] = time.time() - start
    
    # Playfair
    playfair = PlayfairCipher(key)
    start = time.time()
    for _ in range(100):
        playfair.encrypt(test_text)
    results['Playfair'] = time.time() - start
    
    # Custom
    custom = CustomCipher(key)
    start = time.time()
    for _ in range(100):
        custom.encrypt(test_text)
    results['Custom'] = time.time() - start
    
    print(f"Test: 100 encryptions of {len(test_text)}-character text\n")
    print(f"{'Cipher':<15} {'Time (seconds)':<15} {'Relative Speed':<15}")
    print("-" * 45)
    
    baseline = results['Caesar']
    for cipher_name, elapsed in results.items():
        relative = elapsed / baseline
        print(f"{cipher_name:<15} {elapsed:<15.4f} {relative:<15.2f}x")
    
    print("\nAll ciphers have O(n) time complexity.")
    print("Differences in speed are due to constant factors:")
    print("- Caesar: Simplest (single shift operation)")
    print("- Vigenere: Moderate (key-based modulo operations)")
    print("- Playfair: Moderate (matrix lookups and digraph processing)")
    print("- Custom: Slowest (two sequential encryption stages)")


def main():
    """Run all demos."""
    print("\n" + "=" * 70)
    print("  CUSTOM CIPHER IMPLEMENTATION - COMPREHENSIVE DEMO")
    print("  Network Information Security Computing Project")
    print("=" * 70)
    
    # Demo individual ciphers
    demo_custom_cipher()
    demo_vigenere_cipher()
    demo_playfair_cipher()
    demo_caesar_cipher()
    
    # Demo cipher breaking
    demo_custom_cipher_breaking()
    demo_known_plaintext_attack()
    
    # Demo complexity
    demo_complexity_comparison()
    
    print_header("DEMO COMPLETE")
    print("\nFor detailed complexity analysis, run:")
    print("  python3 encryption_complexity_analysis.py")
    print("  python3 decryption_complexity_analysis.py")
    print("\nFor documentation, see:")
    print("  CIPHER_DOCUMENTATION.md")
    print()


if __name__ == "__main__":
    main()
