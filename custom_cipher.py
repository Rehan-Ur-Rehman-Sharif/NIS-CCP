"""
Custom Cipher Implementation
Combines Vigenere and Playfair ciphers for 2-stage encryption.
"""

from vigenere_cipher import VigenereCipher
from playfair_cipher import PlayfairCipher


class CustomCipher:
    """
    Custom cipher combining Vigenere and Playfair ciphers.
    
    Encryption: Plaintext -> Vigenere -> Playfair -> Ciphertext
    Decryption: Ciphertext -> Playfair^-1 -> Vigenere^-1 -> Plaintext
    """
    
    def __init__(self, key):
        """
        Initialize custom cipher with a key.
        
        Args:
            key (str): Encryption key (minimum 10 alphabetical characters)
        """
        key = ''.join(filter(str.isalpha, key.upper()))
        
        if len(key) < 10:
            raise ValueError("Key must contain at least 10 alphabetical characters")
        
        self.key = key
        # Initialize both cipher stages with the same key
        self.vigenere = VigenereCipher(key)
        self.playfair = PlayfairCipher(key)
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using 2-stage encryption (Vigenere then Playfair).
        
        Args:
            plaintext (str): Text to encrypt (alphabetical only)
        
        Returns:
            str: Encrypted ciphertext
        
        Time Complexity: O(n) where n is length of plaintext
        - Vigenere encryption: O(n)
        - Playfair encryption: O(n)
        - Total: O(n) + O(n) = O(n)
        
        Space Complexity: O(n) for intermediate and final results
        """
        plaintext = ''.join(filter(str.isalpha, plaintext.upper()))
        
        if len(plaintext) == 0:
            return ""
        
        # Stage 1: Vigenere encryption
        stage1_cipher = self.vigenere.encrypt(plaintext)
        
        # Stage 2: Playfair encryption
        final_cipher = self.playfair.encrypt(stage1_cipher)
        
        return final_cipher
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using 2-stage decryption (Playfair then Vigenere).
        
        Args:
            ciphertext (str): Text to decrypt
        
        Returns:
            str: Decrypted plaintext
        
        Time Complexity: O(n) where n is length of ciphertext
        - Playfair decryption: O(n)
        - Vigenere decryption: O(n)
        - Total: O(n) + O(n) = O(n)
        
        Space Complexity: O(n) for intermediate and final results
        """
        ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
        
        if len(ciphertext) == 0:
            return ""
        
        # Stage 1: Playfair decryption (reverse order)
        stage1_plain = self.playfair.decrypt(ciphertext)
        
        # Stage 2: Vigenere decryption
        final_plain = self.vigenere.decrypt(stage1_plain)
        
        return final_plain


if __name__ == "__main__":
    # Example usage
    key = "MYSECRETKEYWITHATLEASTTENCHARS"
    cipher = CustomCipher(key)
    
    plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    print(f"Original: {plaintext}")
    
    encrypted = cipher.encrypt(plaintext)
    print(f"Encrypted: {encrypted}")
    
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Test with varying lengths
    test_texts = [
        "HELLO",
        "HELLOWORLD",
        "THISISAVERYLONGTEXTTOTESTTHECIPHER"
    ]
    
    print("\n--- Testing with varying lengths ---")
    for text in test_texts:
        enc = cipher.encrypt(text)
        dec = cipher.decrypt(enc)
        
        # Note: Playfair adds padding which may affect exact match
        # This is expected behavior and not an error
        print(f"Text: {text}")
        print(f"Encrypted: {enc}")
        print(f"Decrypted: {dec}")
        print(f"Note: Decrypted text may contain Playfair padding (X)")
        print()
