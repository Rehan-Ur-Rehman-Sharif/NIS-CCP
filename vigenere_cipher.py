"""
Vigenere Cipher Implementation
Provides encryption and decryption using the Vigenere cipher algorithm.
"""


class VigenereCipher:
    """Implements the Vigenere cipher for encryption and decryption."""
    
    def __init__(self, key):
        """
        Initialize Vigenere cipher with a key.
        
        Args:
            key (str): Encryption key (alphabetical characters only)
        """
        self.key = ''.join(filter(str.isalpha, key.upper()))
        if len(self.key) == 0:
            raise ValueError("Key must contain at least one alphabetical character")
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using Vigenere cipher.
        
        Args:
            plaintext (str): Text to encrypt (alphabetical only)
        
        Returns:
            str: Encrypted ciphertext
        
        Time Complexity: O(n) where n is length of plaintext
        Space Complexity: O(n) for result storage
        """
        plaintext = ''.join(filter(str.isalpha, plaintext.upper()))
        if len(plaintext) == 0:
            return ""
        
        ciphertext = []
        key_length = len(self.key)
        
        for i, char in enumerate(plaintext):
            # Get corresponding key character
            key_char = self.key[i % key_length]
            
            # Shift plaintext character by key character value
            plain_val = ord(char) - ord('A')
            key_val = ord(key_char) - ord('A')
            cipher_val = (plain_val + key_val) % 26
            
            ciphertext.append(chr(cipher_val + ord('A')))
        
        return ''.join(ciphertext)
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using Vigenere cipher.
        
        Args:
            ciphertext (str): Text to decrypt
        
        Returns:
            str: Decrypted plaintext
        
        Time Complexity: O(n) where n is length of ciphertext
        Space Complexity: O(n) for result storage
        """
        ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
        if len(ciphertext) == 0:
            return ""
        
        plaintext = []
        key_length = len(self.key)
        
        for i, char in enumerate(ciphertext):
            # Get corresponding key character
            key_char = self.key[i % key_length]
            
            # Reverse shift ciphertext character by key character value
            cipher_val = ord(char) - ord('A')
            key_val = ord(key_char) - ord('A')
            plain_val = (cipher_val - key_val) % 26
            
            plaintext.append(chr(plain_val + ord('A')))
        
        return ''.join(plaintext)


if __name__ == "__main__":
    # Example usage
    key = input("Enter cipher key (at least one alphabetical character): ").strip()
    key_alpha = ''.join(filter(str.isalpha, key))
    while len(key_alpha) == 0:
        print("Error: Key must contain at least one alphabetical character.")
        key = input("Enter cipher key (at least one alphabetical character): ").strip()
        key_alpha = ''.join(filter(str.isalpha, key))
    cipher = VigenereCipher(key)
    
    plaintext = input("Enter plaintext to encrypt: ").strip()
    while len(plaintext) == 0:
        print("Error: Plaintext cannot be empty.")
        plaintext = input("Enter plaintext to encrypt: ").strip()
    
    print(f"\nOriginal: {plaintext}")
    
    encrypted = cipher.encrypt(plaintext)
    print(f"Encrypted: {encrypted}")
    
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
