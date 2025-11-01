"""
Caesar (Shift) Cipher Implementation
Provides encryption and decryption using the Caesar cipher algorithm.
"""


class CaesarCipher:
    """Implements the Caesar (Shift) cipher for encryption and decryption."""
    
    def __init__(self, shift):
        """
        Initialize Caesar cipher with a shift value.
        
        Args:
            shift (int): Number of positions to shift (0-25)
        """
        self.shift = shift % 26
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using Caesar cipher.
        
        Args:
            plaintext (str): Text to encrypt (alphabetical only)
        
        Returns:
            str: Encrypted ciphertext
        
        Time Complexity: O(n) where n is length of plaintext
        - Single pass through plaintext
        - Constant time operation for each character
        
        Space Complexity: O(n) for result storage
        """
        plaintext = ''.join(filter(str.isalpha, plaintext.upper()))
        
        if len(plaintext) == 0:
            return ""
        
        ciphertext = []
        
        for char in plaintext:
            # Shift character by shift value
            val = ord(char) - ord('A')
            shifted = (val + self.shift) % 26
            ciphertext.append(chr(shifted + ord('A')))
        
        return ''.join(ciphertext)
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using Caesar cipher.
        
        Args:
            ciphertext (str): Text to decrypt
        
        Returns:
            str: Decrypted plaintext
        
        Time Complexity: O(n) where n is length of ciphertext
        - Single pass through ciphertext
        - Constant time operation for each character
        
        Space Complexity: O(n) for result storage
        """
        ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
        
        if len(ciphertext) == 0:
            return ""
        
        plaintext = []
        
        for char in ciphertext:
            # Reverse shift character by shift value
            val = ord(char) - ord('A')
            shifted = (val - self.shift) % 26
            plaintext.append(chr(shifted + ord('A')))
        
        return ''.join(plaintext)
    
    @staticmethod
    def break_with_frequency(ciphertext):
        """
        Break Caesar cipher using frequency analysis.
        
        Args:
            ciphertext (str): Encrypted text
        
        Returns:
            tuple: (shift_value, decrypted_text)
        
        Time Complexity: O(26 * n) = O(n) where n is ciphertext length
        - Try all 26 possible shifts
        - For each shift, decrypt text in O(n)
        """
        from collections import Counter
        
        ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
        
        if len(ciphertext) == 0:
            return None, None
        
        # Find most common letter in ciphertext
        counter = Counter(ciphertext)
        most_common = counter.most_common(1)[0][0]
        
        # Assume most common letter is 'E'
        shift = (ord(most_common) - ord('E')) % 26
        
        cipher = CaesarCipher(shift)
        decrypted = cipher.decrypt(ciphertext)
        
        return shift, decrypted


if __name__ == "__main__":
    # Example usage
    shift_input = input("Enter shift value (0-25): ").strip()
    while not shift_input.isdigit() or not (0 <= int(shift_input) <= 25):
        print("Error: Shift must be a number between 0 and 25.")
        shift_input = input("Enter shift value (0-25): ").strip()
    shift = int(shift_input)
    cipher = CaesarCipher(shift)
    
    plaintext = input("Enter plaintext to encrypt: ").strip()
    while len(plaintext) == 0:
        print("Error: Plaintext cannot be empty.")
        plaintext = input("Enter plaintext to encrypt: ").strip()
    
    print(f"\nOriginal: {plaintext}")
    print(f"Shift: {shift}")
    
    encrypted = cipher.encrypt(plaintext)
    print(f"Encrypted: {encrypted}")
    
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Test breaking
    print("\n--- Breaking Caesar Cipher ---")
    recovered_shift, recovered_text = CaesarCipher.break_with_frequency(encrypted)
    print(f"Recovered shift: {recovered_shift}")
    print(f"Recovered text: {recovered_text}")
