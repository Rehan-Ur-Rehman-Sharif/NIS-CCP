"""
Playfair Cipher Implementation
Provides encryption and decryption using the Playfair cipher algorithm.
"""


class PlayfairCipher:
    """Implements the Playfair cipher for encryption and decryption."""
    
    def __init__(self, key):
        """
        Initialize Playfair cipher with a key.
        
        Args:
            key (str): Encryption key (alphabetical characters only)
        """
        self.key = ''.join(filter(str.isalpha, key.upper()))
        if len(self.key) == 0:
            raise ValueError("Key must contain at least one alphabetical character")
        self.matrix = self._generate_matrix()
        self.position = self._generate_position_dict()
    
    def _generate_matrix(self):
        """
        Generate 5x5 Playfair matrix from key.
        Note: I and J are treated as the same letter.
        
        Returns:
            list: 5x5 matrix as list of lists
        
        Time Complexity: O(k) where k is key length
        """
        # Remove duplicates from key and replace J with I
        key_chars = []
        seen = set()
        for char in self.key.replace('J', 'I'):
            if char not in seen:
                key_chars.append(char)
                seen.add(char)
        
        # Add remaining alphabet letters
        for char in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':  # Note: no J
            if char not in seen:
                key_chars.append(char)
                seen.add(char)
        
        # Create 5x5 matrix
        matrix = []
        for i in range(5):
            matrix.append(key_chars[i*5:(i+1)*5])
        
        return matrix
    
    def _generate_position_dict(self):
        """
        Generate dictionary mapping characters to their matrix positions.
        
        Returns:
            dict: Character -> (row, col) mapping
        """
        position = {}
        for i, row in enumerate(self.matrix):
            for j, char in enumerate(row):
                position[char] = (i, j)
        return position
    
    def _prepare_text(self, text):
        """
        Prepare text for Playfair encryption by:
        1. Converting to uppercase
        2. Removing non-alphabetic characters
        3. Replacing J with I
        4. Splitting into digraphs (pairs)
        5. Adding X between duplicate letters in a pair
        6. Adding X at end if odd length
        
        Args:
            text (str): Text to prepare
        
        Returns:
            list: List of character pairs (digraphs)
        
        Time Complexity: O(n) where n is text length
        """
        text = ''.join(filter(str.isalpha, text.upper())).replace('J', 'I')
        
        if len(text) == 0:
            return []
        
        digraphs = []
        i = 0
        while i < len(text):
            a = text[i]
            
            # If last character, pair with X
            if i + 1 >= len(text):
                digraphs.append(a + 'X')
                break
            
            b = text[i + 1]
            
            # If same letters, insert X
            if a == b:
                digraphs.append(a + 'X')
                i += 1
            else:
                digraphs.append(a + b)
                i += 2
        
        return digraphs
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using Playfair cipher.
        
        Args:
            plaintext (str): Text to encrypt (alphabetical only)
        
        Returns:
            str: Encrypted ciphertext
        
        Time Complexity: O(n) where n is length of plaintext
        Space Complexity: O(n) for result storage
        """
        digraphs = self._prepare_text(plaintext)
        ciphertext = []
        
        for pair in digraphs:
            a, b = pair[0], pair[1]
            row_a, col_a = self.position[a]
            row_b, col_b = self.position[b]
            
            # Same row: shift right
            if row_a == row_b:
                ciphertext.append(self.matrix[row_a][(col_a + 1) % 5])
                ciphertext.append(self.matrix[row_b][(col_b + 1) % 5])
            # Same column: shift down
            elif col_a == col_b:
                ciphertext.append(self.matrix[(row_a + 1) % 5][col_a])
                ciphertext.append(self.matrix[(row_b + 1) % 5][col_b])
            # Rectangle: swap columns
            else:
                ciphertext.append(self.matrix[row_a][col_b])
                ciphertext.append(self.matrix[row_b][col_a])
        
        return ''.join(ciphertext)
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using Playfair cipher.
        
        Args:
            ciphertext (str): Text to decrypt
        
        Returns:
            str: Decrypted plaintext
        
        Time Complexity: O(n) where n is length of ciphertext
        Space Complexity: O(n) for result storage
        """
        ciphertext = ''.join(filter(str.isalpha, ciphertext.upper())).replace('J', 'I')
        
        if len(ciphertext) == 0:
            return ""
        
        # Ensure even length
        if len(ciphertext) % 2 != 0:
            ciphertext += 'X'
        
        plaintext = []
        
        # Process pairs
        for i in range(0, len(ciphertext), 2):
            a, b = ciphertext[i], ciphertext[i + 1]
            row_a, col_a = self.position[a]
            row_b, col_b = self.position[b]
            
            # Same row: shift left
            if row_a == row_b:
                plaintext.append(self.matrix[row_a][(col_a - 1) % 5])
                plaintext.append(self.matrix[row_b][(col_b - 1) % 5])
            # Same column: shift up
            elif col_a == col_b:
                plaintext.append(self.matrix[(row_a - 1) % 5][col_a])
                plaintext.append(self.matrix[(row_b - 1) % 5][col_b])
            # Rectangle: swap columns
            else:
                plaintext.append(self.matrix[row_a][col_b])
                plaintext.append(self.matrix[row_b][col_a])
        
        return ''.join(plaintext)


if __name__ == "__main__":
    # Example usage
    key = input("Enter cipher key (at least one alphabetical character): ").strip()
    key_alpha = ''.join(filter(str.isalpha, key))
    while len(key_alpha) == 0:
        print("Error: Key must contain at least one alphabetical character.")
        key = input("Enter cipher key (at least one alphabetical character): ").strip()
        key_alpha = ''.join(filter(str.isalpha, key))
    cipher = PlayfairCipher(key)
    
    plaintext = input("Enter plaintext to encrypt: ").strip()
    while len(plaintext) == 0:
        print("Error: Plaintext cannot be empty.")
        plaintext = input("Enter plaintext to encrypt: ").strip()
    
    print(f"\nOriginal: {plaintext}")
    
    encrypted = cipher.encrypt(plaintext)
    print(f"Encrypted: {encrypted}")
    
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
