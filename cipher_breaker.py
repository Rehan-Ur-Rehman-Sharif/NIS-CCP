"""
Cipher Breaking Methods
Implements frequency analysis and known plaintext attacks.
"""

import string
from collections import Counter
from vigenere_cipher import VigenereCipher
from playfair_cipher import PlayfairCipher
from custom_cipher import CustomCipher


# English letter frequency (approximate percentages)
ENGLISH_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
    'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
    'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
    'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
    'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
}


def calculate_frequency(text):
    """
    Calculate letter frequency in text.
    
    Args:
        text (str): Text to analyze
    
    Returns:
        dict: Letter -> percentage mapping
    """
    text = ''.join(filter(str.isalpha, text.upper()))
    if len(text) == 0:
        return {}
    
    counter = Counter(text)
    total = len(text)
    
    freq = {}
    for letter in string.ascii_uppercase:
        freq[letter] = (counter.get(letter, 0) / total) * 100
    
    return freq


def chi_squared_score(text):
    """
    Calculate chi-squared statistic comparing text frequency to English.
    Lower score indicates closer match to English.
    
    Args:
        text (str): Text to score
    
    Returns:
        float: Chi-squared score
    """
    observed = calculate_frequency(text)
    
    if not observed:
        return float('inf')
    
    chi2 = 0
    for letter in string.ascii_uppercase:
        expected = ENGLISH_FREQ[letter]
        obs = observed.get(letter, 0)
        if expected > 0:
            chi2 += ((obs - expected) ** 2) / expected
    
    return chi2


class VigenereBreaker:
    """Methods to break Vigenere cipher."""
    
    @staticmethod
    def find_key_length(ciphertext, max_key_length=20):
        """
        Find likely key length using Index of Coincidence method.
        
        Args:
            ciphertext (str): Encrypted text
            max_key_length (int): Maximum key length to test
        
        Returns:
            int: Most likely key length
        """
        ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
        
        def index_of_coincidence(text):
            """Calculate IC for text."""
            if len(text) <= 1:
                return 0
            
            counter = Counter(text)
            n = len(text)
            ic = sum(count * (count - 1) for count in counter.values())
            ic = ic / (n * (n - 1))
            return ic
        
        # English IC is approximately 0.067
        target_ic = 0.067
        best_length = 1
        best_score = float('inf')
        
        for length in range(1, min(max_key_length + 1, len(ciphertext))):
            # Split into groups based on key length
            groups = ['' for _ in range(length)]
            for i, char in enumerate(ciphertext):
                groups[i % length] += char
            
            # Calculate average IC
            avg_ic = sum(index_of_coincidence(group) for group in groups) / length
            
            # Score is distance from English IC
            score = abs(avg_ic - target_ic)
            if score < best_score:
                best_score = score
                best_length = length
        
        return best_length
    
    @staticmethod
    def break_with_frequency(ciphertext, key_length=None):
        """
        Break Vigenere cipher using frequency analysis.
        
        Args:
            ciphertext (str): Encrypted text
            key_length (int): Key length (if None, will be estimated)
        
        Returns:
            tuple: (recovered_key, decrypted_text)
        """
        ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
        
        if len(ciphertext) < 10:
            return None, None
        
        # Estimate key length if not provided
        if key_length is None:
            key_length = VigenereBreaker.find_key_length(ciphertext)
        
        # Split ciphertext into groups by key position
        groups = ['' for _ in range(key_length)]
        for i, char in enumerate(ciphertext):
            groups[i % key_length] += char
        
        # For each group, find most likely shift (Caesar cipher break)
        key = []
        for group in groups:
            best_shift = 0
            best_score = float('inf')
            
            for shift in range(26):
                # Decrypt group with this shift
                decrypted = ''
                for char in group:
                    val = (ord(char) - ord('A') - shift) % 26
                    decrypted += chr(val + ord('A'))
                
                # Score against English frequency
                score = chi_squared_score(decrypted)
                if score < best_score:
                    best_score = score
                    best_shift = shift
            
            key.append(chr(best_shift + ord('A')))
        
        recovered_key = ''.join(key)
        
        # Decrypt with recovered key
        cipher = VigenereCipher(recovered_key)
        decrypted = cipher.decrypt(ciphertext)
        
        return recovered_key, decrypted


class KnownPlaintextAttack:
    """Known plaintext attack methods."""
    
    @staticmethod
    def break_vigenere(plaintext, ciphertext):
        """
        Recover Vigenere key given plaintext-ciphertext pair.
        
        Args:
            plaintext (str): Known plaintext
            ciphertext (str): Corresponding ciphertext
        
        Returns:
            str: Recovered key
        """
        plaintext = ''.join(filter(str.isalpha, plaintext.upper()))
        ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
        
        if len(plaintext) == 0 or len(ciphertext) == 0:
            return None
        
        min_len = min(len(plaintext), len(ciphertext))
        key = []
        
        for i in range(min_len):
            plain_val = ord(plaintext[i]) - ord('A')
            cipher_val = ord(ciphertext[i]) - ord('A')
            key_val = (cipher_val - plain_val) % 26
            key.append(chr(key_val + ord('A')))
        
        # Find repeating pattern in key
        recovered_key = KnownPlaintextAttack._find_key_pattern(key)
        
        return recovered_key
    
    @staticmethod
    def _find_key_pattern(key_chars):
        """
        Find repeating pattern in key characters.
        
        Args:
            key_chars (list): List of key characters
        
        Returns:
            str: Shortest repeating pattern
        """
        if not key_chars:
            return ""
        
        # Try different pattern lengths
        for length in range(1, len(key_chars) // 2 + 1):
            pattern = ''.join(key_chars[:length])
            is_pattern = True
            
            for i in range(length, len(key_chars)):
                if key_chars[i] != pattern[i % length]:
                    is_pattern = False
                    break
            
            if is_pattern:
                return pattern
        
        # No pattern found, return all
        return ''.join(key_chars)
    
    @staticmethod
    def break_custom_cipher(plaintext, ciphertext, min_key_length=10):
        """
        Attempt to break custom cipher with known plaintext.
        
        Args:
            plaintext (str): Known plaintext
            ciphertext (str): Corresponding ciphertext
            min_key_length (int): Minimum key length to try
        
        Returns:
            str: Recovered key (or None if failed)
        """
        plaintext = ''.join(filter(str.isalpha, plaintext.upper()))
        ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
        
        # For custom cipher: plaintext -> Vigenere -> Playfair -> ciphertext
        # We need to work backwards through the Playfair to get Vigenere output
        
        # Note: This is a placeholder for future implementation
        # Breaking the custom cipher is significantly more complex due to:
        # 1. Two layers of encryption (Vigenere + Playfair)
        # 2. Playfair's digraph substitution obscures frequency patterns
        # 3. Requires larger samples and more sophisticated cryptanalysis
        
        # Potential approaches for future implementation:
        # - Dictionary attack with common keys
        # - Brute force for shorter keys (computationally expensive)
        # - Hybrid approach: break Playfair layer first, then Vigenere
        # - Require significantly larger plaintext samples for statistical analysis
        
        print("Breaking custom cipher requires more sophisticated techniques")
        print("Consider: 1) Larger plaintext sample, 2) Dictionary attack, 3) Brute force for key")
        return None


if __name__ == "__main__":
    print("=== Vigenere Cipher Breaking Demo ===\n")
    
    # Test Vigenere frequency analysis
    key = "SECRETKEY"
    vigenere = VigenereCipher(key)
    plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 5
    ciphertext = vigenere.encrypt(plaintext)
    
    print(f"Original key: {key}")
    print(f"Ciphertext length: {len(ciphertext)}")
    
    recovered_key, decrypted = VigenereBreaker.break_with_frequency(ciphertext)
    print(f"Recovered key: {recovered_key}")
    print(f"Original text: {plaintext[:50]}...")
    print(f"Decrypted text: {decrypted[:50]}...")
    print(f"Match: {plaintext == decrypted}\n")
    
    print("=== Known Plaintext Attack Demo ===\n")
    
    # Test known plaintext attack
    known_plain = "HELLOWORLD"
    known_cipher = vigenere.encrypt(known_plain)
    
    recovered_key_kpa = KnownPlaintextAttack.break_vigenere(known_plain, known_cipher)
    print(f"Original key: {key}")
    print(f"Recovered key (KPA): {recovered_key_kpa}")
    
    # Test if recovered key works
    test_cipher = VigenereCipher(recovered_key_kpa)
    test_encrypted = test_cipher.encrypt(plaintext)
    test_match = test_encrypted == vigenere.encrypt(plaintext)
    print(f"Recovered key works: {test_match}")
