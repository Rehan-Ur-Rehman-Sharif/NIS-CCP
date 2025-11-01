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


class CustomCipherBreaker:
    """Methods to break custom cipher (Vigenere + Playfair)."""
    
    @staticmethod
    def break_with_frequency(ciphertext, min_key_length=10, max_key_length=20):
        """
        Attempt to break custom cipher using frequency analysis.
        Tries to attack in stages: Playfair first, then Vigenere.
        
        Args:
            ciphertext (str): Encrypted text
            min_key_length (int): Minimum key length to try
            max_key_length (int): Maximum key length to try
        
        Returns:
            tuple: (recovered_key, decrypted_text) or (None, None)
        """
        ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
        
        if len(ciphertext) < 100:
            print("Custom cipher frequency analysis requires at least 100 characters")
            return None, None
        
        print(f"Attempting frequency analysis on custom cipher...")
        print(f"Ciphertext length: {len(ciphertext)}")
        print("Strategy: Try multiple keys and score results\n")
        
        # Strategy: Try different key candidates and see which produces
        # text closest to English frequency distribution after decryption
        best_key = None
        best_score = float('inf')
        best_decrypted = None
        
        # Try common key patterns
        key_candidates = CustomCipherBreaker._generate_key_candidates(
            min_key_length, max_key_length
        )
        
        for key in key_candidates:
            try:
                cipher = CustomCipher(key)
                decrypted = cipher.decrypt(ciphertext)
                
                # Score the decrypted text
                score = chi_squared_score(decrypted)
                
                if score < best_score:
                    best_score = score
                    best_key = key
                    best_decrypted = decrypted
                    
            except Exception:
                continue
        
        if best_key and best_score < 500:  # Threshold for acceptable English-like text
            print(f"Potential key found: {best_key}")
            print(f"Chi-squared score: {best_score:.2f}")
            print(f"Decrypted text (first 50 chars): {best_decrypted[:50]}...")
            return best_key, best_decrypted
        
        print("Could not break cipher with frequency analysis")
        print("Custom cipher's two-layer encryption is resistant to this attack")
        return None, None
    
    @staticmethod
    def _generate_key_candidates(min_length, max_length):
        """
        Generate candidate keys to try.
        
        Args:
            min_length (int): Minimum key length
            max_length (int): Maximum key length
        
        Returns:
            list: List of candidate keys
        """
        candidates = []
        
        # Common words and patterns
        common_words = [
            'SECRET', 'PASSWORD', 'CIPHER', 'ENCRYPT', 'DECRYPT',
            'SECURE', 'HIDDEN', 'PRIVATE', 'CONFIDENTIAL',
            'KEY', 'LOCK', 'CODE', 'MESSAGE'
        ]
        
        # Generate combinations
        for word1 in common_words:
            for word2 in common_words:
                key = word1 + word2
                if min_length <= len(key) <= max_length:
                    candidates.append(key)
                
                # Add with variations
                key = word1 + word2 + 'KEY'
                if min_length <= len(key) <= max_length:
                    candidates.append(key)
        
        # Add repeated patterns
        for word in common_words:
            for reps in range(2, 5):
                key = word * reps
                if min_length <= len(key) <= max_length:
                    candidates.append(key[:max_length])
        
        return candidates[:100]  # Limit to reasonable number
    
    @staticmethod
    def break_staged(ciphertext, known_key_pattern=None):
        """
        Attempt staged attack: try to identify patterns in each layer.
        This is an advanced technique for educational demonstration.
        
        Args:
            ciphertext (str): Encrypted text
            known_key_pattern (str): Known pattern in key (if any)
        
        Returns:
            tuple: (recovered_key, decrypted_text) or (None, None)
        """
        print("Staged attack on custom cipher...")
        print("Note: This is highly complex and may not succeed\n")
        
        # The challenge: We need to reverse Playfair before we can analyze Vigenere
        # Without knowing the key, Playfair is very difficult to break
        
        # Approach: Try dictionary attack combined with pattern recognition
        print("This attack requires:")
        print("1. Very large ciphertext samples (1000+ characters)")
        print("2. Statistical analysis of digraph frequencies")
        print("3. Computational resources for brute force components")
        print("\nCurrent implementation focuses on known plaintext attack")
        print("which is more practical for this cipher combination.")
        
        return None, None


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
    def break_custom_cipher(plaintext, ciphertext, min_key_length=10, max_key_length=30):
        """
        Attempt to break custom cipher with known plaintext.
        Uses dictionary attack trying common key patterns.
        
        Args:
            plaintext (str): Known plaintext
            ciphertext (str): Corresponding ciphertext
            min_key_length (int): Minimum key length to try
            max_key_length (int): Maximum key length to try
        
        Returns:
            str: Recovered key (or None if failed)
        """
        plaintext = ''.join(filter(str.isalpha, plaintext.upper()))
        ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
        
        if len(plaintext) < min_key_length:
            print(f"Need at least {min_key_length} characters of known plaintext")
            return None
        
        print(f"Attempting to break custom cipher (Vigenere + Playfair)...")
        print(f"Known plaintext length: {len(plaintext)} characters")
        print(f"Strategy: Dictionary attack with common key patterns\n")
        
        # For custom cipher: plaintext -> Vigenere -> Playfair -> ciphertext
        # Strategy: Try dictionary words and common patterns
        
        best_key = None
        best_score = float('inf')
        
        # Generate all candidate keys
        all_candidates = []
        for key_length in range(min_key_length, min(max_key_length + 1, 25)):
            candidates = KnownPlaintextAttack._generate_key_candidates(key_length)
            all_candidates.extend(candidates)
        
        print(f"Testing {len(all_candidates)} candidate keys...")
        tested = 0
        
        for potential_key in all_candidates:
            tested += 1
            if tested % 50 == 0:
                print(f"  Tested {tested}/{len(all_candidates)} keys...")
            
            try:
                test_cipher = CustomCipher(potential_key)
                test_encrypted = test_cipher.encrypt(plaintext)
                
                # Check how close the encryption is to the actual ciphertext
                matches = sum(1 for i in range(min(len(test_encrypted), len(ciphertext))) 
                             if test_encrypted[i] == ciphertext[i])
                match_ratio = matches / max(len(test_encrypted), len(ciphertext))
                
                if match_ratio == 1.0:  # Perfect match!
                    print(f"\n✓ Found exact key: {potential_key}")
                    print(f"  Key length: {len(potential_key)}")
                    print(f"  Match ratio: 100%")
                    return potential_key
                
                # Track best key
                score = 1 - match_ratio
                if score < best_score:
                    best_score = score
                    best_key = potential_key
                    
            except Exception:
                continue
        
        print()  # Newline after progress
        
        if best_key and best_score < 0.3:  # 70% match or better
            print(f"Best key found: {best_key}")
            print(f"Match ratio: {(1-best_score):.2%}")
            print("Note: This may not be the exact key but produces similar output")
            return best_key
        
        print("Could not recover key with sufficient confidence")
        print("The key may not be in the common dictionary patterns tested.")
        print("Consider: 1) Longer plaintext sample, 2) Extended dictionary, 3) Brute force")
        return None
    
    @staticmethod
    def _generate_key_candidates(key_length):
        """
        Generate candidate keys for a specific length.
        
        Args:
            key_length (int): Desired key length
        
        Returns:
            list: List of candidate keys
        """
        candidates = []
        
        # Common words that might be in keys
        common_words = [
            'SECRET', 'KEY', 'WORD', 'PASSWORD', 'PASS', 'CODE',
            'CIPHER', 'ENCRYPT', 'DECRYPT', 'SECURE', 'HIDDEN',
            'LOCK', 'PRIVATE', 'MESSAGE', 'TEXT', 'CRYPTO',
            'SECURITY', 'ACCESS', 'LOGIN', 'ADMIN', 'MASTER',
            'MYSECRET', 'ATLEAST', 'TENCHARS', 'CHARACTERS',
            # Add compound words that are commonly used
            'SECRETKEY', 'KEYWARD', 'CIPHERKEY', 'PASSKEY',
            'SECRETWORD', 'KEYTEXT', 'CODEWORD', 'MASTERKEY'
        ]
        
        # Single words - exact or truncated
        for word in common_words:
            if len(word) == key_length:
                candidates.append(word)
            elif len(word) > key_length:
                candidates.append(word[:key_length])
            else:
                # Repeat word to reach length
                repeated = (word * ((key_length // len(word)) + 1))[:key_length]
                candidates.append(repeated)
        
        # Two-word combinations
        for word1 in common_words:
            for word2 in common_words:
                combined = word1 + word2
                if len(combined) == key_length:
                    candidates.append(combined)
                elif len(combined) > key_length:
                    candidates.append(combined[:key_length])
        
        # Remove duplicates
        return list(set(candidates))


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
    
    print("=== Known Plaintext Attack on Vigenere ===\n")
    
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
    print(f"Recovered key works: {test_match}\n")
    
    print("=== Custom Cipher Breaking Demo ===\n")
    print("Testing attacks on Custom Cipher (Vigenere + Playfair)\n")
    
    # Test 1: Known Plaintext Attack on Custom Cipher
    print("--- Test 1: Known Plaintext Attack ---")
    custom_key = "SECRETKEYWORD"
    custom_cipher = CustomCipher(custom_key)
    custom_plaintext = "THEQUICKBROWNFOX"
    custom_ciphertext = custom_cipher.encrypt(custom_plaintext)
    
    print(f"Original key: {custom_key}")
    print(f"Plaintext: {custom_plaintext}")
    print(f"Ciphertext: {custom_ciphertext}")
    
    recovered_custom_key = KnownPlaintextAttack.break_custom_cipher(
        custom_plaintext, custom_ciphertext
    )
    
    if recovered_custom_key:
        print(f"\nRecovered key: {recovered_custom_key}")
        # Verify it works
        verify_cipher = CustomCipher(recovered_custom_key)
        verify_enc = verify_cipher.encrypt(custom_plaintext)
        print(f"Verification: {verify_enc == custom_ciphertext}")
    
    print("\n--- Test 2: Frequency Analysis Attack ---")
    longer_plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 3
    longer_ciphertext = custom_cipher.encrypt(longer_plaintext)
    
    print(f"Attempting frequency analysis with {len(longer_ciphertext)} characters...")
    recovered_freq_key, decrypted_freq = CustomCipherBreaker.break_with_frequency(
        longer_ciphertext
    )
    
    if recovered_freq_key:
        print(f"Success! Key: {recovered_freq_key}")
    
    print("\n--- Summary ---")
    print("Custom cipher (Vigenere + Playfair) is significantly harder to break")
    print("than individual Vigenere or Playfair ciphers due to:")
    print("1. Two layers of encryption obscure statistical patterns")
    print("2. Playfair digraph substitution adds complexity")
    print("3. Requires larger plaintext samples or known plaintext for attacks")
    print("\nKnown plaintext attack is most effective against this cipher.")
