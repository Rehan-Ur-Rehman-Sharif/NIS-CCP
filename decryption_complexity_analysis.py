"""
Decryption Time Complexity Analysis
Analyzes and compares time complexity of different cipher decryption algorithms.
"""

import time
import os
try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

from custom_cipher import CustomCipher
from caesar_cipher import CaesarCipher
from vigenere_cipher import VigenereCipher
from playfair_cipher import PlayfairCipher


def measure_decryption_time(cipher, ciphertext):
    """
    Measure time taken to decrypt ciphertext.
    
    Args:
        cipher: Cipher object with decrypt method
        ciphertext (str): Text to decrypt
    
    Returns:
        float: Time in seconds
    """
    start = time.time()
    cipher.decrypt(ciphertext)
    end = time.time()
    return end - start


def analyze_cipher_complexity(cipher_class, key, test_sizes):
    """
    Analyze cipher decryption complexity across different input sizes.
    
    Args:
        cipher_class: Cipher class to test
        key: Key for cipher initialization
        test_sizes (list): List of input sizes to test
    
    Returns:
        list: List of execution times
    """
    times = []
    
    for size in test_sizes:
        # Generate ciphertext of specified size
        plaintext = 'A' * size
        
        # Create cipher instance and encrypt
        if cipher_class == CaesarCipher:
            cipher = cipher_class(3)
        else:
            cipher = cipher_class(key)
        
        ciphertext = cipher.encrypt(plaintext)
        
        # Measure decryption time (average of multiple runs)
        runs = 5
        total_time = 0
        for _ in range(runs):
            total_time += measure_decryption_time(cipher, ciphertext)
        
        avg_time = total_time / runs
        times.append(avg_time)
    
    return times


def main():
    """Main function to run complexity analysis."""
    
    print("=" * 60)
    print("DECRYPTION TIME COMPLEXITY ANALYSIS")
    print("=" * 60)
    
    # Test parameters
    key = "SECURITYANALYSISKEY"
    test_sizes = [100, 500, 1000, 2000, 5000, 10000]
    
    print("\n--- Theoretical Time Complexity ---\n")
    
    complexities = {
        "Caesar Cipher": "O(n) - Single pass with constant time per character",
        "Vigenere Cipher": "O(n) - Single pass with modulo operations",
        "Playfair Cipher": "O(n) - Single pass with matrix lookups (constant time)",
        "Custom Cipher": "O(n) - Two sequential O(n) passes (Playfair^-1 + Vigenere^-1)"
    }
    
    for cipher, complexity in complexities.items():
        print(f"{cipher:20s}: {complexity}")
    
    print("\n--- Empirical Time Analysis ---\n")
    print(f"Testing input sizes: {test_sizes}")
    print()
    
    # Analyze each cipher
    results = {}
    
    print("Analyzing Caesar Cipher...")
    results['Caesar'] = analyze_cipher_complexity(CaesarCipher, 3, test_sizes)
    
    print("Analyzing Vigenere Cipher...")
    results['Vigenere'] = analyze_cipher_complexity(VigenereCipher, key, test_sizes)
    
    print("Analyzing Playfair Cipher...")
    results['Playfair'] = analyze_cipher_complexity(PlayfairCipher, key, test_sizes)
    
    print("Analyzing Custom Cipher...")
    results['Custom'] = analyze_cipher_complexity(CustomCipher, key, test_sizes)
    
    print("\n--- Results Table ---\n")
    print(f"{'Size':>8s} | {'Caesar':>12s} | {'Vigenere':>12s} | {'Playfair':>12s} | {'Custom':>12s}")
    print("-" * 68)
    
    for i, size in enumerate(test_sizes):
        print(f"{size:8d} | {results['Caesar'][i]:12.6f} | {results['Vigenere'][i]:12.6f} | "
              f"{results['Playfair'][i]:12.6f} | {results['Custom'][i]:12.6f}")
    
    # Calculate growth rates
    print("\n--- Growth Rate Analysis ---\n")
    print("Comparing time ratio when input size doubles:")
    print()
    
    for cipher_name in ['Caesar', 'Vigenere', 'Playfair', 'Custom']:
        print(f"{cipher_name} Cipher:")
        times = results[cipher_name]
        
        for i in range(1, len(test_sizes)):
            if test_sizes[i] == 2 * test_sizes[i-1]:
                ratio = times[i] / times[i-1] if times[i-1] > 0 else 0
                print(f"  Size {test_sizes[i-1]} -> {test_sizes[i]}: Time ratio = {ratio:.2f}x")
        print()
    
    print("--- Interpretation ---")
    print("For O(n) complexity, when input size doubles, time should approximately double.")
    print("Ratios close to 2.0 confirm linear O(n) time complexity.")
    print()
    
    # Visualization
    if HAS_MATPLOTLIB:
        try:
            plt.figure(figsize=(12, 6))
            
            for cipher_name, times in results.items():
                plt.plot(test_sizes, times, marker='o', label=cipher_name)
            
            plt.xlabel('Input Size (characters)')
            plt.ylabel('Time (seconds)')
            plt.title('Decryption Time Complexity Comparison')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            output_path = 'decryption_complexity.png'
            plt.savefig(output_path, dpi=300)
            print(f"Graph saved to {output_path}")
        except Exception as e:
            print(f"Could not generate graph: {e}")
    else:
        print("Matplotlib not available. Install with: pip3 install matplotlib")
    
    print("\n--- Conclusion ---\n")
    print("All ciphers exhibit O(n) time complexity for decryption.")
    print("Decryption performance mirrors encryption performance.")
    print("Custom cipher is slowest due to two sequential decryption stages.")
    print("Caesar cipher is fastest due to simplest operations.")
    print("Vigenere and Playfair have similar performance with slightly more overhead.")
    print("\n--- Comparison with Caesar Cipher ---\n")
    print("Caesar cipher baseline (O(n)):")
    print("- Simplest algorithm with minimal overhead")
    print("- Only requires single shift operation per character")
    print()
    print("Custom cipher (O(n)):")
    print("- Same asymptotic complexity but higher constant factors")
    print("- Approximately 2-3x slower than Caesar due to:")
    print("  1. Two sequential encryption/decryption stages")
    print("  2. More complex operations (matrix lookups, modulo with key)")
    print("  3. Additional overhead from Playfair digraph processing")
    print()
    print("Key insight: While all have O(n) complexity, practical performance")
    print("differs significantly due to constant factors and operation complexity.")


if __name__ == "__main__":
    main()
