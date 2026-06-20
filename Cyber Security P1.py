#!/usr/bin/env python3
"""
Password Strength Checker - DecodeLabs Project 1
Single-file implementation for Cybersecurity Industrial Training Kit.
"""

import math
import re
import hmac
from typing import Dict, List, Optional


class PasswordStrengthChecker:
    """
    Evaluates password strength based on length, character variety,
    entropy, common patterns, and blacklisting.
    """

    # Character set sizes (approximate)
    _CHAR_SETS = {
        'lower': 26,
        'upper': 26,
        'digits': 10,
        'symbols': 32   # common printable special chars
    }

    # Built‑in list of common weak passwords (top 100)
    _COMMON_PASSWORDS = {
        "password", "123456", "123456789", "qwerty", "abc123",
        "password1", "12345", "12345678", "111111", "1234567",
        "sunshine", "qwertyuiop", "iloveyou", "princess", "admin",
        "welcome", "666666", "abc123", "football", "monkey",
        "charlie", "aa123456", "donald", "mustang", "letmein",
        "trustno1", "master", "hello", "fuckyou", "shadow",
        "passw0rd", "baseball", "dragon", "mickey", "blink182",
        "computer", "superman", "qazwsx", "pokemon", "mike",
        "internet", "maggie", "liverpool", "123123", "sunflower",
        "william", "jesus", "corvette", "soccer", "harley",
        "summer", "batman", "cheese", "arsenal", "pepper",
        "jordan", "winner", "megadeth", "justin", "hammer",
        "chicken", "barbie", "crystal", "nathan", "dallas",
        "darkness", "andrea", "tigger", "freedom", "brandon",
        "whatever", "madison", "winter", "spiderman", "diamond",
        "friendly", "butterfly", "redskins", "scorpion", "joseph",
        "thomas", "killer", "matthew", "cameron", "slipknot",
        "daniel", "monster", "fishing", "cookie", "morgan",
        "rocket", "glitter", "titanic", "samsung", "emily",
        "mickey1", "george", "guitar", "starwars", "mercedes"
    }

    # Common keyboard sequences to flag
    _KEYBOARD_SEQS = {
        "qwerty", "qwertyuiop", "asdfgh", "zxcvbn",
        "123456", "123456789", "987654321", "qwertyuiop[]",
        "asdfghjkl", "zxcvbnm", "1q2w3e4r", "qwerty123"
    }

    def __init__(self, min_length: int = 8, recommended_length: int = 12):
        self.min_length = min_length
        self.recommended_length = recommended_length

    def check(self, password: str) -> Dict:
        """
        Analyse password strength and return a detailed report.

        Returns:
            dict with keys:
                score (int 0-4)
                strength (str: Very Weak, Weak, Moderate, Strong, Very Strong)
                entropy (float bits)
                length (int)
                feedback (list of strings)
        """
        if not password:
            return self._result(0, "Very Weak", 0.0, 0,
                                ["Password cannot be empty."])

        length = len(password)
        char_sets = self._get_character_sets(password)
        entropy = self._calculate_entropy(length, char_sets)
        score = 0
        feedback = []

        # 1. Length checks
        if length < self.min_length:
            feedback.append(f"Length must be at least {self.min_length} characters.")
            score += 0
        elif length < self.recommended_length:
            feedback.append(f"Length is acceptable but {self.recommended_length}+ is recommended.")
            score += 1
        else:
            score += 2   # bonus for good length

        # 2. Character variety
        variety = len(char_sets)
        if variety < 3:
            feedback.append("Use at least three character types: uppercase, lowercase, digits, and symbols.")
        if variety == 4:
            score += 2
        elif variety == 3:
            score += 1
        elif variety < 2:
            score += 0

        # 3. Entropy (bits)
        if entropy < 30:
            feedback.append("Entropy is too low; increase length and variety.")
        elif entropy < 50:
            feedback.append("Entropy is moderate; consider adding more characters.")
        elif entropy < 70:
            feedback.append("Entropy is good.")
        else:
            feedback.append("Excellent entropy.")

        # 4. Common password blacklist
        if password.lower() in self._COMMON_PASSWORDS:
            feedback.append("This password is commonly used and easily guessable.")
            score = max(0, score - 2)

        # 5. Patterns
        if self._has_repeated_pattern(password):
            feedback.append("Contains repeated characters or sequences (e.g., 'aaa', '123').")
            score = max(0, score - 1)
        if self._is_keyboard_sequence(password.lower()):
            feedback.append("Contains an obvious keyboard sequence (e.g., 'qwerty').")
            score = max(0, score - 1)

        # 6. Normalize score to 0-4
        score = min(4, max(0, score))

        # Determine strength label
        if score == 0:
            strength = "Very Weak"
        elif score == 1:
            strength = "Weak"
        elif score == 2:
            strength = "Moderate"
        elif score == 3:
            strength = "Strong"
        else:
            strength = "Very Strong"

        return self._result(score, strength, entropy, length, feedback)

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _get_character_sets(self, pwd: str) -> List[str]:
        """Return list of character set names present in the password."""
        sets = []
        if re.search(r'[a-z]', pwd):
            sets.append('lower')
        if re.search(r'[A-Z]', pwd):
            sets.append('upper')
        if re.search(r'\d', pwd):
            sets.append('digits')
        if re.search(r'[^a-zA-Z0-9]', pwd):
            sets.append('symbols')
        return sets

    def _calculate_entropy(self, length: int, sets: List[str]) -> float:
        """Calculate entropy in bits: log2(number of possible combinations)."""
        if not sets:
            return 0.0
        char_space = sum(self._CHAR_SETS[s] for s in sets)
        return length * math.log2(char_space) if char_space > 0 else 0.0

    def _has_repeated_pattern(self, pwd: str) -> bool:
        """Check for repeated characters or sequential digits/letters."""
        # repeated char (3+)
        if re.search(r'(.)\1{2,}', pwd):
            return True
        # sequential numbers (e.g., 123, 456)
        if re.search(r'(012|123|234|345|456|567|678|789|890|098|987|876|765|654|543|432|321|210)', pwd):
            return True
        # sequential letters (abc, bcd, ...)
        seq = ''.join(chr(i) for i in range(ord('a'), ord('z')+1))
        for i in range(len(seq)-2):
            if seq[i:i+3] in pwd.lower():
                return True
        return False

    def _is_keyboard_sequence(self, pwd: str) -> bool:
        """Check if password contains a known keyboard pattern."""
        pwd_lower = pwd.lower()
        for seq in self._KEYBOARD_SEQS:
            if seq in pwd_lower:
                return True
        return False

    def _result(self, score: int, strength: str, entropy: float,
                length: int, feedback: List[str]) -> Dict:
        """Build the result dictionary."""
        return {
            "score": score,
            "strength": strength,
            "entropy": round(entropy, 2),
            "length": length,
            "feedback": feedback if feedback else ["No issues detected."]
        }

    # ------------------------------------------------------------------
    # Secure verification (constant‑time) - from PDF recommendation
    # ------------------------------------------------------------------

    @staticmethod
    def verify(plain: str, hashed: str) -> bool:
        """
        Constant‑time comparison of two strings (e.g., password confirmation).
        Uses hmac.compare_digest to avoid timing side‑channels.
        """
        return hmac.compare_digest(plain, hashed)

    # ------------------------------------------------------------------
    # Memory safety (mitigation for "Data in RAM Trap")
    # ------------------------------------------------------------------

    @staticmethod
    def clear_sensitive(data: str) -> None:
        """
        Overwrite the string's memory with zeros (best‑effort).
        In practice, use bytearray for truly sensitive data.
        """
        # For demonstration; Python strings are immutable, so we cannot
        # zero out the original object. This is a placeholder.
        # A real implementation would use `ctypes` or `array` to manage
        # mutable buffers.
        pass


# ----------------------------------------------------------------------
# Interactive demo (run this file directly)
# ----------------------------------------------------------------------

def main():
    checker = PasswordStrengthChecker()
    print("=== Password Strength Checker ===")
    print("Type a password to analyse, or 'quit' to exit.\n")

    while True:
        pwd = input("Enter password: ")
        if pwd.lower() in ("quit", "exit", "q"):
            break
        if not pwd:
            print("Password cannot be empty.\n")
            continue

        result = checker.check(pwd)
        print(f"\nStrength: {result['strength']} (score {result['score']}/4)")
        print(f"Entropy: {result['entropy']} bits")
        print(f"Length: {result['length']} characters")
        print("Feedback:")
        for item in result['feedback']:
            print(f"  - {item}")
        print("\n" + "-" * 40 + "\n")


if __name__ == "__main__":
    main()