import json
import os
import getpass
import hashlib
import math
import random
import string
from datetime import datetime

DATA_FILE = "password_analysis_history.json"

class PasswordSecurityAnalyzer:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
        self.analysis_history = self.load_analysis_history()

    def load_common_passwords(self):
        # Static list of common / leaked passwords (real-world would use better sources)
        return {
            "123456", "12345678", "qwerty", "password", "123456789", "12345",
            "1234", "111111", "1234567", "dragon", "123123", "baseball",
            "abc123", "football", "monkey", "letmein", "696969", "shadow",
            "sunshine", "iloveyou", "princess", "admin", "welcome", "login",
            "solo", "passw0rd", "starwars", "master", "hello", "freedom",
            "superman", "batman", "trustno1", "ninja", "abc123", "iloveyou"
        }

    def load_analysis_history(self):
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r") as f:
                    return json.load(f)
            except:
                return []
        return []

    def save_analysis_history(self):
        with open(DATA_FILE, "w") as f:
            json.dump(self.analysis_history, f, indent=2)

    def calculate_entropy(self, password):
        if not password:
            return 0.0
        char_set_size = 0
        if any(c.islower() for c in password): char_set_size += 26
        if any(c.isupper() for c in password): char_set_size += 26
        if any(c.isdigit() for c in password): char_set_size += 10
        if any(c in string.punctuation for c in password): char_set_size += len(string.punctuation)
        return len(password) * math.log2(char_set_size) if char_set_size > 0 else 0

    def evaluate_strength(self, password):
        score = 0
        issues = []

        length = len(password)
        if length < 8:
            issues.append("Password is too short (<8 characters)")
        elif length >= 16:
            score += 40
        elif length >= 12:
            score += 25
        elif length >= 10:
            score += 15

        entropy = self.calculate_entropy(password)
        if entropy < 40:
            issues.append(f"Low entropy (~{entropy:.1f} bits)")
        elif entropy >= 70:
            score += 35

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        if has_lower: score += 10
        if has_upper: score += 10
        if has_digit: score += 10
        if has_special: score += 15

        if sum([has_lower, has_upper, has_digit, has_special]) < 3:
            issues.append("Missing character variety")

        return score, issues

    def is_common_password(self, password):
        if password.lower() in self.common_passwords:
            return True, "Common / previously leaked password detected"
        return False, None

    def check_username_similarity(self, username, password):
        if not username or not password:
            return False, None
        u = username.lower()
        p = password.lower()
        if p in u or u in p or p.startswith(u) or p.endswith(u):
            return True, "Password too similar to username"
        return False, None

    def analyze_password(self):
        print("\n" + "-"*60)
        username = input("Enter username/email (for similarity check): ").strip()
        password = getpass.getpass("Enter password (hidden): ")

        issues = []
        score = 0

        is_common, msg = self.is_common_password(password)
        if is_common:
            issues.append(msg)
            score -= 50

        similar, sim_msg = self.check_username_similarity(username, password)
        if similar:
            issues.append(sim_msg)
            score -= 30

        strength_score, strength_issues = self.evaluate_strength(password)
        score += strength_score
        issues.extend(strength_issues)

        final_score = max(0, min(100, score))

        verdict = "Very Weak" if final_score < 30 else \
                  "Weak" if final_score < 50 else \
                  "Moderate" if final_score < 70 else \
                  "Strong" if final_score < 90 else "Excellent"

        pw_hash = hashlib.sha256(password.encode()).hexdigest()[:16] + "..."

        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "password_hash": pw_hash,
            "score": final_score,
            "verdict": verdict,
            "issues": issues
        }
        self.analysis_history.append(entry)
        self.save_analysis_history()

        print("\nPassword Analysis Result:")
        print(f"Username: {username}")
        print(f"Password (hashed): {pw_hash}")
        print(f"Score: {final_score}/100 → {verdict}")
        if issues:
            print("Issues / Warnings:")
            for i in issues:
                print(f"  • {i}")
        else:
            print("No major issues detected.")

    def generate_secure_passphrase(self):
        words = ["apple", "blue", "cat", "dog", "elephant", "fox", "grape", "horse",
                 "ice", "juice", "kite", "lemon", "moon", "night", "ocean", "panda",
                 "queen", "river", "sun", "tree", "violet", "wind", "yellow", "zebra"]
        length = random.randint(4, 6)
        passphrase = " ".join(random.choice(words) for _ in range(length))
        if random.random() > 0.5:
            passphrase += random.choice(["!", "@", "#", "$", "%", "^", "&"])
        print(f"\nSuggested strong passphrase: {passphrase}")
        print("(For real security, use a proper diceware wordlist)")

    def display_analysis_history(self):
        if not self.analysis_history:
            print("\nNo analysis history yet.")
            return
        print("\nPrevious Password Analyses (most recent first):")
        for entry in reversed(self.analysis_history[-10:]):
            print(f"[{entry['timestamp']}] {entry['username']} → {entry['verdict']} ({entry['score']}/100)")

    def display_menu(self):
        print("\n" + "="*60)
        print("     PASSWORD SECURITY ANALYZER & GENERATOR")
        print("="*60)
        print("1. Analyze password strength & safety")
        print("2. Generate strong passphrase suggestion")
        print("3. View analysis history")
        print("4. Exit")
        print("="*60)

def run_application():
    analyzer = PasswordSecurityAnalyzer()
    print("Password Security Analyzer – Computer Science / Cybersecurity Tool\n")

    while True:
        analyzer.display_menu()
        choice = input("Choose (1-4): ").strip()

        if choice == "1":
            analyzer.analyze_password()
        elif choice == "2":
            analyzer.generate_secure_passphrase()
        elif choice == "3":
            analyzer.display_analysis_history()
        elif choice == "4":
            print("\nExiting. Remember: Use strong, unique passwords!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    run_application()