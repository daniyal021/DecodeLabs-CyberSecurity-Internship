"""
DecodeLabs Industrial Training Kit — Project 1
Password Strength Checker

Goal: Classify a password as WEAK / MEDIUM / STRONG based on
length, character variety, and a common-password blocklist check.

Key Skills covered: string handling, conditional logic, security basics.
"""

import string

# A tiny sample "leaked password" blocklist — in a real system this
# would be a file with 10k+ entries (e.g. RockYou list), loaded once.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "abc123",
    "password1", "111111", "12345678", "letmein", "iloveyou",
}

SYMBOLS = set(string.punctuation)


def check_password_strength(password: str) -> dict:
    """
    Runs the password through the validation pipeline (the 'IPO model'
    from the slides: Input -> Process -> Output) and returns a report.
    """
    length = len(password)

    # --- Process: pattern recognition (Pythonic, short-circuiting checks) ---
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(char in SYMBOLS for char in password)
    is_common = password.lower() in COMMON_PASSWORDS

    # --- Gatekeeper rule: immediate fail conditions ---
    reasons = []
    if length < 8:
        reasons.append("Too short (minimum 8 characters).")
    if is_common:
        reasons.append("This password appears in a common/leaked password list.")
    if not has_upper:
        reasons.append("Add at least one uppercase letter.")
    if not has_lower:
        reasons.append("Add at least one lowercase letter.")
    if not has_digit:
        reasons.append("Add at least one number.")
    if not has_symbol:
        reasons.append("Add at least one symbol (e.g. !, @, #, $).")

    # --- Scoring: each criterion met adds a point ---
    score = sum([
        length >= 8,
        length >= 12,       # bonus point for extra length
        has_upper,
        has_lower,
        has_digit,
        has_symbol,
    ])

    # --- Output: risk classification ---
    if is_common or length < 8:
        strength = "WEAK"
    elif score <= 3:
        strength = "WEAK"
    elif score <= 5:
        strength = "MEDIUM"
    else:
        strength = "STRONG"

    return {
        "password": password,
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "is_common": is_common,
        "score": score,
        "strength": strength,
        "reasons": reasons,
    }


def print_report(report: dict) -> None:
    bar = {"WEAK": "🔴 [██        ]",
           "MEDIUM": "🟠 [██████    ]",
           "STRONG": "🟢 [██████████]"}[report["strength"]]

    print("\n" + "=" * 45)
    print(f"  Password Strength: {report['strength']}  {bar}")
    print("=" * 45)
    print(f"  Length      : {report['length']} characters")
    print(f"  Uppercase   : {'✔' if report['has_upper'] else '✘'}")
    print(f"  Lowercase   : {'✔' if report['has_lower'] else '✘'}")
    print(f"  Number      : {'✔' if report['has_digit'] else '✘'}")
    print(f"  Symbol      : {'✔' if report['has_symbol'] else '✘'}")
    print(f"  Not on leaked list : {'✔' if not report['is_common'] else '✘'}")
    if report["reasons"]:
        print("\n  Suggestions to improve:")
        for r in report["reasons"]:
            print(f"   - {r}")
    print("=" * 45 + "\n")


def main():
    print("DecodeLabs — Password Strength Checker")
    print("Type 'quit' to exit.\n")
    while True:
        pwd = input("Enter a password to check: ")
        if pwd.lower() == "quit":
            print("Goodbye!")
            break
        report = check_password_strength(pwd)
        print_report(report)


if __name__ == "__main__":
    main()