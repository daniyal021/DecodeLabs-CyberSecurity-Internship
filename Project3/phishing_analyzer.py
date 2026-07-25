"""
Cyber Security - Project 3
Phishing Awareness Analysis
DecodeLabs Industrial Training Kit

This tool performs a simple, rule-based scan of an email's text to help a
non-expert user spot common phishing red flags. It is an awareness aid,
NOT a replacement for real email security filtering.
"""

import re

URGENCY_WORDS = [
    "urgent", "immediately", "act now", "verify your account", "suspended",
    "locked", "24 hours", "final notice", "confirm your identity",
    "unauthorized", "click here", "limited time",
]

FEAR_GREED_WORDS = [
    "you have won", "prize", "claim your", "free gift", "legal action",
    "your account will be closed", "penalty", "reward",
]

SENSITIVE_INFO_WORDS = [
    "password", "otp", "one-time code", "pin", "ssn", "social security",
    "credit card", "cvv", "bank details", "login credentials",
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".info", ".zip", ".loan"]


def find_urls(text):
    return re.findall(r"https?://[^\s)>\]]+|www\.[^\s)>\]]+", text)


def flag_urls(urls):
    flags = []
    for url in urls:
        lowered = url.lower()
        if any(lowered.endswith(tld) or (tld + "/") in lowered for tld in SUSPICIOUS_TLDS):
            flags.append(f"Suspicious top-level domain in URL: {url}")
        if re.search(r"\d{1,3}(\.\d{1,3}){3}", url):
            flags.append(f"Raw IP address used instead of a domain: {url}")
        if "-" in url and any(b in lowered for b in ["paypal", "microsoft", "google", "bank", "apple", "amazon"]):
            flags.append(f"Brand name combined with extra words/hyphens (possible lookalike domain): {url}")
        if len(url) > 60:
            flags.append(f"Unusually long / obfuscated-looking URL: {url}")
    return flags


def keyword_flags(text, wordlist, label):
    lowered = text.lower()
    hits = [w for w in wordlist if w in lowered]
    return [f"{label}: found phrase '{w}'" for w in hits]


def analyze_email(sender, subject, body):
    text = f"{subject}\n{body}"
    red_flags = []

    red_flags += keyword_flags(text, URGENCY_WORDS, "Urgency / pressure tactic")
    red_flags += keyword_flags(text, FEAR_GREED_WORDS, "Fear or greed appeal")
    red_flags += keyword_flags(text, SENSITIVE_INFO_WORDS, "Requests sensitive information")

    urls = find_urls(body)
    red_flags += flag_urls(urls)

    if sender and "@" in sender:
        display_name = sender.split("<")[0].strip()
        domain = sender.split("@")[-1].replace(">", "").strip()
        common_brands = ["paypal", "microsoft", "google", "amazon", "apple", "bank"]
        for brand in common_brands:
            if brand in display_name.lower() and brand not in domain.lower():
                red_flags.append(
                    f"Sender display name mentions '{brand}' but the email domain "
                    f"('{domain}') does not match it."
                )

    if not red_flags:
        verdict = "SAFE (no obvious red flags detected)"
    elif len(red_flags) <= 2:
        verdict = "SUSPICIOUS (review before acting)"
    else:
        verdict = "LIKELY PHISHING (do not click links or reply)"

    return verdict, red_flags, urls


def print_report(sender, subject, verdict, red_flags, urls):
    print("\n" + "-" * 55)
    print(f"From    : {sender}")
    print(f"Subject : {subject}")
    print(f"Verdict : {verdict}")
    if urls:
        print(f"Links found ({len(urls)}):")
        for u in urls:
            print(f"   - {u}")
    if red_flags:
        print("Red Flags:")
        for f in red_flags:
            print(f"   ⚠ {f}")
    else:
        print("Red Flags: none detected")
    print("-" * 55)


def main():
    print("=" * 50)
    print("     PHISHING AWARENESS ANALYZER")
    print("=" * 50)

    while True:
        print("\n1. Analyze an email")
        print("2. Exit")
        choice = input("Choose an option (1-2): ").strip()

        if choice == "1":
            sender = input("Sender (e.g. Support <support@example.com>): ")
            subject = input("Subject: ")
            print("Body (end input with a single '.' on its own line):")
            lines = []
            while True:
                line = input()
                if line.strip() == ".":
                    break
                lines.append(line)
            body = "\n".join(lines)

            verdict, red_flags, urls = analyze_email(sender, subject, body)
            print_report(sender, subject, verdict, red_flags, urls)

        elif choice == "2":
            print("Goodbye!")
            break

        else:
            print("Invalid option, please choose 1-2.")


if __name__ == "__main__":
    main()
