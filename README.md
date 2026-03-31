import re
from urllib.parse import urlparse

def check_url(url):
    score = 0
    reasons = []

    # Check HTTPS
    if not url.startswith("https://"):
        score += 2
        reasons.append("Not using HTTPS")

    # Check IP address in URL
    if re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url):
        score += 3
        reasons.append("Uses IP address instead of domain")

    # Suspicious keywords
    suspicious_keywords = ["login", "verify", "bank", "update", "secure", "account"]
    for word in suspicious_keywords:
        if word in url.lower():
            score += 1
            reasons.append(f"Contains suspicious keyword: {word}")

    # Long URL
    if len(url) > 75:
        score += 2
        reasons.append("URL is unusually long")

    return score, reasons


def verdict(score):
    if score >= 6:
        return "🔴 High Risk (Likely Phishing)"
    elif score >= 3:
        return "🟠 Medium Risk"
    else:
        return "🟢 Low Risk"


if __name__ == "__main__":
    url = input("Enter URL: ").strip()

    score, reasons = check_url(url)

    print("\n--- Analysis Result ---")
    print(f"Risk Score: {score}")
    print(f"Verdict: {verdict(score)}")

    print("\nReasons:")
    for r in reasons:
        print(f"- {r}")
