import re
from urllib.parse import urlparse

# ================== CONFIG ==================
BRANDS = ["paypal", "google", "amazon", "microsoft", "apple", "facebook", "whatsapp"]

CASUAL_SALUTATION = ["user", "customer", "sir", "madam"]
URGENCY_WORDS = [
    "urgent",
    "immediately",
    "suspended",
    "verify now",
    "last warning",
    "emergency"
]

SUSPICIOUS_TLDS = [".exe", ".zip", ".scr", ".iso"]

# ================== INPUT ==================
field = input("Paste email text:\n")

# ================== LINK EXTRACTION ==================
full_url_pattern = r'https?://[^\s]+'
domain_pattern = r'\b(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b'

full_urls = re.findall(full_url_pattern, field)
links = full_urls if full_urls else re.findall(domain_pattern, field)

with open("link.txt", "w") as f:
    for link in links:
        f.write(link + "\n")

# ================== LANGUAGE ANALYSIS ==================
def grammar_risk(text):
    words = re.findall(r"[a-zA-Z]+", text)
    if not words:
        return 0

    short_words = [w for w in words if len(w) <= 2]
    ratio = len(short_words) / len(words)

    if ratio > 0.4:
        return 5
    elif ratio > 0.25:
        return 2
    return 0


def punctuation_risk(text):
    score = 0
    if "!!!" in text or "???" in text:
        score += 5
    if text.count("!") > 3:
        score += 3
    return score


def capitalization_risk(text):
    words = text.split()
    if not words:
        return 0

    caps = [w for w in words if len(w) > 2 and w.isupper()]
    ratio = len(caps) / len(words)

    if ratio > 0.1:
        return 7
    elif ratio > 0.05:
        return 4
    return 0


def wording_risk(text):
    score = 0
    text = text.lower()

    for word in CASUAL_SALUTATION:
        if word in text:
            score += 2

    for word in URGENCY_WORDS:
        if word in text:
            score += 3

    return score


def language_risk_score(text):
    return (
        grammar_risk(text)
        + punctuation_risk(text)
        + capitalization_risk(text)
        + wording_risk(text)
    )

# ================== LINK ANALYSIS ==================
def extract_domain(url):
    if not url.startswith("http"):
        url = "http://" + url
    return urlparse(url).netloc.lower()


def protocol_risk(url):
    if url.startswith("https://"):
        return 0
    elif url.startswith("http://"):
        return 35
    return 10


def tld_risk(url):
    for tld in SUSPICIOUS_TLDS:
        if url.lower().endswith(tld):
            return 40
    return 0


def double_extension_risk(url):
    matches = re.findall(r"\.(\w+)", url.lower())
    if len(matches) >= 2:
        return 25
    return 0


def subdomain_risk(domain):
    return 10 if len(domain.split(".")) > 3 else 0


def brand_risk(domain):
    for brand in BRANDS:
        if brand in domain and not domain.endswith(brand + ".com"):
            return 30
    return 0


def analyze_link(url):
    domain = extract_domain(url)
    score = 0

    score += protocol_risk(url)
    score += tld_risk(url)
    score += double_extension_risk(url)
    score += subdomain_risk(domain)
    score += brand_risk(domain)

    return score, domain


def analyze_links(links):
    results = []
    for link in links:
        score, domain = analyze_link(link)
        results.append({
            "url": link,
            "domain": domain,
            "risk_score": score
        })
    return results

# ================== FINAL REPORT ==================
language_score = language_risk_score(field)
link_results = analyze_links(links)

total_link_score = sum(item["risk_score"] for item in link_results)
total_score = language_score + total_link_score

print("\n--- PHISHING ANALYSIS REPORT ---")
print(f"Language risk score: {language_score}")
print(f"Total link risk score: {total_link_score}")
print(f"OVERALL RISK SCORE: {total_score}\n")

for item in link_results:
    print(f"Link: {item['url']}")
    print(f"Domain: {item['domain']}")
    print(f"Link risk score: {item['risk_score']}\n")

if total_score >= 70:
    print("⚠️ HIGH RISK — Likely phishing email")
elif total_score >= 40:
    print("⚠️ MEDIUM RISK — Suspicious content detected")
else:
    print("✅ LOW RISK — No strong phishing indicators")
