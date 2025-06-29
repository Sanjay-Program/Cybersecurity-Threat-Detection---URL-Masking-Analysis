import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, unquote
import csv
import idna
import socket

# --- Load known shorteners from CSV ---
def load_shorteners(csv_file):
    with open(csv_file, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader, None)  # skip header
        return {row[0].strip().lower() for row in reader if row}

SHORTENERS = load_shorteners("shorteners.csv")

# --- Helper Functions ---
def is_shortened(url):
    try:
        return urlparse(url).netloc.lower() in SHORTENERS
    except:
        return False

def unshorten_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        return response.url
    except:
        return url

def contains_redirect_param(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for key in qs:
        if key.lower() in ['url', 'redirect', 'next', 'target', 'r']:
            return True, unquote(qs[key][0])
    return False, None

def is_ip_address(url):
    try:
        host = urlparse(url).hostname
        socket.inet_aton(host)
        return True
    except:
        return False

def is_homograph(domain):
    try:
        decoded = idna.encode(domain).decode()
        legit = ['paypal.com', 'google.com', 'apple.com', 'microsoft.com']
        for legit_domain in legit:
            if domain.lower() != legit_domain and idna.encode(legit_domain).decode() == decoded:
                return True
        return False
    except:
        return False

def detect_encoded_url(url):
    decoded = unquote(url)
    return decoded != url

def detect_data_url(url):
    return url.strip().lower().startswith("data:")

def is_masked(url):
    parsed = urlparse(url)

    # @ Spoofing
    if '@' in parsed.netloc:
        return True, "Username spoofing (@ in domain)"

    # Shortener
    if is_shortened(url):
        return True, "Known shortener domain"

    # Redirect parameter
    is_redirect, target = contains_redirect_param(url)
    if is_redirect:
        return True, f"Redirect parameter to: {target}"

    # IP address
    if is_ip_address(url):
        return True, "IP address used"

    # Homograph
    if is_homograph(parsed.hostname or ""):
        return True, "Homograph domain spoofing"

    # Encoded or data
    if detect_encoded_url(url) or detect_data_url(url):
        return True, "Encoded or base64/data: URL"

    return False, None

# --- MAIN FUNCTION with Loop ---
def analyze_url_recursive(url, max_depth=5):
    visited = [url]
    reasons = []

    for _ in range(max_depth):
        masked, reason = is_masked(url)
        if masked:
            reasons.append(f"→ {reason}")
            # Attempt to unmask
            is_redirect, target = contains_redirect_param(url)
            if is_redirect:
                url = target
            elif is_shortened(url):
                url = unshorten_url(url)
            elif '@' in urlparse(url).netloc:
                domain_part = urlparse(url).netloc.split('@')[-1]
                url = f"http://{domain_part}{urlparse(url).path}"
            else:
                break  # No further unmasking path
            visited.append(url)
        else:
            break

    # --- Output Result ---
    if len(visited) > 1:
        print(f"⚠️ Multi-layer masking detected!")
        print("🧅 Unwrapping path:")
        for i, step in enumerate(visited):
            print(f"  [{i}] {step}")
        if reasons:
            print("📌 Reasons:")
            for r in reasons:
                print("   ", r)
    else:
        print("✅ Not masked")

# --- CLI ---
if __name__ == "__main__":
    user_url = input("🔗 Enter a URL to scan recursively for masking: ").strip()
    analyze_url_recursive(user_url)
