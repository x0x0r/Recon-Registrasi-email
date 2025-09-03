import re
import requests
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

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

def detect_and_highlight(payload, name, regex):
    if regex.search(payload):
        highlighted = highlight_match(regex, payload)
        print(f"{name} detected in payload: {Fore.RED}YES{Style.RESET_ALL} -> {highlighted}")
        return True
    else:
        print(f"{name} detected in payload: {Fore.GREEN}NO{Style.RESET_ALL} -> {payload}")
        return False

def scan_login(url, user_field="username", pass_field="password", output_file="scan_results.txt"):
    print(f"\nðŸ” Scanning login form at {url}\n")

    test_payloads = [
        "admin' OR 1=1 --",
        "../../etc/passwd",
        "{{7*7}}",
        "uname -a; id"
    ]

    valid_results = []

    for payload in test_payloads:
        print(f"\nTesting payload: {payload}")

        # deteksi di sisi client
        rce = detect_and_highlight(payload, "RCE", RCE_REGEX)
        lfi = detect_and_highlight(payload, "LFI", LFI_REGEX)
        ssti = detect_and_highlight(payload, "SSTI", SSTI_REGEX)

        # gabungkan payload dengan email valid
        combined_email = payload + "@abcd.com"
        if is_rfc822_valid("test@abcd.com"):  # pastikan domain valid
            print(f"Email test: {Fore.GREEN}{combined_email}{Style.RESET_ALL} âœ… valid format")
            valid_results.append(combined_email)

        # kirim ke form login
        try:
            resp = requests.post(url, data={user_field: payload, pass_field: "test"})
            body = resp.text[:500]

            # deteksi juga di response
            detect_and_highlight(body, "RCE", RCE_REGEX)
            detect_and_highlight(body, "LFI", LFI_REGEX)
            detect_and_highlight(body, "SSTI", SSTI_REGEX)

        except Exception as e:
            print(f"{Fore.RED}Request error:{Style.RESET_ALL} {e}")

    # simpan hasil valid ke file txt
    if valid_results:
        with open(output_file, "w") as f:
            for item in valid_results:
                f.write(item + "\n")
        print(f"\nðŸ“‚ Hasil valid disimpan ke: {Fore.CYAN}{output_file}{Style.RESET_ALL}")
    else:
        print(Fore.YELLOW + "âš ï¸ Tidak ada hasil valid yang disimpan." + Style.RESET_ALL)

if __name__ == "__main__":
    email = input("Enter email address: ").strip()
    if is_rfc822_valid(email):
        print(f"RFC822 valid: {Fore.GREEN}YES{Style.RESET_ALL}")
    else:
        print(f"RFC822 valid: {Fore.RED}NO{Style.RESET_ALL}")

    target_url = input("Enter login form URL (ex: http://127.0.0.1/login): ").strip()
    scan_login(target_url)
