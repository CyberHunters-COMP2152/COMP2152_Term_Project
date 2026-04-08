# ============================================================
# Author: Tanzeem Shaikh
# Student ID: 101585484
# Vulnerability: Missing HTTP Security Headers
# Target: api.0x10.cloud
# ============================================================

import urllib.request
import time

TARGET = "http://api.0x10.cloud"

# These headers protect users from common web attacks.
# If they are missing, the server is vulnerable.
SECURITY_HEADERS = {
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "Strict-Transport-Security": "Forces HTTPS connections",
    "Content-Security-Policy": "Prevents XSS and code injection",
    "X-XSS-Protection": "Enables browser XSS filter",
    "Referrer-Policy": "Controls referrer info leakage",
    "Server": "Exposes server software version (info leak)",
    "X-Powered-By": "Exposes backend tech (info leak)",
}

def check_security_headers():
    """Fetch HTTP response and check for missing security headers."""
    try:
        # Step 1: Send HTTP GET request
        time.sleep(0.15)
        response = urllib.request.urlopen(TARGET, timeout=5)
        headers = dict(response.headers)

        print(f"[+] Connected to {TARGET}")
        print(f"[+] HTTP Status: {response.status}\n")

        # Step 2: Check each security header
        missing = []
        exposed = []

        for header, description in SECURITY_HEADERS.items():
            value = headers.get(header)
            if header in ["Server", "X-Powered-By"]:
                # These being PRESENT is the vulnerability (info leak)
                if value:
                    exposed.append((header, value, description))
                    print(f"[!] INFO LEAK   — {header}: {value}")
                    print(f"    Risk: {description}")
                else:
                    print(f"[+] SAFE        — {header}: not disclosed")
            else:
                # These being ABSENT is the vulnerability
                if not value:
                    missing.append((header, description))
                    print(f"[!] MISSING     — {header}")
                    print(f"    Risk: {description}")
                else:
                    print(f"[+] PRESENT     — {header}: {value}")

        # Step 3: Summary report
        print("\n" + "=" * 55)
        print("VULNERABILITY SUMMARY")
        print("=" * 55)
        if missing:
            print(f"[!] {len(missing)} missing security header(s) found!")
            print("[!] These missing headers allow attackers to perform")
            print("    clickjacking, XSS injection, and MIME sniffing attacks.")
        if exposed:
            print(f"[!] {len(exposed)} information-leaking header(s) found!")
            print("[!] Exposed server info helps attackers find known exploits.")
        if not missing and not exposed:
            print("[+] No vulnerabilities found in headers.")

    except urllib.error.URLError as e:
        print(f"[-] Could not connect to {TARGET}: {e}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

if __name__ == "__main__":
    print("=" * 55)
    print("  Missing Headers Check — COMP2152 Term Project")
    print("=" * 55)
    check_security_headers()