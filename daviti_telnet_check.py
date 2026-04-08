# ============================================================
# Author: Daviti Sidana
# Student ID: 101540372
# Vulnerability: Open Telnet Port (Cleartext Protocol)
# Target: telnet.0x10.cloud
# ============================================================

import socket
import time

TARGET = "telnet.0x10.cloud"
PORT = 2323  # Non-standard Telnet port

def check_telnet():
    """Connect to Telnet port and confirm cleartext risk."""
    try:
        # Step 1: Create a TCP socket and connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((TARGET, PORT))

        if result == 0:
            print(f"[+] Successfully connected to {TARGET} on port {PORT}")

            # Step 2: Read the banner/welcome message
            time.sleep(0.3)
            try:
                banner = sock.recv(1024).decode(errors="ignore")
                print(f"[+] Server banner: {banner.strip()}")
            except:
                print("[+] No banner received (port still open)")

            # Step 3: Report the vulnerability
            print("\n[!] VULNERABILITY CONFIRMED: Telnet is OPEN on port 2323")
            print("[!] Telnet sends ALL data — including passwords — in CLEARTEXT.")
            print("[!] An attacker on the same network can use a packet sniffer")
            print("    (e.g. Wireshark) to read every character the user types.")
            print("[!] Recommendation: Disable Telnet and use SSH instead.")
        else:
            print(f"[-] Port {PORT} is closed on {TARGET}. Vulnerability not present.")

        sock.close()

    except socket.timeout:
        print(f"[-] Connection timed out connecting to {TARGET}:{PORT}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

if __name__ == "__main__":
    print("=" * 55)
    print("  Telnet Vulnerability Check — COMP2152 Term Project")
    print("=" * 55)
    check_telnet()