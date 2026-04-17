# ============================================================
# Author: M.YUSUF OZCAN
# Student ID: 101462079
# Vulnerability: Multiple Open Ports
# Targets: dns.0x10.cloud,
#          ssh.0x10.cloud,
#          ftp.0x10.cloud,
#          telnet.0x10.cloud,
#          mail.0x10.cloud,
#          redis.0x10.cloud,
#          mongo.0x10.cloud,
#          db.0x10.cloud,
# ============================================================

import socket

RED = '\033[91m'
GREEN = '\033[92m'
BLUE = '\033[94m'
RESET = '\033[0m'

target_links = [
    "0x10.cloud",
    "dns.0x10.cloud",
    "ssh.0x10.cloud",
    "ftp.0x10.cloud",
    "telnet.0x10.cloud",
    "mail.0x10.cloud",
    "redis.0x10.cloud",
    "mongo.0x10.cloud",
    "db.0x10.cloud",
]
# Non-Standard Ports
ports = {
    2121 : "FTP",
    2525 : "SMTP",
    6379 : "REDIS",
    2222 : "SSH",
    2967 : "MALICIOUS",
    2323 : "TELNET"
}
errMessages = {
    2121 :"FTP ERROR: Attackers can intercept usernames, passwords, and files during transfer",
    2525 :"SMTP ERROR: Attackers can send spam e-mails",
    6379 :"REDIS ERROR: Attackers can read, modify, or delete all database contents",
    2222 :"SSH ERROR: Attackers can crack passwords and able to access whole system",
    2967 :"MALICIOUS ERROR: means system has Malware",
    2323 :"TELNET ERROR: Attackers can steal passwords and take whole control of the system",
}

for link in target_links:
    print(f"{BLUE}--------------------------------------------------------{RESET}")
    print("Checking For Address:"+link)
    print(f"{BLUE}--------------------------------------------------------{RESET}")
    for key,value in ports.items():
        x = errMessages[key]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            connect = int(sock.connect_ex((link, key)))
            if connect == 0:
               print(f"{RED}[!] {key}:{value} Port is open")
               print(f"{x}")
            else:
               print(f"{GREEN}{key}:{value} is closed which is secure{RESET}")
            sock.close()
        except ConnectionError as e:
            print(e)
