"""
simulate_attack.py
-------------------
Hits the running Flask app's /api/login endpoint repeatedly to simulate a
brute-force attack, so you can watch the dashboard flag and block it live.

Usage:
    python simulate_attack.py                     # default: attack from 1 IP
    python simulate_attack.py --ip 10.0.0.9 --user admin --attempts 8
    python simulate_attack.py --distributed        # simulate multiple attacker IPs
"""

import argparse
import time
import requests

API_URL = "http://127.0.0.1:5000/api/login"


def attack(ip: str, username: str, attempts: int, delay: float):
    print(f"Simulating {attempts} failed logins from IP={ip} user={username}")
    for i in range(1, attempts + 1):
        resp = requests.post(API_URL, json={
            "ip": ip,
            "username": username,
            "password": "wrong-password",
        })
        print(f"  attempt {i}: status={resp.status_code} body={resp.json()}")
        time.sleep(delay)


def distributed_attack(username: str, attempts_per_ip: int, num_ips: int, delay: float):
    for n in range(num_ips):
        ip = f"203.0.113.{n+1}"
        attack(ip, username, attempts_per_ip, delay)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate a brute-force login attack.")
    parser.add_argument("--ip", default="198.51.100.42", help="Attacker source IP to simulate")
    parser.add_argument("--user", default="admin", help="Target username")
    parser.add_argument("--attempts", type=int, default=7, help="Number of failed attempts")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between attempts (seconds)")
    parser.add_argument("--distributed", action="store_true",
                         help="Simulate several attacker IPs targeting the same username")
    parser.add_argument("--num-ips", type=int, default=3, help="Number of IPs for --distributed mode")
    args = parser.parse_args()

    if args.distributed:
        distributed_attack(args.user, args.attempts, args.num_ips, args.delay)
    else:
        attack(args.ip, args.user, args.attempts, args.delay)

    print("\nDone. Check the dashboard at http://127.0.0.1:5000/dashboard")
