import json
import ssl
import socket
import whois
from pathlib import Path
from datetime import datetime


SSL_WARNING_DAYS = 30
SSL_CRITICAL_DAYS = 10

DOMAIN_WARNING_DAYS = 30
DOMAIN_CRITICAL_DAYS = 15


def load_domains():
    file_path = Path("domains.json")

    if not file_path.exists():
        raise FileNotFoundError("domains.json bulunamadı")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data.get("domains", [])


def check_ssl_expiry(domain, timeout=5):
    context = ssl.create_default_context()

    with socket.create_connection((domain, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()

    not_after_str = cert.get("notAfter")
    if not not_after_str:
        raise ValueError("SSL bitiş tarihi alınamadı")

    expiry_date = datetime.strptime(
        not_after_str, "%b %d %H:%M:%S %Y %Z"
    )

    remaining_days = (expiry_date - datetime.utcnow()).days
    return expiry_date, remaining_days


def check_domain_expiry(domain):
    w = whois.whois(domain)

    expiry_date = w.expiration_date

    if isinstance(expiry_date, list):
        expiry_date = expiry_date[0]

    if not expiry_date:
        raise ValueError("Domain expiry tarihi alınamadı")

    remaining_days = (expiry_date - datetime.utcnow()).days
    return expiry_date, remaining_days


def risk_level(remaining_days, warning, critical):
    if remaining_days < critical:
        return "CRITICAL"
    elif remaining_days < warning:
        return "WARNING"
    else:
        return "OK"


def main():
    print("Domain monitor started (SSL + WHOIS)\n")

    domains = load_domains()
    risky_domains = []

    for domain in domains:
        print(f"Domain: {domain}")

        # SSL CHECK
        try:
            ssl_expiry, ssl_days = check_ssl_expiry(domain)
            ssl_risk = risk_level(
                ssl_days, SSL_WARNING_DAYS, SSL_CRITICAL_DAYS
            )
            print(f"  SSL Expiry      : {ssl_expiry}")
            print(f"  SSL Remaining   : {ssl_days} days")
            print(f"  SSL Risk        : {ssl_risk}")
        except Exception as e:
            ssl_expiry = None
            ssl_days = None
            ssl_risk = "ERROR"
            print(f"  SSL check FAILED: {e}")

        # DOMAIN CHECK
        try:
            dom_expiry, dom_days = check_domain_expiry(domain)
            dom_risk = risk_level(
                dom_days, DOMAIN_WARNING_DAYS, DOMAIN_CRITICAL_DAYS
            )
            print(f"  Domain Expiry   : {dom_expiry}")
            print(f"  Domain Remaining: {dom_days} days")
            print(f"  Domain Risk     : {dom_risk}")
        except Exception as e:
            dom_expiry = None
            dom_days = None
            dom_risk = "ERROR"
            print(f"  Domain check FAILED: {e}")

        # TOPLAM RİSK
        if "CRITICAL" in (ssl_risk, dom_risk):
            overall_risk = "CRITICAL"
        elif "WARNING" in (ssl_risk, dom_risk):
            overall_risk = "WARNING"
        elif "ERROR" in (ssl_risk, dom_risk):
            overall_risk = "ERROR"
        else:
            overall_risk = "OK"

        print(f"  OVERALL RISK    : {overall_risk}")
        print("-" * 50)

        if overall_risk != "OK":
            risky_domains.append(domain)

    print("\nÖZET")
    print(f"Toplam domain        : {len(domains)}")
    print(f"Riskli domain sayısı : {len(risky_domains)}")

    if risky_domains:
        for d in risky_domains:
            print(f"- {d}")

    print("\nKontrol tamamlandı")


if __name__ == "__main__":
    main()
