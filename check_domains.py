import json
import ssl
import socket
from pathlib import Path
from datetime import datetime


SSL_WARNING_DAYS = 30
SSL_CRITICAL_DAYS = 10


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
        raise ValueError("Sertifika bitiş tarihi alınamadı")

    expiry_date = datetime.strptime(
        not_after_str, "%b %d %H:%M:%S %Y %Z"
    )

    remaining_days = (expiry_date - datetime.utcnow()).days
    return expiry_date, remaining_days


def ssl_risk_level(remaining_days):
    if remaining_days < SSL_CRITICAL_DAYS:
        return "CRITICAL"
    elif remaining_days < SSL_WARNING_DAYS:
        return "WARNING"
    else:
        return "OK"


def main():
    print("Domain monitor started (SSL risk analysis)\n")

    domains = load_domains()

    if not domains:
        print("Tanımlı domain bulunamadı")
        return

    risky_domains = []

    for domain in domains:
        try:
            expiry_date, remaining_days = check_ssl_expiry(domain)
            risk = ssl_risk_level(remaining_days)

            print(f"Domain: {domain}")
            print(f"  SSL Expiry Date : {expiry_date}")
            print(f"  Remaining Days  : {remaining_days}")
            print(f"  Risk Level     : {risk}")

            if risk != "OK":
                risky_domains.append(
                    (domain, expiry_date, remaining_days, risk)
                )

        except Exception as e:
            print(f"Domain: {domain}")
            print(f"  SSL check FAILED: {e}")
            risky_domains.append(
                (domain, None, None, "ERROR")
            )

        print("-" * 40)

    print("\nÖZET")
    print(f"Toplam domain      : {len(domains)}")
    print(f"Riskli domain sayısı: {len(risky_domains)}")

    if risky_domains:
        print("\nRiskli Domainler:")
        for d in risky_domains:
            print(f"- {d[0]} | {d[3]}")

    print("\nSSL risk analizi tamamlandı")


if __name__ == "__main__":
    main()
