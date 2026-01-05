import json
import ssl
import socket
from pathlib import Path
from datetime import datetime


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

    remaining_days = (expi_
