import os
import ssl
import json
import socket
import smtplib
import whois
from pathlib import Path
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# =====================
# CONFIG
# =====================

SSL_WARNING_DAYS = 30
DOMAIN_WARNING_DAYS = 30

DOMAINS_FILE = Path("domains.json")

# =====================
# HELPERS
# =====================

def load_domains():
    with open(DOMAINS_FILE, "r") as f:
        return json.load(f)

def normalize_datetime(dt):
    """
    WHOIS bazen liste, bazen naive datetime döndürür.
    """
    if isinstance(dt, list):
        dt = dt[0]
    if dt and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

def risk_level(days):
    if days is None:
        return "ERROR"
    if days <= 7:
        return "CRITICAL"
    if days <= 30:
        return "WARNING"
    return "OK"

# =====================
# SSL CHECK
# =====================

def check_ssl_expiry(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            expiry = datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            remaining_days = (expiry - datetime.now(timezone.utc)).days
            return expiry, remaining_days

# =====================
# DOMAIN (WHOIS) CHECK
# =====================

def check_domain_expiry(domain):
    w = whois.whois(domain)
    expiry = normalize_datetime(w.expiration_date)

    if not expiry:
        return None, None

    remaining_days = (expiry - datetime.now(timezone.utc)).days
    return expiry, remaining_days

# =====================
# MAIL
# =====================

def send_mail(subject, body):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    mail_to = os.getenv("MAIL_TO")

    if not all([smtp_host, smtp_user, smtp_pass, mail_to]):
        print("Mail ayarları eksik, mail gönderilmedi.")
        return

    msg = MIMEMultipart()
    msg["From"] = smtp_user
    msg["To"] = mail_to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)

# =====================
# MAIN
# =====================

def main():
    domains = load_domains()
    report_lines = []
    overall_risk = "OK"

    print("\nDomain monitor started (SSL + WHOIS)\n")

    for domain in domains:
        report_lines.append(f"Domain: {domain}")

        # ---- SSL ----
        try:
            ssl_expiry, ssl_days = check_ssl_expiry(domain)
            ssl_risk = risk_level(ssl_days)

            report_lines.append(f"  SSL Expiry      : {ssl_expiry}")
            report_lines.append(f"  SSL Remaining   : {ssl_days} days")
            report_lines.append(f"  SSL Risk        : {ssl_risk}")
        except Exception as e:
            ssl_risk = "ERROR"
            report_lines.append(f"  SSL check FAILED: {e}")

        # ---- DOMAIN ----
        try:
            dom_expiry, dom_days = check_domain_expiry(domain)
            dom_risk = risk_level(dom_days)

            report_lines.append(f"  Domain Expiry   : {dom_expiry}")
            report_lines.append(f"  Domain Remaining: {dom_days} days")
            report_lines.append(f"  Domain Risk     : {dom_risk}")
        except Exception as e:
            dom_risk = "ERROR"
            report_lines.append(f"  Domain check FAILED: {e}")

        # ---- OVERALL ----
        if "CRITICAL" in (ssl_risk, dom_risk):
            overall = "CRITICAL"
        elif "WARNING" in (ssl_risk, dom_risk):
            overall = "WARNING"
        elif "ERROR" in (ssl_risk, dom_risk):
            overall = "ERROR"
        else:
            overall = "OK"

        report_lines.append(f"  OVERALL RISK    : {overall}")
        report_lines.append("-" * 50)

        if overall in ["CRITICAL", "WARNING"]:
            overall_risk = overall

    report = "\n".join(report_lines)
    print(report)

    if overall_risk in ["CRITICAL", "WARNING"]:
        send_mail(
            subject=f"[ALERT] Domain & SSL Expiry Warning ({overall_risk})",
            body=report
        )

# =====================
# ENTRY
# =====================

if __name__ == "__main__":
    main()
