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

DOMAINS_FILE = Path("domains.json")

# =====================
# HELPERS
# =====================

def load_domains():
    with open(DOMAINS_FILE, "r") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("domains.json must be a JSON array")
    return data

def normalize_datetime(dt):
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
# DOMAIN CHECK (WHOIS)
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
    smtp_port = os.getenv("SMTP_PORT")
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    mail_to = os.getenv("MAIL_TO")

    if not all([smtp_host, smtp_user, smtp_pass, mail_to]):
        print("Mail ayarları eksik, mail gönderilmedi")
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
    risk_report = []

    print("\nDomain monitor started (SSL + WHOIS)\n")

    for domain in domains:
        print(f"Checking {domain}")

        # SSL
        try:
            _, ssl_days = check_ssl_expiry(domain)
            ssl_risk = risk_level(ssl_days)
            ssl_error = None
        except Exception as e:
            ssl_days = None
            ssl_risk = "ERROR"
            ssl_error = str(e)

        # DOMAIN
        try:
            _, dom_days = check_domain_expiry(domain)
            dom_risk = risk_level(dom_days)
            dom_error = None
        except Exception as e:
            dom_days = None
            dom_risk = "ERROR"
            dom_error = str(e)

        # OVERALL
        if "CRITICAL" in (ssl_risk, dom_risk):
            overall = "CRITICAL"
        elif "WARNING" in (ssl_risk, dom_risk):
            overall = "WARNING"
        elif "ERROR" in (ssl_risk, dom_risk):
            overall = "ERROR"
        else:
            overall = "OK"

        if overall != "OK":
            risk_report.append({
                "domain": domain,
                "ssl_risk": ssl_risk,
                "ssl_days": ssl_days,
                "ssl_error": ssl_error,
                "domain_risk": dom_risk,
                "domain_days": dom_days,
                "domain_error": dom_error,
                "overall": overall
            })

    # =====================
    # MAIL REPORT
    # =====================

    if risk_report:
        lines = []
        lines.append("SSL & Domain Expiry Risk Report\n")
        lines.append(f"Toplam riskli domain: {len(risk_report)}\n")

        for r in risk_report:
            lines.append(f"- {r['domain']}")
            lines.append(
                f"  SSL Risk    : {r['ssl_risk']} ({r['ssl_days']} days)"
            )
            if r["ssl_error"]:
                lines.append(f"  SSL Error   : {r['ssl_error']}")

            lines.append(
                f"  Domain Risk : {r['domain_risk']} ({r['domain_days']} days)"
            )
            if r["domain_error"]:
                lines.append(f"  Domain Error: {r['domain_error']}")

            lines.append(f"  OVERALL     : {r['overall']}\n")

        body = "\n".join(lines)
        subject = f"[ALERT] Domain & SSL Risk Report ({len(risk_report)})"

        send_mail(subject, body)
        print("Risk maili gönderildi")
    else:
        print("Risk yok, mail gönderilmedi")

if __name__ == "__main__":
    main()
