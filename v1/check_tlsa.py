import os
import requests
import dns.resolver
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from datetime import datetime

def fetch_tlsa_record(domain, tlsa_record):
    try:
        answer = dns.resolver.resolve(f"{tlsa_record}.{domain}", 'TLSA')
        tlsa_data = answer[0].to_text().split()
        usage, selector, matching_type, cert_data = tlsa_data
        return int(usage), int(selector), int(matching_type), cert_data
    except Exception as e:
        print(f"Error fetching TLSA record: {e}")
        return None

def get_certificate(domain):
    try:
        context = ssl.create_default_context()

        # Erstellt eine Socket-Verbindung und umwandelt sie in einen sicheren Socket
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert_bin, default_backend())

        return x509_cert
    except Exception as e:
        print(f"Error fetching certificate: {e}")
        return None

def verify_tlsa_record(x509_cert, tlsa_entry):
    if not tlsa_entry:
        print("No valid TLSA record found.")
        return False

    usage, selector, matching_type, tlsa_cert_data = tlsa_entry

    # Auswahl von Daten je nach `selector`
    if selector == 0:
        cert_data = x509_cert.public_bytes(Encoding.DER)
    elif selector == 1:
        cert_data = x509_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    else:
        print("Unsupported selector in TLSA record.")
        return False

    # Hashes erzeugen gemäß `matching_type`
    if matching_type == 0:
        hash_data = cert_data.hex()
    elif matching_type == 1:
        digest = hashes.Hash(hashes.SHA256(), default_backend())
        digest.update(cert_data)
        hash_data = digest.finalize().hex()
    elif matching_type == 2:
        digest = hashes.Hash(hashes.SHA512(), default_backend())
        digest.update(cert_data)
        hash_data = digest.finalize().hex()
    else:
        print("Unsupported matching type in TLSA record.")
        return False

    # Vergleich mit TLSA-Daten
    if hash_data == tlsa_cert_data:
        print("TLSA record is valid and matches the certificate.")
        return True
    else:
        print("TLSA record does not match the certificate.")
        return False

def send_discord_message(webhook_url, message):
    try:
        response = requests.post(webhook_url, json={"content": message})
        if response.status_code == 204:
            print("Discord notification sent successfully.")
        else:
            print(f"Failed to send Discord notification. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending message to Discord: {e}")

def check_tlsa():
    domain = os.getenv("DOMAIN")
    tlsa_record = os.getenv("TLSA_RECORD")
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")

    if not all([domain, tlsa_record, webhook_url]):
        print("Environment variables DOMAIN, TLSA_RECORD, or DISCORD_WEBHOOK_URL not set.")
        return

    # TLSA-Eintrag und Zertifikat abrufen
    tlsa_entry = fetch_tlsa_record(domain, tlsa_record)
    x509_cert = get_certificate(domain)
    if not x509_cert:
        print("No certificate found. Skipping TLSA verification.")
        return

    # Ablaufdatum des Zertifikats prüfen
    expiry_date = x509_cert.not_valid_after
    days_remaining = (expiry_date - datetime.utcnow()).days
    print(f"Certificate for {domain} expires on {expiry_date} ({days_remaining} days remaining)")

    # TLSA Eintrag überprüfen
    if days_remaining < 0:
        print("Certificate expired. Sending notification to Discord.")
        send_discord_message(webhook_url, f"Dein TLSA Eintrag {tlsa_record} ist abgelaufen.")
    else:
        tlsa_valid = verify_tlsa_record(x509_cert, tlsa_entry)
        if not tlsa_valid:
            print("TLSA record is invalid. Sending notification to Discord.")
            send_discord_message(webhook_url, f"Der TLSA Eintrag {tlsa_record} ist ungültig oder passt nicht zum Zertifikat.")

def send_test_message():
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
    if webhook_url:
        send_discord_message(webhook_url, "Testnachricht: TLSA-Überprüfung funktioniert.")
    else:
        print("DISCORD_WEBHOOK_URL ist nicht gesetzt.")

if __name__ == "__main__":
    mode = os.getenv("MODE", "check")
    if mode == "test":
        send_test_message()
    else:
        check_tlsa()

