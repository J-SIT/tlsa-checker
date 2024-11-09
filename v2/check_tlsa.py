import os
import requests
import dns.resolver
import ssl
import socket
import json
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from datetime import datetime, timezone

def fetch_tlsa_record(domain, tlsa_record):
    try:
        answer = dns.resolver.resolve(f"{tlsa_record}.{domain}", 'TLSA')
        tlsa_data = answer[0].to_text().split()
        usage, selector, matching_type, cert_data = tlsa_data
        return int(usage), int(selector), int(matching_type), cert_data
    except Exception as e:
        print(f"FAIL - Error fetching TLSA record: {e}")
        return None

def get_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert_bin, default_backend())
        return x509_cert
    except Exception as e:
        print(f"FAIL - Error fetching certificate: {e}")
        return None

def verify_tlsa_record(x509_cert, tlsa_entry):
    if not tlsa_entry:
        print("FAIL - No valid TLSA record found.")
        return False

    usage, selector, matching_type, tlsa_cert_data = tlsa_entry

    # Auswahl von Daten je nach `selector`
    if selector == 0:
        cert_data = x509_cert.public_bytes(Encoding.DER)
    elif selector == 1:
        cert_data = x509_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    else:
        print("FAIL - Unsupported selector in TLSA record.")
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
        print("FAIL - Unsupported matching type in TLSA record.")
        return False

    # Vergleich mit TLSA-Daten
    if hash_data == tlsa_cert_data:
        print("INFO - TLSA record is valid and matches the certificate.")
        return True
    else:
        print(f"INFO - TLSA record does not match the certificate. Found: {tlsa_cert_data}, Expected: {hash_data}")
        
        return False


def get_expected_hash(x509_cert, tlsa_entry):
    if not tlsa_entry:
        print("FAIL - No valid TLSA record found.")
        return False

    usage, selector, matching_type, tlsa_cert_data = tlsa_entry

    # Auswahl von Daten je nach `selector`
    if selector == 0:
        cert_data = x509_cert.public_bytes(Encoding.DER)
    elif selector == 1:
        cert_data = x509_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    else:
        print("FAIL - Unsupported selector in TLSA record.")
        return False

    # Hashes erzeugen gemäß `matching_type`
    if matching_type == 0:
        hash_data = cert_data.hex()
    elif matching_type == 1:
        digest = hashes.Hash(hashes.SHA256(), default_backend())
        digest.update(cert_data)
        hash_data = digest.finalize().hex()
        return hash_data
    elif matching_type == 2:
        digest = hashes.Hash(hashes.SHA512(), default_backend())
        digest.update(cert_data)
        hash_data = digest.finalize().hex()
        return hash_data
    else:
        print("FAIL - Unsupported matching type in TLSA record.")
        return False

def send_discord_message(message):
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
    try:
        response = requests.post(webhook_url, json={"content": message})
        if response.status_code == 204:
            print("SUCESS - Discord notification sent successfully.")
        else:
            print(f"FAIL - Failed to send Discord notification. Status code: {response.status_code}")
    except Exception as e:
        print(f"FAIL - Fail sending message to Discord: {e}")

def fetch_and_select_tlsa_record(api_token, zone_id, tlsa_record_name):
    # Fetches existing Cloudflare TLSA records and returns the record ID of the specified TLSA record.
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=TLSA"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200 and response.json().get('success'):
        records = response.json().get('result', [])
        for record in records:
            if record['name'] == tlsa_record_name:
                print(f"INFO - Found TLSA record: {record['name']} (ID: {record['id']})")
                return record['id']
        logging.info("FAIL - No matching TLSA record found.")
        return None
    else:
        logging.error("FAIL - Failed to fetch TLSA records.")
        return None

def update_tlsa_record_in_cloudflare(api_token, zone_id, domain, tlsa_record, usage, selector, matching_type, expected_hash):
    # Updates a specific TLSA record in Cloudflare with new certificate data.
    print(f"INFO - Starting update of TLSA record for {tlsa_record}.{domain} with new certificate data.")
    target_name = f"{tlsa_record}.{domain}"
    
    # Find the record ID for the TLSA record
    record_id = fetch_and_select_tlsa_record(api_token, zone_id, target_name)
    
    if not record_id:
        print(f"FAIL - No TLSA record found for {target_name}. Cannot proceed with update.")
        send_discord_message(f"FAIL - Cloudflare no TLSA record found for {target_name}. Cannot proceed with update.")
        return
    
    # Define the URL and headers for the update request
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    # Data payload with new TLSA record details
    data = {
        "type": "TLSA",
        "name": target_name,
        "ttl": 1,
        "data": {
            "usage": usage,
            "selector": selector,
            "matching_type": matching_type,
            "certificate": expected_hash
        }
    }
    
    # Perform the update request
    try:
        update_response = requests.put(url, headers=headers, json=data)
        update_response.raise_for_status()  # Raises HTTPError if the request returned unsuccessful status
        #print(f"Update response: Status Code: {update_response.status_code}, Content: {update_response.json()}")
        print(f"SUCCESS - Successfully updated TLSA record for {target_name} with new certificate data.")
        send_discord_message(f"SUCCESS - TLSA record for {tlsa_record}.{domain} was updated.")
    except requests.exceptions.HTTPError as http_err:
        print(f"FAIL - HTTP error occurred: {http_err}")
        send_discord_message(f"FAIL - Cloudflare TLSA-Record update HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"FAIL - An error occurred: {err}")
        send_discord_message(f"FAIL - Cloudflare TLSA-Record update An error occurred: {err}")

def check_tlsa():
    domain = os.getenv("DOMAIN")
    tlsa_records = [record for record in os.getenv("TLSA_RECORDS", "").split(",") if record]
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
    api_token = os.getenv("CLOUDFLARE_API_TOKEN")
    zone_id = os.getenv("CLOUDFLARE_ZONE_ID")

    if not all([domain, tlsa_records, webhook_url, api_token, zone_id]):
        print("FAIL - Environment variables missing.")
        return

    # TLSA-Eintrag und Zertifikat abrufen
    x509_cert = get_certificate(domain)
    if not x509_cert:
        print("FAIL - No certificate found. Skipping TLSA verification.")
        send_discord_message(f"FAIL - No certificate found. Skipping TLSA verification.")
        return

    # Ablaufdatum des Zertifikats prüfen
    expiry_date = x509_cert.not_valid_after_utc.replace(tzinfo=timezone.utc)
    days_remaining = (expiry_date - datetime.now(timezone.utc)).days
    print(f"INFO - Certificate for {domain} expires on {expiry_date} ({days_remaining} days remaining)")

    # TLSA Eintrag überprüfen
    for tlsa_record in tlsa_records:
        print(f"INFO - Checking TLSA record for {tlsa_record}.{domain}")
        tlsa_entry = fetch_tlsa_record(domain, tlsa_record)
        if tlsa_entry is None:
            print(f"FAIL - No Cloudflare TLSA record found for {tlsa_record}.{domain} Skipping...")
            continue

        if not verify_tlsa_record(x509_cert, tlsa_entry):
            print(f"INFO - TLSA record for {tlsa_record}.{domain} is invalid or does not match. Updating...")
            send_discord_message(f"INFO - TLSA record for {tlsa_record}.{domain} is invalid or does not match. Updating...")
            usage, selector, matching_type, cert_data = tlsa_entry
            expected_hash = get_expected_hash(x509_cert, tlsa_entry)
            update_tlsa_record_in_cloudflare(api_token, zone_id, domain, tlsa_record, usage, selector, matching_type, expected_hash)

        else:
            print(f"INFO - TLSA record for {tlsa_record}.{domain} is valid.")

if __name__ == "__main__":
    mode = os.getenv("MODE", "check")
    if mode == "test":
        send_discord_message("TEST - TLSA-Checker functional.")
    else:
        check_tlsa()