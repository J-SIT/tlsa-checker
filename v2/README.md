This project is about being automatically notified when a certificate and a DANE TLSA record no longer match. This happens, for example, when certificates are used via Lets Encrypt and auto renewal. 
A notification is sent via a Discord WebHook. <br>

GitHub project: https://github.com/J-SIT/tlsa-checker/

The following can be set via the environment variables:
- DOMAIN: "abc.de"
- TLSA_RECORDS: "_25._tcp,_143._tcp,_465._tcp"
- DISCORD_WEBHOOK_URL: "https://discord.com/api/webhooks/130..."
- CHECK_INTERVAL: 86400
- CLOUDFLARE_API_TOKEN: "XXX"
- CLOUDFLARE_ZONE_ID: "XXX"
- MODE: "test"

There is a test mode which can be used to test the Discord connection.

Create a Bearer API Token with write authorization for the corresponding DNS zone. Together with the API zone ID, the corresponding entries can then be updated automatically


To start the container use this command or compose.

```
docker run -e DOMAIN="abc.de" -e TLSA_RECORD="_25._tcp" -e DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/1303443" -e CHECK_INTERVAL=21600 -e CLOUDFLARE_API_TOKEN="XXX" -e CLOUDFLARE_ZONE_ID="XXX" schefflerit/tlsa-checker:v2
```

```
version: '3.8'
services:
  tlsa_checker:
    image: schefflerit/tlsa-checker:v2
    container_name: TLSA-Checker_v2
    environment:
      DOMAIN: "sxxxx.de"
      TLSA_RECORDS: "_25._tcp,_143._tcp,_465._tcp"
      DISCORD_WEBHOOK_URL: "https://discord.com/api/webhooks/13034XXX"
      CHECK_INTERVAL: 21600
      CLOUDFLARE_API_TOKEN: "XXX"
      CLOUDFLARE_ZONE_ID: "XXX"
    restart: unless-stopped
```
