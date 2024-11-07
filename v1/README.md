This project is about being automatically notified when a certificate and a DANE TLSA record no longer match. This happens, for example, when certificates are used via Lets Encrypt and auto renewal. 
A notification is sent via a Discord WebHook. <br>

GitHub project: https://github.com/J-SIT/tlsa-checker/

The following can be set via the environment variables:
- DOMAIN="abc.de”
- TLSA_RECORD="_25._tcp”
- DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/130...”
- CHECK_INTERVAL=86400
- MODE="test”

There is a test mode which can be used to test the Discord connection.


To start the container use this command or compose.

```
docker run -e DOMAIN="abc.de" -e TLSA_RECORD="_25._tcp" -e DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/1303443" -e CHECK_INTERVAL=86400 schefflerit/tlsa-checker:latest
```

```
version: '3.8'
services:
  tlsa_checker:
    image: schefflerit/tlsa-checker:latest
    container_name: TLSA-Checker
    environment:
      - DOMAIN=abc.de
      - TLSA_RECORD=_25._tcp
      - DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1303443
      - CHECK_INTERVAL=86400
    restart: unless-stopped
```