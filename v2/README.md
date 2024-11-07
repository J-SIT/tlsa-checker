

Create a Bearer API Token with write authorization for the corresponding DNS zone. Together with the API zone ID, the corresponding entries can then be updated automatically

```
docker run -e DOMAIN="abc.de" -e TLSA_RECORD="_25._tcp" -e DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/1303443" -e CHECK_INTERVAL=86400 -e CLOUDFLARE_API_TOKEN="XXX" -e CLOUDFLARE_ZONE_ID="XXX" schefflerit/tlsa-checker:v2
```

```
version: '3.8'
services:
  tlsa_checker:
    image: tlsa-checker-v2
    container_name: TLSA-Checker_v2
    environment:
      DOMAIN: "sxxxx.de"
      TLSA_RECORDS: "_25._tcp,_143._tcp,_465._tcp"
      DISCORD_WEBHOOK_URL: "https://discord.com/api/webhooks/13034XXX"
      CHECK_INTERVAL: 86400
      CLOUDFLARE_API_TOKEN: "XXX"
      CLOUDFLARE_ZONE_ID: "XXX"
    restart: unless-stopped
```