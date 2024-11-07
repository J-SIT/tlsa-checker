




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
      CLOUDFLARE_EMAIL: "abc@def.de"
      CLOUDFLARE_API_KEY: "XXX"
      CLOUDFLARE_ZONE_ID: "XXX"
    restart: unless-stopped
```