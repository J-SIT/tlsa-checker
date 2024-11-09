# tlsa-checker
Automatically notification when a certificate and a DANE TLSA record no longer match. <br>
Reference see here: https://hub.docker.com/r/schefflerit/tlsa-checker

<br>
In the first version (v1), the container can only monitor one TLSA record and automatically send a message to a Discord WebHook.

<br>
<br>
In the second version (v2), it should be possible to check several TLSA records and also update them automatically (there is of course still a notification via Discord WebHook). However, this is only possible with Cloudflare as a public DNS provider.

<br>
<br>

Version 1 is already functional, version 2 is now out of beta state.
