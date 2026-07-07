
Step 1 — Baseline (confirms block is active)

curl -I https://claude.ai
curl -I https://api.anthropic.com
→ Check Monitor > Logs > URL Filtering for these two. Note the Action and Category shown. This is your control baseline.

Step 2 — DoH via curl, Cloudflare resolver

curl --doh-url https://cloudflare-dns.com/dns-query -I https://claude.ai
→ Check Monitor > Logs > Traffic. Look at the App column specifically — does it say dns-over-https, ssl, or something else? Note Action (allow/deny).

Step 3 — DoH via curl, Google resolver

curl --doh-url https://dns.google/dns-query -I https://claude.ai
→ Same log check.

Step 4 — System-wide DoH (Windows native)

powershell
Get-DnsClientDohServerAddress
Set-DnsClientDohServerAddress -ServerAddress 1.1.1.1 -DohTemplate "https://cloudflare-dns.com/dns-query" -AllowFallbackToUdp $false
ipconfig /flushdns
curl -I https://claude.ai
→ Check both URL Filtering and Traffic logs. Then revert:

powershell
Set-DnsClientDohServerAddress -ServerAddress 1.1.1.1 -DohTemplate "https://cloudflare-dns.com/dns-query" -AllowFallbackToUdp $true
ipconfig /flushdns
Step 5 — IP-literal request

nslookup claude.ai 1.1.1.1
Take the IP it returns, then:

curl -I https://<IP-from-above> -H "Host: claude.ai" -k
→ Check if URL Filtering even logs this differently (IP-based category lookup vs hostname-based).

Step 6 — ECH (browser-based)
In Chrome: go to chrome://flags/#encrypted-client-hello, set to Enabled, relaunch. Visit claude.ai. Then check:

chrome://net-internals/#events
filter for ECH to see if it negotiated. Cross-check against your Palo Alto logs for the same timestamp.
