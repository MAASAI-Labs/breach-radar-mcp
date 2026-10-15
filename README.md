# Breach Radar (MCP server)

**Live MCP URL (Streamable HTTP):** `https://breach-radar-mcp.vercel.app/mcp`  
Health check: `https://breach-radar-mcp.vercel.app/health`

Breach Radar is security intelligence for Grok Bot (or any MCP client):

- **Have I Been Pwned**: the breach catalogue, breaches of a company/domain, email checks (with an optional API key), and **Pwned Passwords** via k-anonymity.
- **NIST NVD** CVE search and the **CISA Known Exploited Vulnerabilities** catalogue.
- A **passive** attack-surface report for a domain: security headers, TLS, SPF/DMARC/CAA/DNSSEC, Certificate Transparency subdomains, and HIBP breaches.

## Passive only, by design

Breach Radar **does not** scan ports, crawl, fuzz, brute-force subdomains, attempt logins, or send exploit or vulnerability probes. Its only contact with a target domain is:

1. **one HTTPS GET of `/`** (redirects followed, max 5), to read response headers
2. **one TLS handshake** on port 443, to read the certificate and protocol

Everything else comes from public third parties: DNS-over-HTTPS (Cloudflare), Certificate Transparency logs (crt.sh, with Cert Spotter as fallback), HIBP, NVD and CISA. Even so, only assess domains you own or are authorised to assess.

## Tools

| Tool | Key needed? | What it does |
|---|---|---|
| `breach_catalog` | no | Search HIBP breaches: recent, largest, or by keyword/data type |
| `breach_details` | no | One breach in full |
| `domain_breaches` | no | Breaches where this domain's service was breached |
| `email_breaches` | `HIBP_API_KEY` (optional) | Breaches containing an email. Without a key, it explains the alternatives and makes no request |
| `password_pwned` | no | Pwned Passwords k-anonymity. Only the first 5 hex chars of the SHA-1 are sent, with padding enabled. Never stored or echoed |
| `cve_search` | no (`NVD_API_KEY` optional) | NVD search by CVE id, keyword, severity, recency or KEV-only, with CVSS, CWE and KEV flag |
| `kev_lookup` | no | CISA KEV by CVE, vendor, keyword, recency or ransomware use, with the required action and federal due date |
| `security_headers` | no | Header grade A–F, weak values, and version leaks (1 GET) |
| `ct_subdomains` | no | Hostnames seen in CT logs |
| `attack_surface_report` | no | All passive checks in one report, with key findings |

## Example prompts

- "Has my password 'Summer2024!' been leaked?" (only a hash prefix leaves the server)
- "What are the biggest breaches added to HIBP recently?" / "Was Canva ever breached?"
- "Which vulnerabilities did CISA add to KEV this week? Any Ivanti ones?"
- "Find critical OpenSSL CVEs from the last 90 days."
- "Run a passive security check on mycompany.com."

## Configuration (optional)

- `HIBP_API_KEY` enables `email_breaches`. HIBP keys are paid.
- `NVD_API_KEY` raises NVD's keyless limit (about 5 requests per 30 s) to 50.

## Caching and limits

- **HIBP catalogue, KEV and Pwned Passwords ranges**: 6 h.
- **NVD**: 15 min.
- **Email lookups**: 15 min, in memory only.
- **DNS**: 5 min.
- **CT**: 6 h. crt.sh is often slow; after a 15 s timeout it falls back to Cert Spotter's free tier.
- **Errors**: a 429 is retried once. Upstream failures in the combined report show as "unavailable" rather than failing the whole report.

## Run locally

```bash
npm install && npm test && npm run build
npm start             # http://localhost:3000/mcp
npm run start:stdio
npm run smoke         # live calls to every tool
```

## Deploy to Vercel

1. Push to GitHub and import it at vercel.com/new (preset: Other).
2. Optionally add `HIBP_API_KEY` and `NVD_API_KEY` as environment variables.
3. The MCP URL is `https://<project>.vercel.app/mcp`.

The TLS check needs outbound TCP 443, which Vercel Node functions allow.

## Testing instructions for marketplace reviewers

No credentials needed. Email lookups show a clear "needs HIBP_API_KEY" message.

1. List tools. You should see 10, and none of them scan, fuzz or brute-force.
2. `password_pwned` with `{"password": "password123"}`: found about 2 million times. The output shows only the 5-char prefix that was sent.
3. `breach_catalog` with `{"sort": "largest", "limit": 5}` and `domain_breaches` with `{"domain": "linkedin.com"}`.
4. `cve_search` with `{"cveId": "CVE-2024-3094"}` (the xz backdoor, CVSS 10) and `kev_lookup` with `{"lastDays": 14}`.
5. `attack_surface_report` with `{"domain": "github.com"}`: headers grade, TLS, SPF/DMARC/CAA/DNSSEC, CT names and breaches.
6. `email_breaches` with `{"email": "test@example.com"}` (no key): a graceful explanation.

## Attribution

- Breach data: [Have I Been Pwned](https://haveibeenpwned.com), CC BY 4.0.
- CVE data: [NIST NVD](https://nvd.nist.gov). This product uses data from the NVD API but is not endorsed or certified by the NVD.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- CT: [crt.sh](https://crt.sh) and [Cert Spotter](https://sslmate.com/certspotter/).

## License

MIT
