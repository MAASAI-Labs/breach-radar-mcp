import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as S from "./security.js";

const run = (fn: (a: any) => Promise<{ markdown: string } & Record<string, unknown>>) => async (a: any) => {
  try { const r = await fn(a); return { content: [{ type: "text" as const, text: r.markdown }, { type: "text" as const, text: "```json\n" + JSON.stringify({ ...r, markdown: undefined }, null, 2) + "\n```" }] }; }
  catch (e) { return { isError: true, content: [{ type: "text" as const, text: (e as Error).message }] }; }
};
const n = (x: number) => x.toLocaleString("en-US");
const src = (label: string, url: string, at: string) => `_Source: ${label} (${url}), fetched ${at}._`;
const HIBP_ATTR = "Breach data: Have I Been Pwned (haveibeenpwned.com), CC BY 4.0.";
const esc = (s: string) => (s ?? "").replace(/\|/g, "\\|").replace(/\s+/g, " ");
const breachTable = (bs: ReturnType<typeof S.mapBreach>[]) => `| Breach | Breach date | Accounts | Data exposed | Verified |\n|---|---|---:|---|---|\n` + bs.map(b => `| [${esc(b.title)}](${b.url}) (${b.domain || "-"}) | ${b.breachDate} | ${n(b.accounts)} | ${b.dataClasses.slice(0, 5).join(", ")}${b.dataClasses.length > 5 ? "…" : ""} | ${b.verified ? "yes" : b.fabricated ? "fabricated" : "no"} |`).join("\n");

export const PASSIVE_NOTE = "Passive checks only: one HTTPS GET to the site root, one TLS handshake, public DNS queries via DNS-over-HTTPS, and public Certificate Transparency logs. No port scanning, crawling, fuzzing, login attempts or vulnerability probing.";

export function createServer() {
  const server = new McpServer({ name: "breach-radar-mcp", version: "1.0.0" });
  const ro = { readOnlyHint: true, openWorldHint: true };

  server.registerTool("breach_catalog", { title: "Breach catalogue (HIBP)", annotations: ro,
    description: "Search the Have I Been Pwned breach catalogue (no key needed): most recent, largest, or by keyword/data type (e.g. 'passwords', 'crypto', 'health').",
    inputSchema: { search: z.string().max(80).optional(), sort: z.enum(["recent", "largest", "breachDate"]).optional(), limit: z.number().int().min(1).max(50).optional(), includeSensitive: z.boolean().optional() } },
    run(async a => { const r = await S.breachCatalog(a); return { ...r, markdown: `## HIBP breaches${a.search ? ` matching "${a.search}"` : ""} (${a.sort ?? "recently added"}): ${n(r.matches)} of ${n(r.total)}\n\n${breachTable(r.breaches)}\n\n${src("HIBP API v3", r.source, r.fetchedAt)} ${HIBP_ATTR}` }; }));

  server.registerTool("breach_details", { title: "Breach details", annotations: ro,
    description: "Full details of one HIBP breach by name (e.g. 'Adobe', 'LinkedIn').",
    inputSchema: { name: z.string().min(1).max(80) } },
    run(async a => { const r = await S.breachByName(a.name); const b = r.breach; return { ...r, markdown: `## ${b.title}\n\n- Domain: ${b.domain || "-"}\n- Breach date: ${b.breachDate} (added to HIBP ${b.addedDate.slice(0, 10)})\n- Accounts: **${n(b.accounts)}**\n- Data exposed: ${b.dataClasses.join(", ")}\n- Verified: ${b.verified ? "yes" : "no"}${b.sensitive ? " · sensitive" : ""}${b.spamList ? " · spam list" : ""}\n\n${b.summary}\n\n[HIBP page](${b.url})\n\n${src("HIBP API v3", r.source, r.fetchedAt)} ${HIBP_ATTR}` }; }));

  server.registerTool("domain_breaches", { title: "Breaches of a company/site", annotations: ro,
    description: "Breaches in HIBP where the breached service is this domain (no key needed). Does not list individual addresses.",
    inputSchema: { domain: z.string().min(3).max(253) } },
    run(async a => { const r = await S.breachesForDomain(a.domain); return { ...r, markdown: `## Breaches of ${r.domain}\n\n${r.breaches.length ? breachTable(r.breaches) : "No breaches of this service are listed in HIBP."}\n\n${src("HIBP API v3", r.source, r.fetchedAt)} ${HIBP_ATTR}` }; }));

  server.registerTool("email_breaches", { title: "Breaches for an email (needs HIBP key)", annotations: ro,
    description: "Breaches containing an email address. Requires the server operator to set HIBP_API_KEY; otherwise explains alternatives. Only check addresses the user owns or is authorised to check.",
    inputSchema: { email: z.string().email() } },
    run(async a => {
      const r = await S.breachesForEmail(a.email);
      if (!r.configured) return { ...r, markdown: `## Email breach check unavailable\n\n${r.message}` };
      return { ...r, markdown: `## ${r.email}: found in ${r.breaches.length} breach${r.breaches.length === 1 ? "" : "es"}\n\n${r.breaches.length ? breachTable(r.breaches) + "\n\nChange passwords for these services (and anywhere they were reused), and turn on 2FA." : "Good news: not found in any HIBP breach."}\n\n${src("HIBP API v3", r.source, r.fetchedAt!)} ${HIBP_ATTR}` };
    }));

  server.registerTool("password_pwned", { title: "Pwned Passwords (k-anonymity)", annotations: { ...ro, idempotentHint: true },
    description: "Check if a password appears in known breaches using HIBP Pwned Passwords k-anonymity: the password is SHA-1 hashed locally and only the first 5 hex characters are sent. Accepts the password or its SHA-1. The password is never stored, logged or echoed.",
    inputSchema: { password: z.string().min(1).max(256).optional(), sha1: z.string().regex(/^[0-9a-fA-F]{40}$/).optional() } },
    run(async a => { const r = await S.pwnedPassword(a); return { ...r, markdown: r.pwned ? `## ⚠️ This password has appeared in breaches **${n(r.count)} times**\n\nDon't use it anywhere. Pick a long unique passphrase and use a password manager.\n\nPrivacy: only the hash prefix \`${r.prefixSent}\` was sent (k-anonymity); the password never left this server.\n\n${src("HIBP Pwned Passwords", r.source, r.fetchedAt)}` : `## ✅ Not found in Pwned Passwords\n\nThat doesn't make it strong: use a long, unique passphrase.\n\nPrivacy: only the hash prefix \`${r.prefixSent}\` was sent (k-anonymity).\n\n${src("HIBP Pwned Passwords", r.source, r.fetchedAt)}` }; }));

  server.registerTool("cve_search", { title: "CVE search (NVD)", annotations: ro,
    description: "Search the NIST National Vulnerability Database: by CVE id, keyword (product/vendor), severity, recency, or KEV-listed only. Returns CVSS, CWE and KEV status. Keyless (rate-limited); optional NVD_API_KEY raises limits.",
    inputSchema: { cveId: z.string().optional(), keyword: z.string().max(80).optional(), severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(), lastDays: z.number().int().min(1).max(120).optional(), kevOnly: z.boolean().optional(), limit: z.number().int().min(1).max(30).optional() } },
    run(async a => { const r = await S.cveSearch(a);
      const md = `## CVEs${a.cveId ? ` ${a.cveId}` : a.keyword ? ` matching "${a.keyword}"` : ""}${a.severity ? ` (${a.severity})` : ""}${a.lastDays ? `, last ${a.lastDays} days` : ""}: ${n(r.total)} total, top ${r.cves.length} by CVSS\n\n| CVE | CVSS | Published | KEV | Summary |\n|---|---:|---|---|---|\n` + r.cves.map((c: any) => `| [${c.id}](${c.url}) | ${c.cvss ? `${c.cvss.score} ${c.cvss.severity ?? ""} (v${c.cvss.version})` : "n/a"} | ${c.published.slice(0, 10)} | ${c.inKev ? "⚠️ yes" : "-"} | ${esc(c.description.slice(0, 160))}${c.description.length > 160 ? "…" : ""} |`).join("\n") + `\n\n${src("NIST NVD CVE API 2.0", r.source, r.fetchedAt)}`;
      return { ...r, markdown: md }; }));

  server.registerTool("kev_lookup", { title: "CISA Known Exploited Vulnerabilities", annotations: ro,
    description: "Search the CISA KEV catalogue (vulnerabilities exploited in the wild): by CVE, vendor, keyword, recency, or ransomware use. Includes CISA's required action and due date.",
    inputSchema: { cveId: z.string().optional(), vendor: z.string().max(60).optional(), query: z.string().max(80).optional(), lastDays: z.number().int().min(1).max(365).optional(), ransomwareOnly: z.boolean().optional(), limit: z.number().int().min(1).max(50).optional() } },
    run(async a => { const r = await S.kevSearch(a);
      const md = `## CISA KEV: ${n(r.matches)} match${r.matches === 1 ? "" : "es"} (catalogue v${r.catalogVersion}, ${n(r.totalInCatalog)} entries)\n\n| CVE | Vendor / product | Vulnerability | Added | Fed. due date | Ransomware |\n|---|---|---|---|---|---|\n` + r.items.map(i => `| [${i.cve}](${i.url}) | ${esc(i.vendor)} ${esc(i.product)} | ${esc(i.name)} | ${i.dateAdded} | ${i.dueDate} | ${i.ransomware === "Known" ? "⚠️ known" : "-"} |`).join("\n") + `\n\n${src("CISA KEV JSON feed", r.source, r.fetchedAt)}`;
      return { ...r, markdown: md }; }));

  server.registerTool("security_headers", { title: "HTTP security headers (1 GET)", annotations: ro,
    description: "Grade a site's HTTP security headers from a single GET of its homepage (HSTS, CSP, X-Content-Type-Options, frame protection, Referrer-Policy, Permissions-Policy, COOP) and flag version-leaking headers. Passive.",
    inputSchema: { domain: z.string().min(3).max(253) } },
    run(async a => { const r = await S.securityHeaders(a.domain);
      const md = `## Security headers for ${r.domain}: grade **${r.grade}**\n\nFinal URL: ${r.finalUrl} (HTTP ${r.status})\n\n| Header | Present | Note |\n|---|---|---|\n` + r.headers.map(h => `| ${h.header} | ${h.present ? (h.issue ? "⚠️" : "✅") : "❌"} | ${h.issue ?? (h.present ? "" : h.why)} |`).join("\n") + (r.infoLeaks.length ? `\n\nVersion/info leaks: ${r.infoLeaks.join("; ")}` : "") + `\n\n_${PASSIVE_NOTE} Checked ${r.checkedAt}._`;
      return { ...r, markdown: md }; }));

  server.registerTool("attack_surface_report", { title: "Passive attack-surface report", annotations: ro,
    description: "One passive report for a domain the user owns or is authorised to assess: security headers (1 GET), TLS certificate/protocol, SPF/DMARC/CAA/DNSSEC, Certificate Transparency subdomains, and HIBP breaches of the domain. No scanning or probing.",
    inputSchema: { domain: z.string().min(3).max(253), maxSubdomains: z.number().int().min(1).max(500).optional() } },
    run(async a => {
      const d = S.normaliseDomain(a.domain);
      const [hdr, tlsR, dns, ct, br] = await Promise.allSettled([S.securityHeaders(d), S.tlsInfo(d), S.dnsSecurity(d), S.ctSubdomains(d, a.maxSubdomains ?? 50), S.breachesForDomain(d)]);
      const v = <T,>(p: PromiseSettledResult<T>) => (p.status === "fulfilled" ? p.value : null);
      const err = (p: PromiseSettledResult<unknown>) => (p.status === "rejected" ? `unavailable (${(p.reason as Error).message})` : "");
      const H = v(hdr), T = v(tlsR), D = v(dns), C = v(ct), B = v(br);
      const findings: string[] = [];
      if (H && "FD".includes(H.grade)) findings.push(`Weak HTTP security headers (grade ${H.grade})`);
      if (T && !T.trusted) findings.push(`TLS certificate not trusted: ${T.trustError}`);
      if (T && T.daysLeft !== null && T.daysLeft < 14) findings.push(`TLS certificate expires in ${T.daysLeft} days`);
      if (T && /TLSv1(\.0|\.1)?$/.test(T.protocol ?? "")) findings.push(`Old TLS protocol negotiated (${T.protocol})`);
      if (D && /missing|DANGEROUS|weak/.test(D.spfAssessment)) findings.push(`SPF ${D.spfAssessment}`);
      if (D && /missing|monitoring/.test(D.dmarcAssessment)) findings.push(`DMARC ${D.dmarcAssessment}`);
      if (D && !D.dnssec.signed) findings.push("DNSSEC not enabled");
      if (D && !D.caa.length) findings.push("No CAA record");
      if (B && B.breaches.length) findings.push(`${B.breaches.length} known breach(es) of this service in HIBP`);
      let md = `# Passive attack-surface report: ${d}\n\n## Key findings\n${findings.length ? findings.map(f => `- ${f}`).join("\n") : "- No notable issues found by these passive checks."}\n\n`;
      md += `## Web\n${H ? `- Security headers grade **${H.grade}** (${H.headers.filter(h => !h.present).map(h => h.header).join(", ") || "all present"} missing)${H.infoLeaks.length ? `; leaks: ${H.infoLeaks.join(", ")}` : ""}` : `- Headers ${err(hdr)}`}\n${T ? `- TLS: ${T.protocol}, ${T.cipher}; cert by ${T.issuer}, ${T.daysLeft} days left, ${T.trusted ? "trusted" : "NOT trusted"}` : `- TLS ${err(tlsR)}`}\n\n`;
      md += `## DNS & email\n${D ? `- SPF: ${D.spfAssessment}\n- DMARC: ${D.dmarcAssessment}\n- CAA: ${D.caaAssessment}\n- DNSSEC: ${D.dnssec.signed ? `signed${D.dnssec.validated ? " and validated" : ""}` : "not enabled"}\n- MX: ${D.mx.join(", ") || "none"}` : `- ${err(dns)}`}\n\n`;
      md += `## Certificate Transparency\n${C ? `- ${C.count} names seen in CT logs${C.truncated ? ` (showing ${C.subdomains.length})` : ""}: ${C.subdomains.slice(0, 30).join(", ")}${C.subdomains.length > 30 ? "…" : ""}\n- Source: ${C.source}` : `- ${err(ct)}`}\n\n`;
      md += `## Breaches\n${B ? (B.breaches.length ? B.breaches.map(b => `- ${b.title} (${b.breachDate}): ${n(b.accounts)} accounts, ${b.dataClasses.slice(0, 4).join(", ")}`).join("\n") : "- None listed in HIBP.") : `- ${err(br)}`}\n\n_${PASSIVE_NOTE} Generated ${new Date().toISOString()}. Sources: HIBP, Cloudflare DoH, ${C?.source ?? "crt.sh"}, direct TLS/HTTPS to ${d}._`;
      return { domain: d, findings, headers: H, tls: T, dns: D, ct: C, breaches: B?.breaches ?? null, markdown: md };
    }));

  server.registerTool("ct_subdomains", { title: "Subdomains from Certificate Transparency", annotations: ro,
    description: "Hostnames for a domain seen in public Certificate Transparency logs (crt.sh, Cert Spotter fallback). Passive: no DNS brute force.",
    inputSchema: { domain: z.string().min(3).max(253), limit: z.number().int().min(1).max(1000).optional() } },
    run(async a => { const r = await S.ctSubdomains(a.domain, a.limit ?? 200);
      return { ...r, markdown: `## ${r.count} names for ${r.domain} in CT logs\n\n${r.subdomains.map(s => `- ${s}`).join("\n")}${r.truncated ? `\n- … (${r.count - r.subdomains.length} more)` : ""}\n\n${r.errors.length ? `> ${r.errors.join("; ")}\n\n` : ""}_Source: ${r.source}, fetched ${r.fetchedAt}._` }; }));
  return server;
}
