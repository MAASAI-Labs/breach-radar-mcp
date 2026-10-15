import crypto from "node:crypto";
import tls from "node:tls";
import { cachedFetch } from "./cache.js";

export const HIBP = "https://haveibeenpwned.com/api/v3";
export const PWNED = "https://api.pwnedpasswords.com/range";
export const NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
export const KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const DOH = "https://cloudflare-dns.com/dns-query";
const H6 = 6 * 3600_000;

export function normaliseDomain(input: string) {
  const d = input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[/?#].*$/, "").replace(/\.$/, "");
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(d)) throw new Error(`"${input}" is not a valid domain name.`);
  return d;
}
const strip = (h: string) => (h ?? "").replace(/<[^>]+>/g, "").replace(/&quot;/g, '"').replace(/&amp;/g, "&").replace(/\s+/g, " ").trim();

// ---------- HIBP ----------
export interface Breach { Name: string; Title: string; Domain: string; BreachDate: string; AddedDate: string; PwnCount: number; Description: string; DataClasses: string[]; IsVerified: boolean; IsSensitive: boolean; IsSpamList: boolean; IsFabricated: boolean; IsMalware?: boolean }
export const mapBreach = (b: Breach) => ({ name: b.Name, title: b.Title, domain: b.Domain, breachDate: b.BreachDate, addedDate: b.AddedDate, accounts: b.PwnCount, dataClasses: b.DataClasses, verified: b.IsVerified, sensitive: b.IsSensitive, spamList: b.IsSpamList, fabricated: b.IsFabricated, summary: strip(b.Description).slice(0, 400), url: `https://haveibeenpwned.com/Breach/${b.Name}` });

export async function breachCatalog(o: { search?: string; sort?: "recent" | "largest" | "breachDate"; limit?: number; includeSensitive?: boolean }) {
  const f = await cachedFetch<Breach[]>(`${HIBP}/breaches`, H6);
  let list = f.data.map(mapBreach);
  if (!o.includeSensitive) list = list.filter(b => !b.sensitive);
  if (o.search) { const q = o.search.toLowerCase(); list = list.filter(b => `${b.name} ${b.title} ${b.domain} ${b.dataClasses.join(" ")}`.toLowerCase().includes(q)); }
  const sort = o.sort ?? "recent";
  list.sort((a, b) => sort === "largest" ? b.accounts - a.accounts : sort === "breachDate" ? b.breachDate.localeCompare(a.breachDate) : b.addedDate.localeCompare(a.addedDate));
  return { total: f.data.length, matches: list.length, breaches: list.slice(0, o.limit ?? 10), fetchedAt: f.fetchedAt, source: f.source };
}
export async function breachByName(name: string) {
  const f = await cachedFetch<any>(`${HIBP}/breach/${encodeURIComponent(name)}`, H6, { allow404: true });
  if (f.data?.__notFound) throw new Error(`No HIBP breach named "${name}". Use breach_catalog to search names.`);
  return { breach: mapBreach(f.data), fetchedAt: f.fetchedAt, source: f.source };
}
export async function breachesForDomain(domain: string) {
  const d = normaliseDomain(domain);
  const f = await cachedFetch<Breach[]>(`${HIBP}/breaches?domain=${encodeURIComponent(d)}`, H6);
  return { domain: d, breaches: f.data.map(mapBreach), fetchedAt: f.fetchedAt, source: f.source.split("?")[0] };
}
export async function breachesForEmail(email: string, apiKey = process.env.HIBP_API_KEY) {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("That doesn't look like an email address.");
  if (!apiKey) return { configured: false as const, email, breaches: [] as ReturnType<typeof mapBreach>[], message: "Email breach lookups need a Have I Been Pwned API key (paid, from https://haveibeenpwned.com/API/Key), set as HIBP_API_KEY on this server. Without a key you can still: check the address yourself at https://haveibeenpwned.com, look up breaches affecting the email's domain (domain_breaches), and check passwords with password_pwned." };
  const f = await cachedFetch<any>(`${HIBP}/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, 15 * 60_000, { allow404: true, headers: { "hibp-api-key": apiKey } });
  const list: Breach[] = f.data?.__notFound ? [] : f.data;
  return { configured: true as const, email, breaches: list.map(mapBreach), fetchedAt: f.fetchedAt, source: `${HIBP}/breachedaccount` };
}

/** Pwned Passwords k-anonymity: only the first 5 hex chars of the SHA-1 leave this server. */
export function sha1Upper(s: string) { return crypto.createHash("sha1").update(s, "utf8").digest("hex").toUpperCase(); }
export async function pwnedPassword(o: { password?: string; sha1?: string }) {
  const hash = o.sha1 ? o.sha1.toUpperCase() : o.password !== undefined ? sha1Upper(o.password) : "";
  if (!/^[0-9A-F]{40}$/.test(hash)) throw new Error("Provide `password` or a 40-character SHA-1 hex `sha1`.");
  const prefix = hash.slice(0, 5), suffix = hash.slice(5);
  const f = await cachedFetch<string>(`${PWNED}/${prefix}`, H6, { text: true, headers: { "Add-Padding": "true" } });
  let count = 0;
  for (const line of f.data.split(/\r?\n/)) { const [suf, c] = line.trim().split(":"); if (suf === suffix) { count = Number(c); break; } }
  return { pwned: count > 0, count, prefixSent: prefix, fetchedAt: f.fetchedAt, source: `${PWNED}/{first 5 of SHA-1}` };
}

// ---------- NVD / KEV ----------
export function mapCve(v: any) {
  const c = v.cve; const m = c.metrics ?? {};
  const pick = m.cvssMetricV40?.[0] ?? m.cvssMetricV31?.[0] ?? m.cvssMetricV30?.[0] ?? m.cvssMetricV2?.[0];
  const d = pick?.cvssData;
  return { id: c.id, published: c.published, lastModified: c.lastModified, status: c.vulnStatus, description: c.descriptions?.find((x: any) => x.lang === "en")?.value ?? "",
    cvss: d ? { version: d.version, score: d.baseScore, severity: d.baseSeverity ?? pick.baseSeverity, vector: d.vectorString } : null,
    cwe: c.weaknesses?.flatMap((w: any) => w.description.map((x: any) => x.value)).filter((x: string) => x.startsWith("CWE")) ?? [],
    inKev: !!c.cisaExploitAdd, kevAdded: c.cisaExploitAdd ?? null, url: `https://nvd.nist.gov/vuln/detail/${c.id}` };
}
export async function cveSearch(o: { cveId?: string; keyword?: string; severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; lastDays?: number; limit?: number; kevOnly?: boolean }) {
  const q = new URLSearchParams();
  if (o.cveId) { if (!/^CVE-\d{4}-\d{4,}$/i.test(o.cveId)) throw new Error("cveId must look like CVE-2024-3094."); q.set("cveId", o.cveId.toUpperCase()); }
  else {
    if (o.keyword) q.set("keywordSearch", o.keyword);
    if (o.severity) q.set("cvssV3Severity", o.severity);
    if (o.kevOnly) q.set("hasKev", "");
    const days = Math.min(o.lastDays ?? (o.keyword ? 0 : 30), 120);
    if (days) { const end = new Date(); const start = new Date(end.getTime() - days * 86400_000); q.set("pubStartDate", start.toISOString().replace("Z", "")); q.set("pubEndDate", end.toISOString().replace("Z", "")); }
    q.set("resultsPerPage", "2000");
  }
  const key = process.env.NVD_API_KEY;
  const f = await cachedFetch<any>(`${NVD}?${q.toString().replace("hasKev=", "hasKev")}`, 15 * 60_000, key ? { headers: { apiKey: key } } : {});
  const all = (f.data.vulnerabilities ?? []).map(mapCve);
  all.sort((a: any, b: any) => (b.cvss?.score ?? 0) - (a.cvss?.score ?? 0) || b.published.localeCompare(a.published));
  return { total: f.data.totalResults, cves: all.slice(0, o.limit ?? 10), fetchedAt: f.fetchedAt, source: NVD };
}
export async function kevSearch(o: { query?: string; cveId?: string; vendor?: string; lastDays?: number; ransomwareOnly?: boolean; limit?: number }) {
  const f = await cachedFetch<any>(KEV, H6);
  let v: any[] = f.data.vulnerabilities;
  if (o.cveId) v = v.filter(x => x.cveID.toUpperCase() === o.cveId!.toUpperCase());
  if (o.vendor) v = v.filter(x => x.vendorProject.toLowerCase().includes(o.vendor!.toLowerCase()));
  if (o.query) { const q = o.query.toLowerCase(); v = v.filter(x => `${x.vendorProject} ${x.product} ${x.vulnerabilityName} ${x.shortDescription}`.toLowerCase().includes(q)); }
  if (o.lastDays) { const c = new Date(Date.now() - o.lastDays * 86400_000).toISOString().slice(0, 10); v = v.filter(x => x.dateAdded >= c); }
  if (o.ransomwareOnly) v = v.filter(x => x.knownRansomwareCampaignUse === "Known");
  v = [...v].sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));
  return { catalogVersion: f.data.catalogVersion, catalogReleased: f.data.dateReleased, totalInCatalog: f.data.count, matches: v.length,
    items: v.slice(0, o.limit ?? 15).map(x => ({ cve: x.cveID, vendor: x.vendorProject, product: x.product, name: x.vulnerabilityName, dateAdded: x.dateAdded, dueDate: x.dueDate, ransomware: x.knownRansomwareCampaignUse, action: x.requiredAction, url: `https://nvd.nist.gov/vuln/detail/${x.cveID}` })),
    fetchedAt: f.fetchedAt, source: KEV };
}

// ---------- passive attack surface ----------
export const SECURITY_HEADERS: { name: string; why: string; check?: (v: string) => string | null }[] = [
  { name: "strict-transport-security", why: "Forces HTTPS (HSTS)", check: v => (Number(v.match(/max-age=(\d+)/i)?.[1] ?? 0) < 15552000 ? "max-age below 180 days" : null) },
  { name: "content-security-policy", why: "Mitigates XSS and injection", check: v => (/unsafe-inline|unsafe-eval/.test(v) ? "allows unsafe-inline/unsafe-eval" : null) },
  { name: "x-content-type-options", why: "Stops MIME sniffing", check: v => (v.toLowerCase() !== "nosniff" ? "should be 'nosniff'" : null) },
  { name: "x-frame-options", why: "Clickjacking protection (or CSP frame-ancestors)" },
  { name: "referrer-policy", why: "Limits referrer leakage" },
  { name: "permissions-policy", why: "Restricts powerful browser features" },
  { name: "cross-origin-opener-policy", why: "Isolates browsing context" },
];
export function gradeHeaders(h: Record<string, string>) {
  const res = SECURITY_HEADERS.map(s => {
    let present = h[s.name] !== undefined;
    if (s.name === "x-frame-options" && !present && /frame-ancestors/i.test(h["content-security-policy"] ?? "")) present = true;
    const issue = present && s.check && h[s.name] !== undefined ? s.check(h[s.name]) : null;
    return { header: s.name, present, value: h[s.name] ?? null, issue, why: s.why };
  });
  const score = res.reduce((a, r) => a + (r.present ? (r.issue ? 0.5 : 1) : 0), 0);
  const grade = score >= 6.5 ? "A" : score >= 5 ? "B" : score >= 3.5 ? "C" : score >= 2 ? "D" : "F";
  const leaks = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"].filter(k => h[k]).map(k => `${k}: ${h[k]}`);
  return { grade, score, headers: res, infoLeaks: leaks };
}
/** Exactly one GET to the site root (redirects followed, max 5). No other paths are requested. */
export async function securityHeaders(domain: string, fetchImpl: typeof fetch = fetch) {
  const d = normaliseDomain(domain);
  const res = await fetchImpl(`https://${d}/`, { method: "GET", redirect: "follow", headers: { "User-Agent": "breach-radar-mcp/1.0 (passive header check)" }, signal: AbortSignal.timeout(12000) });
  const h: Record<string, string> = {}; res.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
  try { await res.body?.cancel(); } catch { /* ignore */ }
  return { domain: d, finalUrl: res.url, status: res.status, ...gradeHeaders(h), checkedAt: new Date().toISOString() };
}
export function tlsInfo(domain: string): Promise<any> {
  const d = normaliseDomain(domain);
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host: d, port: 443, servername: d, rejectUnauthorized: false, timeout: 10000 }, () => {
      const c = s.getPeerCertificate(); const out = { domain: d, protocol: s.getProtocol(), cipher: s.getCipher()?.name, trusted: s.authorized, trustError: s.authorizationError ? String(s.authorizationError) : null,
        issuer: [c.issuer?.O, c.issuer?.CN].filter(Boolean).join(" / "), subject: c.subject?.CN, validTo: c.valid_to ? new Date(c.valid_to).toISOString() : null,
        daysLeft: c.valid_to ? Math.floor((new Date(c.valid_to).getTime() - Date.now()) / 86400_000) : null, sanCount: (c.subjectaltname ?? "").split(", ").filter(Boolean).length, checkedAt: new Date().toISOString() };
      s.end(); resolve(out);
    });
    s.on("timeout", () => { s.destroy(); reject(new Error(`TLS timeout for ${d}`)); });
    s.on("error", e => reject(new Error(`TLS to ${d} failed: ${e.message}`)));
  });
}
async function doh(name: string, type: string) {
  const f = await cachedFetch<any>(`${DOH}?name=${encodeURIComponent(name)}&type=${type}&do=1`, 5 * 60_000, { accept: "application/dns-json" });
  return { answers: (f.data.Answer ?? []).filter((a: any) => a.type !== 46).map((a: any) => String(a.data)), ad: !!f.data.AD, status: f.data.Status, fetchedAt: f.fetchedAt };
}
export function assessSpf(spf: string | null) {
  if (!spf) return "missing: anyone can spoof mail from this domain";
  if (/\+all\b/.test(spf)) return "DANGEROUS: '+all' authorises every sender";
  if (/\?all\b/.test(spf)) return "weak: '?all' (neutral)";
  if (/~all\b/.test(spf)) return "ok: '~all' softfail";
  if (/-all\b/.test(spf)) return "strong: '-all' hardfail";
  return "incomplete: no 'all' mechanism";
}
export function assessDmarc(d: string | null) {
  if (!d) return "missing: no DMARC policy";
  const p = d.match(/\bp=(\w+)/i)?.[1]?.toLowerCase();
  return p === "reject" ? "strong: p=reject" : p === "quarantine" ? "good: p=quarantine" : p === "none" ? "monitoring only: p=none (not enforced)" : "invalid policy";
}
export async function dnsSecurity(domain: string) {
  const d = normaliseDomain(domain);
  const [txt, dmarc, caa, mx, ds, a] = await Promise.all([doh(d, "TXT"), doh(`_dmarc.${d}`, "TXT"), doh(d, "CAA"), doh(d, "MX"), doh(d, "DS"), doh(d, "A")]);
  const unq = (s: string) => s.replace(/^"|"$/g, "").replace(/" "/g, "");
  const spf = txt.answers.map(unq).find((x: string) => /^v=spf1/i.test(x)) ?? null;
  const dm = dmarc.answers.map(unq).find((x: string) => /^v=DMARC1/i.test(x)) ?? null;
  return { domain: d, spf, spfAssessment: assessSpf(spf), dmarc: dm, dmarcAssessment: assessDmarc(dm), caa: caa.answers, caaAssessment: caa.answers.length ? "present: limits which CAs may issue certificates" : "missing: any CA may issue certificates",
    dnssec: { signed: ds.answers.length > 0, validated: a.ad }, mx: mx.answers, resolver: "Cloudflare DNS-over-HTTPS", fetchedAt: txt.fetchedAt };
}
export async function ctSubdomains(domain: string, limit = 200) {
  const d = normaliseDomain(domain);
  const names = new Set<string>(); let source = ""; let fetchedAt = ""; const errors: string[] = [];
  try {
    const f = await cachedFetch<any[]>(`https://crt.sh/?q=${encodeURIComponent("%." + d)}&output=json`, 6 * 3600_000);
    for (const r of f.data) for (const n of String(r.name_value).split(/\n/)) names.add(n.trim().toLowerCase());
    source = "crt.sh (Certificate Transparency)"; fetchedAt = f.fetchedAt;
  } catch (e) {
    errors.push(`crt.sh: ${(e as Error).message}`);
    const f = await cachedFetch<any[]>(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(d)}&include_subdomains=true&expand=dns_names`, 6 * 3600_000);
    for (const r of f.data) for (const n of r.dns_names ?? []) names.add(String(n).toLowerCase());
    source = "SSLMate Cert Spotter (Certificate Transparency; free tier, recent issuances only)"; fetchedAt = f.fetchedAt;
  }
  const subs = [...names].filter(n => n === d || n.endsWith("." + d)).map(n => n.replace(/^\*\./, "*.")).sort();
  const wildcard = subs.filter(s => s.startsWith("*."));
  return { domain: d, count: subs.length, subdomains: subs.slice(0, limit), wildcards: wildcard, truncated: subs.length > limit, source, fetchedAt, errors };
}
