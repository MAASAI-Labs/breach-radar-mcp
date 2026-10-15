import { describe, it, expect, vi, afterEach } from "vitest";
import * as S from "../src/security";
import { clearCache } from "../src/cache";
import { createServer } from "../src/server";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

afterEach(() => { vi.restoreAllMocks(); clearCache(); delete process.env.HIBP_API_KEY; });
const breach = { Name: "Adobe", Title: "Adobe", Domain: "adobe.com", BreachDate: "2013-10-04", AddedDate: "2013-12-04T00:00:00Z", PwnCount: 152445165, Description: "In <a href='x'>October 2013</a> ...", DataClasses: ["Email addresses", "Passwords"], IsVerified: true, IsSensitive: false, IsSpamList: false, IsFabricated: false };

describe("Pwned Passwords k-anonymity", () => {
  it("sends only the 5-char SHA-1 prefix and matches the suffix", async () => {
    const hash = S.sha1Upper("password"); // 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    expect(hash).toBe("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(`0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n${hash.slice(5)}:9545824\r\n`));
    const r = await S.pwnedPassword({ password: "password" });
    expect(r).toMatchObject({ pwned: true, count: 9545824, prefixSent: "5BAA6" });
    const url = String(spy.mock.calls[0][0]);
    expect(url).toBe("https://api.pwnedpasswords.com/range/5BAA6");
    expect(url.split("/range/")[1]).toBe("5BAA6");
    expect((spy.mock.calls[0][1] as any).headers["Add-Padding"]).toBe("true");
  });
  it("rejects malformed SHA-1", async () => { await expect(S.pwnedPassword({ sha1: "abc" })).rejects.toThrow(/40-character/); });
});

describe("HIBP", () => {
  it("maps breaches and strips HTML", () => {
    const b = S.mapBreach(breach as any);
    expect(b).toMatchObject({ name: "Adobe", accounts: 152445165, url: "https://haveibeenpwned.com/Breach/Adobe" });
    expect(b.summary).toBe("In October 2013 ...");
  });
  it("email lookup degrades gracefully without a key and makes no request", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    const r = await S.breachesForEmail("a@b.com", undefined);
    expect(r.configured).toBe(false); expect(r.message).toMatch(/HIBP_API_KEY/); expect(spy).not.toHaveBeenCalled();
  });
  it("email lookup with a key sends hibp-api-key and treats 404 as clean", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("", { status: 404 }));
    const r = await S.breachesForEmail("clean@example.com", "KEY123");
    expect(r).toMatchObject({ configured: true, breaches: [] });
    expect((spy.mock.calls[0][1] as any).headers["hibp-api-key"]).toBe("KEY123");
  });
});

describe("NVD / KEV", () => {
  it("prefers CVSS v4/v3.1 and flags KEV", () => {
    const c = S.mapCve({ cve: { id: "CVE-2024-3094", published: "2024-03-29", lastModified: "x", vulnStatus: "Analyzed", cisaExploitAdd: "2024-04-01", descriptions: [{ lang: "en", value: "xz backdoor" }],
      metrics: { cvssMetricV31: [{ cvssData: { version: "3.1", baseScore: 10, baseSeverity: "CRITICAL", vectorString: "AV:N" } }], cvssMetricV2: [{ cvssData: { version: "2.0", baseScore: 7.5 } }] }, weaknesses: [{ description: [{ value: "CWE-506" }] }] } });
    expect(c.cvss).toMatchObject({ version: "3.1", score: 10 }); expect(c.inKev).toBe(true); expect(c.cwe).toEqual(["CWE-506"]);
  });
  it("rejects bad CVE ids before any request", async () => { await expect(S.cveSearch({ cveId: "2024-1" })).rejects.toThrow(/CVE-2024-3094/); });
  it("filters KEV by vendor, recency and ransomware", async () => {
    const today = new Date().toISOString().slice(0, 10);
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ catalogVersion: "1", dateReleased: today, count: 3, vulnerabilities: [
      { cveID: "CVE-1", vendorProject: "Ivanti", product: "Connect Secure", vulnerabilityName: "x", shortDescription: "", dateAdded: today, dueDate: today, knownRansomwareCampaignUse: "Known", requiredAction: "patch" },
      { cveID: "CVE-2", vendorProject: "Ivanti", product: "EPMM", vulnerabilityName: "y", shortDescription: "", dateAdded: "2020-01-01", dueDate: "2020-01-21", knownRansomwareCampaignUse: "Unknown", requiredAction: "patch" },
      { cveID: "CVE-3", vendorProject: "Cisco", product: "IOS", vulnerabilityName: "z", shortDescription: "", dateAdded: today, dueDate: today, knownRansomwareCampaignUse: "Unknown", requiredAction: "patch" }] })));
    expect((await S.kevSearch({ vendor: "ivanti" })).matches).toBe(2);
    expect((await S.kevSearch({ vendor: "ivanti", lastDays: 7 })).items.map(i => i.cve)).toEqual(["CVE-1"]);
    expect((await S.kevSearch({ ransomwareOnly: true })).items.map(i => i.cve)).toEqual(["CVE-1"]);
  });
});

describe("passive surface", () => {
  it("grades headers and catches weak values and leaks", () => {
    const g = S.gradeHeaders({ "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "permissions-policy": "camera=()", "cross-origin-opener-policy": "same-origin", server: "nginx/1.18.0" });
    expect(g.grade).toBe("A"); expect(g.headers.find(h => h.header === "x-frame-options")!.present).toBe(true); expect(g.infoLeaks).toEqual(["server: nginx/1.18.0"]);
    expect(S.gradeHeaders({ "strict-transport-security": "max-age=300" }).grade).toBe("F");
  });
  it("security header check makes exactly one GET to the root", async () => {
    const f = vi.fn().mockResolvedValue(Object.assign(new Response("ok", { headers: { "x-content-type-options": "nosniff" } }), {}));
    const r = await S.securityHeaders("Example.com", f as any);
    expect(f).toHaveBeenCalledTimes(1); expect(f.mock.calls[0][0]).toBe("https://example.com/"); expect(f.mock.calls[0][1].method).toBe("GET");
    expect(r.headers.find(h => h.header === "x-content-type-options")!.present).toBe(true);
  });
  it("SPF and DMARC assessments", () => {
    expect(S.assessSpf("v=spf1 +all")).toMatch(/DANGEROUS/); expect(S.assessSpf("v=spf1 include:x -all")).toMatch(/strong/); expect(S.assessSpf(null)).toMatch(/missing/);
    expect(S.assessDmarc("v=DMARC1; p=none")).toMatch(/monitoring/); expect(S.assessDmarc("v=DMARC1; p=reject")).toMatch(/strong/);
  });
  it("CT subdomains fall back to Cert Spotter and keep only in-scope names", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (u: any) => String(u).includes("crt.sh") ? new Response("", { status: 502 }) : new Response(JSON.stringify([{ dns_names: ["a.example.com", "*.example.com", "evil.com"] }])));
    const r = await S.ctSubdomains("example.com");
    expect(r.subdomains).toEqual(["*.example.com", "a.example.com"]); expect(r.source).toMatch(/Cert Spotter/); expect(r.errors[0]).toMatch(/crt\.sh/);
  });
});

describe("MCP surface", () => {
  it("exposes no active scanning tools", async () => {
    const [a, b] = InMemoryTransport.createLinkedPair(); await createServer().connect(a);
    const c = new Client({ name: "t", version: "1" }); await c.connect(b);
    const names = (await c.listTools()).tools.map(t => t.name);
    expect(names).toHaveLength(10);
    expect(names.some(n => /(^|_)(scan|port|ports|fuzz|brute|exploit)(_|$)/.test(n))).toBe(false);
  });
});
