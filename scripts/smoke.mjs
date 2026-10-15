// Live smoke test: node scripts/smoke.mjs [url]
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
const client = new Client({ name: "smoke", version: "1.0.0" });
await client.connect(new StreamableHTTPClientTransport(new URL(process.argv[2] ?? "http://localhost:3000/mcp")));
console.log("tools:", (await client.listTools()).tools.map(t => t.name).join(", "));
const calls = [
  ["breach_catalog", { limit: 3 }], ["breach_details", { name: "Adobe" }], ["domain_breaches", { domain: "linkedin.com" }],
  ["email_breaches", { email: "test@example.com" }], ["password_pwned", { password: "password123" }],
  ["cve_search", { cveId: "CVE-2024-3094" }], ["cve_search", { keyword: "openssl", severity: "CRITICAL", limit: 3 }],
  ["kev_lookup", { lastDays: 14, limit: 5 }], ["security_headers", { domain: "github.com" }],
  ["ct_subdomains", { domain: "x.ai", limit: 15 }], ["attack_surface_report", { domain: "x.ai" }],
];
for (const [name, args] of calls) { const t = Date.now(); const r = await client.callTool({ name, arguments: args }); console.log(`\n===== ${name} ${JSON.stringify(args)} (${Date.now() - t} ms)${r.isError ? " ERROR" : ""}\n${r.content[0].text.slice(0, 1800)}`); }
await client.close();
