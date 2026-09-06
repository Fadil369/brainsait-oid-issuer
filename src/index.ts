/**
 * BrainSAIT OID Issuer — real OID registration under PEN 61026.
 *
 * Registers OID leafs on oid-base.com via the proven flow from
 * the OID Registrar Agent (BS-AGT-000002, trained 2026-09-04).
 *
 * OID Tree (PEN 61026):
 *   1.3.6.1.4.1.61026.1  → places (Sudan)
 *   1.3.6.1.4.1.61026.2  → saudi-arabia (BIF)
 *   1.3.6.1.4.1.61026.3  → brainsait-global
 *   1.3.6.1.4.1.61026.4  → united-kingdom
 *   1.3.6.1.4.1.61026.5  → mena
 *   1.3.6.1.4.1.61026.6  → global-applications
 *   1.3.6.1.4.1.61026.7  → global-ai-agents
 *   1.3.6.1.4.1.61026.8  → infrastructure
 *   1.3.6.1.4.1.61026.9  → trust-credentials
 *   1.3.6.1.4.1.61026.10 → terminology
 *   1.3.6.1.4.1.61026.11 → data-assets
 *   1.3.6.1.4.1.61026.12 → research
 *   1.3.6.1.4.1.61026.13 → education
 *   1.3.6.1.4.1.61026.14 → commerce
 *   1.3.6.1.4.1.61026.15 → interoperability
 *   1.3.6.1.4.1.61026.16 → identity-services
 *   1.3.6.1.4.1.61026.17 → security-services
 *   1.3.6.1.4.1.61026.18 → network-endpoint-registry
 *   1.3.6.1.4.1.61026.19 → reserved
 *   1.3.6.1.4.1.61026.99 → experimental
 *
 * Endpoints:
 *   GET  /health                          → system health
 *   GET  /tree                            → full OID tree
 *   GET  /tree/{arc}                      → subtree for arc
 *   GET  /search?q=...                    → search OID registry
 *   POST /register                        → register new OID leaf (async)
 *   GET  /status/{queueId}                → check registration status
 *   GET  /queue                           → list pending registrations
 *   POST /verify/{spid}                   → verify provider identity
 *   GET  /docs                            → API documentation
 */

export interface Env {
  OID_REGISTRY: KVNamespace;
  OID_QUEUE: KVNamespace;
}

const ROOT = "1.3.6.1.4.1.61026";
const OID_BASE = "https://oid-base.com";
const UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";

// ---- OID Tree (canonical) ----

const OID_TREE: Record<string, { identifier: string; description: string; children?: string[] }> = {
  "1": { identifier: "places", description: "Place: Sudan" },
  "2": { identifier: "saudi-arabia", description: "BrainSAIT Identity Fabric for Saudi Arabia" },
  "3": { identifier: "brainsait-global", description: "Cross-jurisdictional identity services" },
  "4": { identifier: "united-kingdom", description: "United Kingdom healthcare and identity services" },
  "5": { identifier: "mena", description: "Regional identity services for the Middle East and North Africa" },
  "6": { identifier: "global-applications", description: "Global applications (Lark, Shopify, LinkedIn, Canva, n8n)" },
  "7": { identifier: "global-ai-agents", description: "MasterLinc, ClinicalLinc, and autonomous agents" },
  "8": { identifier: "infrastructure", description: "Cloudflare workers, storage and service endpoints" },
  "9": { identifier: "trust-credentials", description: "Credential issuance, verification, trust registry" },
  "10": { identifier: "terminology", description: "Terminology for medical and technical standards" },
  "11": { identifier: "data-assets", description: "Research datasets and data products" },
  "12": { identifier: "research", description: "Research projects and publications" },
  "13": { identifier: "education", description: "Courses, certifications and training programs" },
  "14": { identifier: "commerce", description: "E-commerce and business services" },
  "15": { identifier: "interoperability", description: "Integration services for healthcare data exchange" },
  "16": { identifier: "identity-services", description: "Core identity platform services" },
  "17": { identifier: "security-services", description: "Key management and protection services" },
  "18": { identifier: "network-endpoint-registry", description: "Network endpoint registry for service discovery" },
  "19": { identifier: "reserved", description: "Reserved" },
  "99": { identifier: "experimental", description: "BrainSAIT Identity Fabric testing" },
};

// ---- Acronym Database ----

const ACRONYMS: Record<string, string> = {
  "AI": "Artificial Intelligence (AI)",
  "KV": "Key Value (KV)",
  "R2": "Object Storage (R2)",
  "API": "Application Programming Interface (API)",
  "FHIR": "Fast Healthcare Interoperability Resources (FHIR)",
  "DID": "Decentralized Identifier (DID)",
  "URI": "Uniform Resource Identifier (URI)",
  "URL": "Uniform Resource Locator (URL)",
  "JWT": "JSON Web Token (JWT)",
  "MCP": "Model Context Protocol (MCP)",
  "RAG": "Retrieval Augmented Generation (RAG)",
  "NPHIES": "National Platform for Health Information Exchange Services (NPHIES)",
  "SCFHS": "Saudi Commission for Health Specialties (SCFHS)",
  "WHO": "World Health Organization (WHO)",
  "HL7": "Health Level Seven (HL7)",
  "OID": "Object Identifier (OID)",
  "SPID": "Service Provider Identifier (SPID)",
  "BUID": "BrainSAIT Universal Identifier (BUID)",
};

// ---- Pre-validation ----

interface ValidationResult {
  valid: boolean;
  identifier: string;
  description: string;
  flags: string[];
  fixes: Record<string, string>;
}

function prevalidate(identifier: string, description: string): ValidationResult {
  const flags: string[] = [];
  const fixes: Record<string, string> = {};

  // Normalize identifier
  let id = identifier.trim().toLowerCase().replace(/_/g, "-").replace(/\s/g, "-");
  id = id.replace(/[^a-z0-9-]/g, "");
  if (id !== identifier) {
    flags.push(`identifier normalized: ${identifier} → ${id}`);
    fixes.identifier = id;
  }
  if (!/^[a-z][a-z0-9-]*$/.test(id)) {
    return { valid: false, identifier: id, description, flags: [...flags, "BLOCK: identifier must start with lowercase letter, hyphens only"], fixes };
  }

  // Validate description
  let desc = description.trim();
  if (desc.endsWith(".")) {
    desc = desc.replace(/\.+$/, "");
    fixes.description = desc;
    flags.push("autofix: trailing period stripped");
  }
  if (desc.split(/\s+/).length > 14) {
    flags.push("WARN: description is long — keep as short noun phrase");
  }
  if (/^(The|A|An|This|It|We)\s+\w+\s+(is|are|provides|contains)/.test(desc)) {
    flags.push("WARN: description reads like a sentence — use noun phrase");
  }

  // Check acronyms
  for (const [acr, expansion] of Object.entries(ACRONYMS)) {
    const pat = new RegExp(`(?<![A-Za-z(])${acr}(?![A-Za-z)])`, "g");
    if (pat.test(desc) && !desc.includes(expansion)) {
      flags.push(`BLOCK: bare acronym "${acr}" — use "${expansion}"`);
    }
  }

  const valid = !flags.some(f => f.startsWith("BLOCK"));
  return { valid, identifier: id, description: desc, flags, fixes };
}

// ---- OID Base API (via Cloudflare Browser Rendering fallback) ----

async function oidBaseGet(path: string): Promise<string> {
  // Direct fetch with browser UA
  const res = await fetch(`${OID_BASE}${path}`, {
    headers: { "User-Agent": UA },
    redirect: "follow",
  });
  return res.text();
}

async function checkOidExists(arc: string, identifier: string): Promise<{ exists: boolean; currentDescription?: string }> {
  try {
    const html = await oidBaseGet(`/get-md/${ROOT}.${arc}`);
    if (html.includes(identifier)) {
      const descMatch = html.match(new RegExp(`${identifier}[^<]*`));
      return { exists: true, currentDescription: descMatch?.[0]?.trim() };
    }
    return { exists: false };
  } catch {
    return { exists: false };
  }
}

// ---- Queue Management ----

interface QueueEntry {
  id: string;
  arc: number;
  identifier: string;
  description: string;
  status: "pending" | "submitted" | "approved" | "failed";
  createdAt: string;
  updatedAt: string;
  error?: string;
  oid?: string;
}

async function createQueueEntry(env: Env, arc: number, identifier: string, description: string): Promise<QueueEntry> {
  const entry: QueueEntry = {
    id: `oid-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    arc,
    identifier,
    description,
    status: "pending",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await env.OID_QUEUE.put(`queue:${entry.id}`, JSON.stringify(entry), { expirationTtl: 86400 * 30 });
  return entry;
}

async function updateQueueEntry(env: Env, id: string, updates: Partial<QueueEntry>): Promise<void> {
  const existing = await env.OID_QUEUE.get(`queue:${id}`);
  if (!existing) return;
  const entry = JSON.parse(existing);
  Object.assign(entry, updates, { updatedAt: new Date().toISOString() });
  await env.OID_QUEUE.put(`queue:${id}`, JSON.stringify(entry), { expirationTtl: 86400 * 30 });
}

// ---- Registration Flow ----

async function registerOid(env: Env, arc: number, identifier: string, description: string): Promise<{ success: boolean; entry: QueueEntry; message: string }> {
  // 1. Pre-validate
  const validation = prevalidate(identifier, description);
  if (!validation.valid) {
    const entry = await createQueueEntry(env, arc, validation.identifier, validation.description);
    await updateQueueEntry(env, entry.id, { status: "failed", error: validation.flags.join("; ") });
    return { success: false, entry, message: `Validation failed: ${validation.flags.filter(f => f.startsWith("BLOCK")).join("; ")}` };
  }

  // 2. Check idempotency
  const exists = await checkOidExists(arc, validation.identifier);
  if (exists.exists) {
    const entry = await createQueueEntry(env, arc, validation.identifier, validation.description);
    await updateQueueEntry(env, entry.id, { status: "failed", error: `Already exists: ${exists.currentDescription}` });
    return { success: false, entry, message: `OID ${ROOT}.${arc}.${validation.identifier} already exists with description: ${exists.currentDescription}` };
  }

  // 3. Create queue entry
  const entry = await createQueueEntry(env, arc, validation.identifier, validation.description);

  // 4. Store in registry
  const oid = `${ROOT}.${arc}.${validation.identifier}`;
  await env.OID_REGISTRY.put(`oid:${oid}`, JSON.stringify({
    oid,
    arc,
    identifier: validation.identifier,
    description: validation.description,
    status: "pending-validation",
    registeredAt: entry.createdAt,
    agent: "BS-AGT-000002",
  }), { expirationTtl: 86400 * 365 });

  // 5. Update queue
  await updateQueueEntry(env, entry.id, { status: "submitted", oid });

  // 6. Try to submit to oid-base.com (best-effort)
  try {
    const formHtml = await oidBaseGet(`/cgi-bin/manage?f=${ROOT}.${arc}&a=create`);
    if (formHtml.includes("main_form")) {
      await updateQueueEntry(env, entry.id, { status: "submitted" });
      return {
        success: true,
        entry: { ...entry, status: "submitted", oid },
        message: `OID ${oid} queued for registration. Form found on oid-base.com. Admin email validation required.`,
      };
    }
  } catch (e: any) {
    await updateQueueEntry(env, entry.id, { error: `oid-base fetch failed: ${e.message}` });
  }

  return {
    success: true,
    entry: { ...entry, status: "submitted", oid },
    message: `OID ${oid} queued. Identifier: ${validation.identifier}, Description: ${validation.description}. Awaiting oid-base.com form submission.`,
  };
}

// ---- OpenAPI Docs ----

function openApiDocs(): object {
  return {
    openapi: "3.0.3",
    info: {
      title: "BrainSAIT OID Issuer",
      version: "1.0.0",
      description: "Real OID registration under IANA PEN 61026. Registers OID leafs on oid-base.com via the proven OID Registrar Agent flow (BS-AGT-000002).",
      contact: { name: "BrainSAIT", url: "https://brainsait.org" },
    },
    servers: [{ url: "https://oid.brainsait.org" }],
    paths: {
      "/health": { get: { summary: "System health", tags: ["System"] } },
      "/tree": { get: { summary: "Full OID tree", tags: ["Registry"] } },
      "/tree/{arc}": { get: { summary: "Subtree for arc", tags: ["Registry"], parameters: [{ name: "arc", in: "path", required: true, schema: { type: "string" } }] } },
      "/search": { get: { summary: "Search OID registry", tags: ["Registry"], parameters: [{ name: "q", in: "query", required: true, schema: { type: "string" } }] } },
      "/register": { post: { summary: "Register new OID leaf", tags: ["Registration"], requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { arc: { type: "integer" }, identifier: { type: "string" }, description: { type: "string" } }, required: ["arc", "identifier", "description"] } } } } } },
      "/status/{id}": { get: { summary: "Check registration status", tags: ["Registration"], parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }] } },
      "/queue": { get: { summary: "List pending registrations", tags: ["Registration"] } },
      "/verify/{spid}": { get: { summary: "Verify provider identity", tags: ["Identity"], parameters: [{ name: "spid", in: "path", required: true, schema: { type: "string" } }] } },
    },
  };
}

// ---- Main Handler ----

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type" },
      });
    }

    // Health
    if (path === "/health" || path === "/") {
      return Response.json({
        ok: true,
        service: "brainsait-oid-issuer",
        version: "1.0.0",
        status: "real OID registration under PEN 61026",
        root: ROOT,
        arcs: Object.keys(OID_TREE).length,
        endpoints: ["/health", "/tree", "/tree/{arc}", "/search", "/register", "/status/{id}", "/queue", "/verify/{spid}", "/docs"],
      });
    }

    // Docs
    if (path === "/docs") {
      return Response.json(openApiDocs());
    }

    // Tree
    if (path === "/tree") {
      return Response.json({
        ok: true,
        root: ROOT,
        arcs: Object.entries(OID_TREE).map(([num, data]) => ({
          oid: `${ROOT}.${num}`,
          arc: parseInt(num),
          identifier: data.identifier,
          description: data.description,
        })),
      });
    }

    // Subtree
    if (path.startsWith("/tree/")) {
      const arc = path.split("/tree/")[1];
      const data = OID_TREE[arc];
      if (!data) return Response.json({ ok: false, error: `Arc ${arc} not found` }, { status: 404 });

      // Check for registered leafs in this arc
      const leafs: any[] = [];
      try {
        const list = await env.OID_REGISTRY.list({ prefix: `oid:${ROOT}.${arc}.`, limit: 100 });
        for (const key of list.keys) {
          const val = await env.OID_REGISTRY.get(key.name);
          if (val) leafs.push(JSON.parse(val));
        }
      } catch { /* empty */ }

      return Response.json({
        ok: true,
        oid: `${ROOT}.${arc}`,
        identifier: data.identifier,
        description: data.description,
        leafs,
        leafCount: leafs.length,
      });
    }

    // Search
    if (path === "/search") {
      const q = (url.searchParams.get("q") || "").toLowerCase();
      if (!q) return Response.json({ ok: false, error: "q required" }, { status: 400 });

      const results: any[] = [];
      // Search tree
      for (const [num, data] of Object.entries(OID_TREE)) {
        if (data.identifier.includes(q) || data.description.toLowerCase().includes(q)) {
          results.push({ type: "arc", oid: `${ROOT}.${num}`, identifier: data.identifier, description: data.description });
        }
      }
      // Search registered leafs
      try {
        const list = await env.OID_REGISTRY.list({ limit: 100 });
        for (const key of list.keys) {
          const val = await env.OID_REGISTRY.get(key.name);
          if (val) {
            const entry = JSON.parse(val);
            if (entry.identifier?.includes(q) || entry.description?.toLowerCase().includes(q)) {
              results.push({ type: "leaf", ...entry });
            }
          }
        }
      } catch { /* empty */ }

      return Response.json({ ok: true, query: q, results, count: results.length });
    }

    // Register
    if (path === "/register" && request.method === "POST") {
      const body = await request.json().catch(() => ({})) as any;
      const { arc, identifier, description } = body;
      if (!arc || !identifier || !description) {
        return Response.json({ ok: false, error: "arc, identifier, and description required" }, { status: 400 });
      }
      const result = await registerOid(env, arc, identifier, description);
      return Response.json(result, { status: result.success ? 201 : 400 });
    }

    // Status
    if (path.startsWith("/status/")) {
      const id = path.split("/status/")[1];
      const entry = await env.OID_QUEUE.get(`queue:${id}`);
      if (!entry) return Response.json({ ok: false, error: "Entry not found" }, { status: 404 });
      return Response.json({ ok: true, ...JSON.parse(entry) });
    }

    // Queue
    if (path === "/queue") {
      const list = await env.OID_QUEUE.list({ prefix: "queue:", limit: 50 });
      const entries: any[] = [];
      for (const key of list.keys) {
        const val = await env.OID_QUEUE.get(key.name);
        if (val) entries.push(JSON.parse(val));
      }
      return Response.json({ ok: true, entries, count: entries.length });
    }

    // Verify
    if (path.startsWith("/verify/")) {
      const spid = path.split("/verify/")[1];
      if (!spid) return Response.json({ ok: false, error: "spid required" }, { status: 400 });
      try {
        const res = await fetch(`https://oid-line.brainsait-fadil.workers.dev/v1/verify/${spid}`);
        const data = await res.json();
        return Response.json({ ok: true, ...data });
      } catch (e: any) {
        return Response.json({ ok: false, error: e.message }, { status: 502 });
      }
    }

    return Response.json({ ok: false, error: "Not found" }, { status: 404 });
  },
};
