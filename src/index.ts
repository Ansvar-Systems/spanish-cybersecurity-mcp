#!/usr/bin/env node

/**
 * Spanish Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying CCN-CERT (Centro Criptológico Nacional CERT)
 * guidelines, technical reports, security advisories, and ENS/CCN-STIC frameworks.
 *
 * Tool prefix: es_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
} from "./db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback to default
}

const SERVER_NAME = "spanish-cybersecurity-mcp";

// --- Tool definitions ---------------------------------------------------------

const TOOLS = [
  {
    name: "es_cyber_search_guidance",
    description:
      "Full-text search across CCN-CERT guidelines and technical reports. Covers CCN-STIC series (network security, hardening, cryptography, cloud, industrial), ENS (Esquema Nacional de Seguridad) implementation guides, and CCN technical reports. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'cifrado TLS', 'ENS medidas seguridad', 'hardening sistemas')",
        },
        type: {
          type: "string",
          enum: ["technical_guideline", "ens_guide", "technical_report", "recommendation"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["CCN-STIC", "ENS", "CCN-CERT"],
          description: "Filter by CCN series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Defaults to returning all statuses.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "es_cyber_get_guidance",
    description:
      "Get a specific CCN guidance document by reference (e.g., 'CCN-STIC-807', 'CCN-STIC-830', 'CCN-STIC-302').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "CCN document reference (e.g., 'CCN-STIC-807', 'CCN-STIC-830')",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "es_cyber_search_advisories",
    description:
      "Search CCN-CERT security advisories and alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'vulnerabilidad crítica', 'ransomware', 'APT')",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "es_cyber_get_advisory",
    description:
      "Get a specific CCN-CERT security advisory by reference (e.g., 'CCN-CERT-AV-24/001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "CCN-CERT advisory reference (e.g., 'CCN-CERT-AV-24/001')",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "es_cyber_list_frameworks",
    description:
      "List all CCN-CERT frameworks and standard series covered in this MCP, including CCN-STIC series, ENS (Esquema Nacional de Seguridad), and CCN-CERT alert series.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "es_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// --- Zod schemas for argument validation --------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["technical_guideline", "ens_guide", "technical_report", "recommendation"]).optional(),
  series: z.enum(["CCN-STIC", "ENS", "CCN-CERT"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- Helper ------------------------------------------------------------------

function textContent(data: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(data, null, 2) },
    ],
  };
}

function errorContent(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true as const,
  };
}

// --- Server setup ------------------------------------------------------------

const server = new Server(
  { name: SERVER_NAME, version: pkgVersion },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case "es_cyber_search_guidance": {
        const parsed = SearchGuidanceArgs.parse(args);
        const results = searchGuidance({
          query: parsed.query,
          type: parsed.type,
          series: parsed.series,
          status: parsed.status,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "es_cyber_get_guidance": {
        const parsed = GetGuidanceArgs.parse(args);
        const doc = getGuidance(parsed.reference);
        if (!doc) {
          return errorContent(`Guidance document not found: ${parsed.reference}`);
        }
        return textContent(doc);
      }

      case "es_cyber_search_advisories": {
        const parsed = SearchAdvisoriesArgs.parse(args);
        const results = searchAdvisories({
          query: parsed.query,
          severity: parsed.severity,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "es_cyber_get_advisory": {
        const parsed = GetAdvisoryArgs.parse(args);
        const advisory = getAdvisory(parsed.reference);
        if (!advisory) {
          return errorContent(`Advisory not found: ${parsed.reference}`);
        }
        return textContent(advisory);
      }

      case "es_cyber_list_frameworks": {
        const frameworks = listFrameworks();
        return textContent({ frameworks, count: frameworks.length });
      }

      case "es_cyber_about": {
        return textContent({
          name: SERVER_NAME,
          version: pkgVersion,
          description:
            "CCN-CERT (Centro Criptológico Nacional CERT — Spanish National Cryptologic Centre CERT) MCP server. Provides access to CCN-STIC technical guidelines, ENS (Esquema Nacional de Seguridad) implementation guides, CCN technical reports, and security advisories.",
          data_source: "CCN-CERT (https://www.ccn-cert.cni.es/)",
          coverage: {
            guidance: "CCN-STIC series (800 series: ENS, 400 series: network, 500 series: OS hardening, 300 series: cryptography), CCN-CERT technical reports",
            advisories: "CCN-CERT security advisories and alerts (AV series)",
            frameworks: "CCN-STIC series, ENS (Esquema Nacional de Seguridad), CCN-CERT alert series",
          },
          tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
        });
      }

      default:
        return errorContent(`Unknown tool: ${name}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorContent(`Error executing ${name}: ${message}`);
  }
});

// --- Main --------------------------------------------------------------------

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
