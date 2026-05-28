/**
 * INCIBE Ingestion Crawler
 *
 * Scrapes the INCIBE website (incibe.es) and populates the SQLite database
 * with security advisories from INCIBE-CERT (alerta-temprana/avisos) and
 * cybersecurity guidance from INCIBE-CERT guías-y-estudios, /empresas/guias,
 * /empresas/blog, and /incibe-cert/blog.
 *
 * Phase 4 of the EU cybersecurity corpus consolidation.
 *
 * Authority: INCIBE (Instituto Nacional de Ciberseguridad).
 * Scope decision (2026-05-28): INCIBE only for this first pass. CCN-CERT
 * (Centro Criptológico Nacional) also exists but its corpus is largely
 * classified-government-only; defer to a later session.
 *
 * Data sources:
 *   1. INCIBE-CERT advisories: /incibe-cert/alerta-temprana/avisos        (paginated)
 *   2. INCIBE-CERT guides:     /incibe-cert/publicaciones/guias-y-estudios (paginated)
 *   3. INCIBE-CERT blog:       /incibe-cert/blog                          (paginated)
 *   4. Empresas guides:        /empresas/guias                            (paginated)
 *   5. Empresas blog:          /empresas/blog                             (paginated)
 *
 * License: Spanish-TRLPI-Art-13 (per fleet manifest audit).
 *
 * Usage:
 *   npx tsx scripts/ingest-incibe.ts                  # full crawl
 *   npx tsx scripts/ingest-incibe.ts --resume          # resume from last checkpoint
 *   npx tsx scripts/ingest-incibe.ts --dry-run         # log what would be inserted
 *   npx tsx scripts/ingest-incibe.ts --force            # drop and recreate DB first
 *   npx tsx scripts/ingest-incibe.ts --advisories-only  # only crawl advisories
 *   npx tsx scripts/ingest-incibe.ts --guidance-only    # only crawl guidance
 *   npx tsx scripts/ingest-incibe.ts --max-pages 5      # limit pages per listing
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["INCIBE_DB_PATH"] ?? "data/incibe.db";
const PROGRESS_FILE = resolve(dirname(DB_PATH), "ingest-progress.json");
const BASE_URL = "https://www.incibe.es";

const RATE_LIMIT_MS = 1200;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 2000;
const USER_AGENT =
  "AnsvarINCIBECrawler/1.0 (+https://ansvar.eu; compliance research)";

const DEFAULT_MAX_PAGES = 4; // pages per listing; ~9 detail links/page

// CLI flags
const args = process.argv.slice(2);
const force = args.includes("--force");
const dryRun = args.includes("--dry-run");
const resume = args.includes("--resume");
const advisoriesOnly = args.includes("--advisories-only");
const guidanceOnly = args.includes("--guidance-only");

function getMaxPages(): number {
  const idx = args.indexOf("--max-pages");
  if (idx >= 0 && idx + 1 < args.length) {
    const raw = args[idx + 1]!;
    const n = parseInt(raw, 10);
    if (!Number.isNaN(n) && n > 0) return n;
  }
  return DEFAULT_MAX_PAGES;
}
const MAX_PAGES = getMaxPages();

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
  source_url: string;
}

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null;
  summary: string;
  full_text: string;
  cve_references: string | null;
  source_url: string;
}

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string | null;
  description: string;
  document_count: number;
}

interface Progress {
  completed_advisory_urls: string[];
  completed_guidance_urls: string[];
  last_updated: string;
}

// ---------------------------------------------------------------------------
// Utility: rate-limited fetch with retry
// ---------------------------------------------------------------------------

let lastRequestTime = 0;

async function rateLimitedFetch(
  url: string,
  opts?: RequestInit,
): Promise<Response> {
  const now = Date.now();
  const elapsed = now - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }

  let lastError: Error | null = null;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      lastRequestTime = Date.now();
      const resp = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          Accept:
            "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
          "Accept-Language": "es-ES,es;q=0.9,en;q=0.6",
        },
        redirect: "follow",
        signal: AbortSignal.timeout(30_000),
        ...opts,
      });
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} for ${url}`);
      }
      return resp;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      console.warn(
        `  [retry ${attempt}/${MAX_RETRIES}] ${url}: ${lastError.message}`,
      );
      if (attempt < MAX_RETRIES) {
        await sleep(RETRY_BACKOFF_MS * attempt);
      }
    }
  }
  throw lastError!;
}

async function fetchText(url: string): Promise<string> {
  const resp = await rateLimitedFetch(url);
  return resp.text();
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// HTML helpers (lightweight, regex-based — same shape as ingest-bsi.ts)
// ---------------------------------------------------------------------------

function htmlToText(html: string): string {
  return html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<\/li>/gi, "\n")
    .replace(/<\/h[1-6]>/gi, "\n\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&aacute;/g, "á")
    .replace(/&eacute;/g, "é")
    .replace(/&iacute;/g, "í")
    .replace(/&oacute;/g, "ó")
    .replace(/&uacute;/g, "ú")
    .replace(/&ntilde;/g, "ñ")
    .replace(/&Aacute;/g, "Á")
    .replace(/&Eacute;/g, "É")
    .replace(/&Iacute;/g, "Í")
    .replace(/&Oacute;/g, "Ó")
    .replace(/&Uacute;/g, "Ú")
    .replace(/&Ntilde;/g, "Ñ")
    .replace(/&#\d+;/g, "")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function extractLinks(
  html: string,
  hrefPattern: RegExp,
): Array<{ href: string; text: string }> {
  const results: Array<{ href: string; text: string }> = [];
  const re = /<a\s[^>]*href\s*=\s*"([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const href = m[1]!;
    const text = htmlToText(m[2]!);
    if (hrefPattern.test(href)) {
      results.push({ href, text });
    }
  }
  return results;
}

function extractSection(
  html: string,
  startPattern: RegExp,
  endPattern: RegExp,
): string {
  const startMatch = startPattern.exec(html);
  if (!startMatch) return "";
  const startIdx = startMatch.index + startMatch[0].length;
  const rest = html.slice(startIdx);
  const endMatch = endPattern.exec(rest);
  const endIdx = endMatch ? endMatch.index : rest.length;
  return rest.slice(0, endIdx);
}

function extractMainContent(html: string): string {
  // Drupal sites typically have <main> wrappers
  const patterns: Array<[RegExp, RegExp]> = [
    [/<main[^>]*>/i, /<\/main>/i],
    [/<article[^>]*>/i, /<\/article>/i],
    [/<div[^>]*class="[^"]*main-content[^"]*"[^>]*>/i, /<\/div>\s*<\/(?:main|body)/i],
    [/<div[^>]*class="[^"]*node-content[^"]*"[^>]*>/i, /<\/div>\s*<\/(?:main|body)/i],
    [/<div[^>]*id="content"[^>]*>/i, /<footer/i],
  ];

  for (const [start, end] of patterns) {
    const section = extractSection(html, start, end);
    if (section.length > 200) {
      return section;
    }
  }

  const fallback = extractSection(html, /<\/nav>/i, /<footer/i);
  return fallback.length > 100 ? fallback : html;
}

// ---------------------------------------------------------------------------
// Date / severity parsing
// ---------------------------------------------------------------------------

/**
 * Parse a date in DD/MM/YYYY format (INCIBE's standard) to YYYY-MM-DD.
 */
function parseSpanishDate(raw: string): string | null {
  const m = raw.match(/(\d{2})\/(\d{2})\/(\d{4})/);
  if (m) return `${m[3]}-${m[2]}-${m[1]}`;
  // Fallback: YYYY-MM-DD or YYYY/MM/DD already
  const m2 = raw.match(/(\d{4})[-/](\d{2})[-/](\d{2})/);
  if (m2) return `${m2[1]}-${m2[2]}-${m2[3]}`;
  return null;
}

/**
 * Normalise an INCIBE Importancia field. Values seen:
 *   "5 - Crítica" / "4 - Alta" / "3 - Media" / "2 - Baja" / "1 - Muy Baja"
 *   Plain "Crítica", "Alta", "Media", "Baja".
 */
function normaliseSeverity(raw: string): string {
  const lower = raw.toLowerCase().trim();
  if (/crítica|critica|critical|^5\b/.test(lower)) return "critical";
  if (/^4\b|alta|high/.test(lower)) return "high";
  if (/^3\b|media|medium/.test(lower)) return "medium";
  if (/^2\b|baja|low/.test(lower)) return "low";
  if (/^1\b|muy\s*baja|very\s*low/.test(lower)) return "low";
  return "medium";
}

// ---------------------------------------------------------------------------
// Topic detection (Spanish)
// ---------------------------------------------------------------------------

function detectTopics(text: string): string[] {
  const topics: string[] = [];
  const lower = text.toLowerCase();

  const topicPatterns: Array<[RegExp, string]> = [
    [/cve-\d/i, "vulnerabilidad"],
    [/rce|ejecuci[oó]n.*c[oó]digo.*remot/i, "rce"],
    [/sql.?injection|inyecci[oó]n.*sql/i, "sql-injection"],
    [/xss|cross.?site.?script/i, "xss"],
    [/csrf|cross.?site.?request/i, "csrf"],
    [/phishing|suplantaci[oó]n/i, "phishing"],
    [/ransomware/i, "ransomware"],
    [/malware/i, "malware"],
    [/cifrado|cripto|encrypt/i, "criptografia"],
    [/contrase[ñn]a|password|credencial/i, "credenciales"],
    [/autenticaci[oó]n|authentication|2fa|mfa/i, "autenticacion"],
    [/red|network|firewall|vpn/i, "red"],
    [/cloud|nube/i, "cloud"],
    [/iot/i, "iot"],
    [/sci|industri|ics|scada|ot[\s-]/i, "industrial"],
    [/m[oó]vil|mobile|android|ios/i, "movil"],
    [/web|http|api/i, "web"],
    [/correo|email|smtp/i, "email"],
    [/dns/i, "dns"],
    [/copias.*seguridad|backup/i, "backup"],
    [/forense|forensic/i, "forense"],
    [/incidente|incident/i, "gestion-incidentes"],
    [/cumplimiento|gdpr|rgpd/i, "cumplimiento"],
    [/nis2|nis-2|nis ?2/i, "nis2"],
    [/inteligencia.*artificial|machine.*learn|ai\b/i, "ia"],
    [/pyme|empresa/i, "pyme"],
    [/concienciaci[oó]n|formaci[oó]n|awareness/i, "concienciacion"],
  ];

  for (const [pattern, topic] of topicPatterns) {
    if (pattern.test(lower)) {
      if (!topics.includes(topic)) topics.push(topic);
    }
  }

  return topics.length > 0 ? topics : ["general"];
}

// ---------------------------------------------------------------------------
// Progress tracking
// ---------------------------------------------------------------------------

function loadProgress(): Progress {
  if (resume && existsSync(PROGRESS_FILE)) {
    try {
      const raw = readFileSync(PROGRESS_FILE, "utf-8");
      const p = JSON.parse(raw) as Progress;
      console.log(
        `Resuming from checkpoint (${p.last_updated}): ` +
          `${p.completed_advisory_urls.length} advisories, ` +
          `${p.completed_guidance_urls.length} guidance`,
      );
      return p;
    } catch {
      console.warn("Could not parse progress file, starting fresh");
    }
  }
  return {
    completed_advisory_urls: [],
    completed_guidance_urls: [],
    last_updated: new Date().toISOString(),
  };
}

function saveProgress(progress: Progress): void {
  progress.last_updated = new Date().toISOString();
  writeFileSync(PROGRESS_FILE, JSON.stringify(progress, null, 2));
}

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

function initDatabase(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  if (force && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    console.log(`Deleted existing database at ${DB_PATH}`);
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  console.log(`Database initialised at ${DB_PATH}`);
  return db;
}

// ---------------------------------------------------------------------------
// Frameworks (static)
// ---------------------------------------------------------------------------

const FRAMEWORKS: FrameworkRow[] = [
  {
    id: "incibe-cert-avisos",
    name: "INCIBE-CERT Avisos de Seguridad",
    name_en: "INCIBE-CERT Security Advisories",
    description:
      "Avisos de seguridad publicados por INCIBE-CERT (Centro de Respuesta a Incidentes de Seguridad para ciudadanos, empresas y operadores estratégicos). Cubren vulnerabilidades en productos software y hardware, con detalle de CVE, recursos afectados, descripción técnica y medidas de mitigación o solución.",
    document_count: 0,
  },
  {
    id: "incibe-cert-guias",
    name: "INCIBE-CERT Guías y Estudios",
    name_en: "INCIBE-CERT Guides and Studies",
    description:
      "Guías técnicas y estudios publicados por INCIBE-CERT sobre ciberseguridad industrial (SCI), análisis de vulnerabilidades persistentes, herramientas de respuesta a incidentes y mejores prácticas para operadores de servicios esenciales.",
    document_count: 0,
  },
  {
    id: "incibe-empresas-guias",
    name: "INCIBE Guías para Empresas",
    name_en: "INCIBE Guides for Companies",
    description:
      "Guías de aproximación al empresario publicadas por INCIBE: gestión de riesgos, plan director de seguridad, ransomware, glosario de términos, ciberseguridad sectorial (turismo, comercio, salud) y cumplimiento normativo (RGPD).",
    document_count: 0,
  },
  {
    id: "incibe-blog",
    name: "INCIBE Blog (Empresas + INCIBE-CERT)",
    name_en: "INCIBE Blog (Companies + INCIBE-CERT)",
    description:
      "Artículos publicados en el blog de INCIBE dirigidos a empresas y profesionales de la ciberseguridad, cubriendo amenazas actuales, casos de incidentes, normativa europea (NIS2, eIDAS2) y orientaciones para responsables de seguridad.",
    document_count: 0,
  },
];

// ---------------------------------------------------------------------------
// Listing discovery (paginated)
// ---------------------------------------------------------------------------

interface ListingTarget {
  /** Pretty name for log output. */
  name: string;
  /** Absolute URL of the listing page (no ?page= suffix). */
  listingUrl: string;
  /** Regex matching detail page hrefs to harvest. */
  detailHrefPattern: RegExp;
  /** Output type label for guidance/advisory row. */
  type: "advisory" | "guidance";
  /** Guidance series tag (ignored for advisories). */
  series: string;
}

const ADVISORY_LISTINGS: ListingTarget[] = [
  {
    name: "INCIBE-CERT Avisos",
    listingUrl: `${BASE_URL}/incibe-cert/alerta-temprana/avisos`,
    detailHrefPattern: /^\/incibe-cert\/alerta-temprana\/avisos\/[^"]+$/,
    type: "advisory",
    series: "INCIBE-CERT-Aviso",
  },
];

const GUIDANCE_LISTINGS: ListingTarget[] = [
  {
    name: "INCIBE-CERT Guías y Estudios",
    listingUrl: `${BASE_URL}/incibe-cert/publicaciones/guias-y-estudios`,
    detailHrefPattern: /^\/incibe-cert\/guias-y-estudios\/[^"]+$/,
    type: "guidance",
    series: "INCIBE-CERT-Guia",
  },
  {
    name: "INCIBE-CERT Blog",
    listingUrl: `${BASE_URL}/incibe-cert/blog`,
    detailHrefPattern: /^\/incibe-cert\/blog\/[^"]+$/,
    type: "guidance",
    series: "INCIBE-CERT-Blog",
  },
  {
    name: "Empresas Guías",
    listingUrl: `${BASE_URL}/empresas/guias`,
    detailHrefPattern: /^\/empresas\/guias\/[^"]+$/,
    type: "guidance",
    series: "Empresas-Guia",
  },
  {
    name: "Empresas Blog",
    listingUrl: `${BASE_URL}/empresas/blog`,
    detailHrefPattern: /^\/empresas\/blog\/[^"]+$/,
    type: "guidance",
    series: "Empresas-Blog",
  },
];

async function discoverDetailUrls(target: ListingTarget): Promise<string[]> {
  console.log(`\n--- Discovering ${target.name} (max ${MAX_PAGES} pages) ---`);
  const seen = new Set<string>();
  const urls: string[] = [];

  for (let page = 0; page < MAX_PAGES; page++) {
    const pageUrl = page === 0 ? target.listingUrl : `${target.listingUrl}?page=${page}`;
    let html: string;
    try {
      html = await fetchText(pageUrl);
    } catch (err) {
      console.warn(
        `  Could not fetch page ${page}: ${err instanceof Error ? err.message : err}`,
      );
      break;
    }

    const links = extractLinks(html, target.detailHrefPattern);
    let newOnThisPage = 0;
    for (const link of links) {
      if (!seen.has(link.href)) {
        seen.add(link.href);
        urls.push(`${BASE_URL}${link.href}`);
        newOnThisPage++;
      }
    }
    console.log(`  page=${page}: +${newOnThisPage} new (total ${urls.length})`);
    if (newOnThisPage === 0) break;
  }

  console.log(`  Discovered ${urls.length} detail URLs for ${target.name}`);
  return urls;
}

// ---------------------------------------------------------------------------
// Detail page crawl
// ---------------------------------------------------------------------------

function extractAdvisoryFields(html: string): {
  reference: string | null;
  importancia: string | null;
  fechaPub: string | null;
  recursosAfectados: string | null;
  descripcion: string | null;
  solucion: string | null;
  etiquetas: string | null;
} {
  const mainHtml = extractMainContent(html);
  const text = htmlToText(mainHtml);

  // Identifier — INCIBE-YYYY-NNN
  const refMatch = text.match(/Identificador\s+(INCIBE-\d{4}-\d+)/i);
  const reference = refMatch?.[1] ?? null;

  // Importancia (severity) — value follows the label
  const impMatch = text.match(/Importancia\s+([^\n]+?)(?:\s{2,}|\n|$)/);
  const importancia = impMatch?.[1]?.trim() ?? null;

  // Fecha de publicación
  const dateMatch = text.match(/Fecha de publicaci[oó]n\s+(\d{2}\/\d{2}\/\d{4})/);
  const fechaPub = dateMatch?.[1] ?? null;

  // Recursos Afectados — text until next labelled section
  const recursosMatch = text.match(
    /Recursos Afectados\s+([\s\S]*?)(?:Descripci[oó]n|Soluci[oó]n|Detalle|Listado de referencias|Etiquetas|$)/,
  );
  const recursosAfectados = recursosMatch?.[1]?.trim() ?? null;

  const descMatch = text.match(
    /Descripci[oó]n\s+([\s\S]*?)(?:Soluci[oó]n|Detalle|Recursos Afectados|Listado de referencias|Etiquetas|$)/,
  );
  const descripcion = descMatch?.[1]?.trim() ?? null;

  const solucionMatch = text.match(
    /Soluci[oó]n\s+([\s\S]*?)(?:Detalle|Listado de referencias|Etiquetas|$)/,
  );
  const solucion = solucionMatch?.[1]?.trim() ?? null;

  const etiquetasMatch = text.match(/Etiquetas\s+([\s\S]*?)(?:Compartir|$)/);
  const etiquetas = etiquetasMatch?.[1]?.trim() ?? null;

  return { reference, importancia, fechaPub, recursosAfectados, descripcion, solucion, etiquetas };
}

async function crawlAdvisoryDetail(
  url: string,
  _target: ListingTarget,
): Promise<AdvisoryRow | null> {
  try {
    const html = await fetchText(url);
    const fields = extractAdvisoryFields(html);
    const mainContent = extractMainContent(html);
    const bodyText = htmlToText(mainContent);

    if (bodyText.length < 80) {
      console.warn(`  Skipping ${url}: page content too short`);
      return null;
    }

    // Title — first reasonable line after navigation breadcrumb
    const titleMatch = html.match(/<title>([^<]+)<\/title>/i);
    let title = titleMatch?.[1] ?? "";
    title = title.replace(/\s*\|\s*INCIBE-?CERT.*$/i, "").replace(/\s+/g, " ").trim();

    // Fall back to URL slug
    if (!title) {
      const slug = url.split("/").pop() ?? "";
      title = slug.replace(/-/g, " ");
    }

    // Reference: prefer extracted INCIBE-YYYY-NNN, fall back to slug
    const slug = url.split("/").pop() ?? "";
    const reference = fields.reference ?? `INCIBE-AV-${slug}`.slice(0, 200);

    const date = fields.fechaPub ? parseSpanishDate(fields.fechaPub) : null;
    const severity = fields.importancia ? normaliseSeverity(fields.importancia) : "medium";

    // CVEs
    const cveSet = new Set<string>();
    const cveRe = /CVE-\d{4}-\d{4,}/g;
    let cm: RegExpExecArray | null;
    while ((cm = cveRe.exec(bodyText)) !== null) {
      cveSet.add(cm[0]);
    }
    const cves = Array.from(cveSet);

    const summary =
      fields.descripcion?.slice(0, 1800) ??
      bodyText.slice(0, 1800);

    // Compose full_text from the structured sections we extracted, fall back to whole body
    const fullTextParts: string[] = [];
    if (fields.recursosAfectados) fullTextParts.push(`Recursos Afectados:\n${fields.recursosAfectados}`);
    if (fields.descripcion) fullTextParts.push(`Descripción:\n${fields.descripcion}`);
    if (fields.solucion) fullTextParts.push(`Solución:\n${fields.solucion}`);
    if (fields.etiquetas) fullTextParts.push(`Etiquetas: ${fields.etiquetas}`);
    let fullText = fullTextParts.join("\n\n");
    if (fullText.length < 200) fullText = bodyText;
    fullText = fullText.slice(0, 50_000);

    return {
      reference,
      title: title.slice(0, 500),
      date,
      severity,
      affected_products: fields.recursosAfectados
        ? JSON.stringify([fields.recursosAfectados.slice(0, 1000)])
        : null,
      summary,
      full_text: fullText,
      cve_references: cves.length > 0 ? JSON.stringify(cves) : null,
      source_url: url,
    };
  } catch (err) {
    console.error(
      `  Error crawling advisory ${url}: ${err instanceof Error ? err.message : err}`,
    );
    return null;
  }
}

async function crawlGuidanceDetail(
  url: string,
  target: ListingTarget,
): Promise<GuidanceRow | null> {
  try {
    const html = await fetchText(url);
    const mainContent = extractMainContent(html);
    const bodyText = htmlToText(mainContent);

    if (bodyText.length < 150) {
      console.warn(`  Skipping ${url}: page content too short`);
      return null;
    }

    const titleMatch = html.match(/<title>([^<]+)<\/title>/i);
    let title = titleMatch?.[1] ?? "";
    title = title.replace(/\s*\|\s*INCIBE.*$/i, "").replace(/\s+/g, " ").trim();
    if (!title) {
      const slug = url.split("/").pop() ?? "";
      title = slug.replace(/-/g, " ");
    }

    // Fecha de publicación pattern matches guidance too
    const dateMatch = bodyText.match(/Fecha de publicaci[oó]n\s+(\d{2}\/\d{2}\/\d{4})/);
    const date = dateMatch?.[1] ? parseSpanishDate(dateMatch[1]) : null;

    // Reference = slug-based stable ID
    const slug = url.split("/").pop() ?? "";
    const seriesShort = target.series.replace(/[^A-Za-z0-9]/g, "");
    const reference = `${seriesShort}-${slug}`.slice(0, 240);

    // Summary: first substantial paragraph after the date/title block
    const paragraphs = bodyText
      .split(/\n\n+/)
      .map((p) => p.trim())
      .filter((p) => p.length > 80);
    const summary = (paragraphs[0] ?? bodyText.slice(0, 600)).slice(0, 2000);

    const topics = detectTopics(`${title} ${bodyText.slice(0, 4000)}`);

    return {
      reference,
      title: title.slice(0, 500),
      title_en: null,
      date,
      type: target.series.startsWith("Empresas-Blog") || target.series.endsWith("Blog")
        ? "blog_article"
        : "guide",
      series: target.series,
      summary,
      full_text: bodyText.slice(0, 50_000),
      topics: JSON.stringify(topics),
      status: "current",
      source_url: url,
    };
  } catch (err) {
    console.error(
      `  Error crawling guidance ${url}: ${err instanceof Error ? err.message : err}`,
    );
    return null;
  }
}

// ---------------------------------------------------------------------------
// Database insert helpers
// ---------------------------------------------------------------------------

function createInsertStatements(db: Database.Database) {
  const insertGuidance = db.prepare(`
    INSERT OR REPLACE INTO guidance
      (reference, title, title_en, date, type, series, summary, full_text, topics, status)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertAdvisory = db.prepare(`
    INSERT OR REPLACE INTO advisories
      (reference, title, date, severity, affected_products, summary, full_text, cve_references)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertFramework = db.prepare(
    "INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
  );

  const updateFrameworkCount = db.prepare(
    "UPDATE frameworks SET document_count = (SELECT count(*) FROM guidance WHERE series = ?) WHERE id = ?",
  );

  return { insertGuidance, insertAdvisory, insertFramework, updateFrameworkCount };
}

// ---------------------------------------------------------------------------
// Main orchestrator
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("INCIBE Ingestion Crawler");
  console.log("========================");
  console.log(`  Database:       ${DB_PATH}`);
  console.log(`  Max pages:      ${MAX_PAGES} per listing`);
  console.log(`  Rate limit:     ${RATE_LIMIT_MS}ms between requests`);
  console.log(`  Flags:          ${[force && "--force", dryRun && "--dry-run", resume && "--resume", advisoriesOnly && "--advisories-only", guidanceOnly && "--guidance-only"].filter(Boolean).join(", ") || "(none)"}`);
  console.log();

  const db = dryRun ? null : initDatabase();
  const stmts = db ? createInsertStatements(db) : null;
  const progress = loadProgress();

  let guidanceInserted = 0;
  let advisoriesInserted = 0;

  // ── Frameworks ──────────────────────────────────────────────────────────
  if (stmts && db) {
    console.log("\n=== Inserting frameworks ===");
    const insertFrameworks = db.transaction(() => {
      for (const f of FRAMEWORKS) {
        stmts.insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count);
      }
    });
    insertFrameworks();
    console.log(`  Inserted ${FRAMEWORKS.length} frameworks`);
  }

  // ── Advisories ──────────────────────────────────────────────────────────
  if (!guidanceOnly) {
    for (const target of ADVISORY_LISTINGS) {
      const urls = await discoverDetailUrls(target);
      console.log(`\n=== Crawling ${urls.length} advisories from ${target.name} ===`);

      for (let i = 0; i < urls.length; i++) {
        const url = urls[i]!;
        if (progress.completed_advisory_urls.includes(url)) {
          console.log(`  [${i + 1}/${urls.length}] skipped (already completed): ${url}`);
          continue;
        }

        console.log(`  [${i + 1}/${urls.length}] ${url}`);
        const row = await crawlAdvisoryDetail(url, target);
        if (row) {
          if (dryRun) {
            console.log(`    [dry-run] Would insert advisory: ${row.reference}`);
          } else if (stmts) {
            stmts.insertAdvisory.run(
              row.reference, row.title, row.date, row.severity,
              row.affected_products, row.summary, row.full_text,
              row.cve_references,
            );
            advisoriesInserted++;
          }
        }
        progress.completed_advisory_urls.push(url);
        if ((i + 1) % 5 === 0) saveProgress(progress);
      }
      saveProgress(progress);
    }
  }

  // ── Guidance ────────────────────────────────────────────────────────────
  if (!advisoriesOnly) {
    for (const target of GUIDANCE_LISTINGS) {
      const urls = await discoverDetailUrls(target);
      console.log(`\n=== Crawling ${urls.length} guidance docs from ${target.name} ===`);

      for (let i = 0; i < urls.length; i++) {
        const url = urls[i]!;
        if (progress.completed_guidance_urls.includes(url)) {
          console.log(`  [${i + 1}/${urls.length}] skipped (already completed): ${url}`);
          continue;
        }

        console.log(`  [${i + 1}/${urls.length}] ${url}`);
        const row = await crawlGuidanceDetail(url, target);
        if (row) {
          if (dryRun) {
            console.log(`    [dry-run] Would insert guidance: ${row.reference}`);
          } else if (stmts) {
            stmts.insertGuidance.run(
              row.reference, row.title, row.title_en, row.date,
              row.type, row.series, row.summary, row.full_text,
              row.topics, row.status,
            );
            guidanceInserted++;
          }
        }
        progress.completed_guidance_urls.push(url);
        if ((i + 1) % 5 === 0) saveProgress(progress);
      }
      saveProgress(progress);
    }
  }

  // ── Update framework document counts ────────────────────────────────────
  if (stmts && db && !dryRun) {
    // Advisories framework: row count from advisories table (no series column there)
    db.prepare(
      "UPDATE frameworks SET document_count = (SELECT count(*) FROM advisories) WHERE id = ?",
    ).run("incibe-cert-avisos");
    stmts.updateFrameworkCount.run("INCIBE-CERT-Guia", "incibe-cert-guias");
    stmts.updateFrameworkCount.run("Empresas-Guia", "incibe-empresas-guias");
    // Combine blog counts under one framework
    db.prepare(
      "UPDATE frameworks SET document_count = (SELECT count(*) FROM guidance WHERE series LIKE '%Blog%') WHERE id = ?",
    ).run("incibe-blog");
    console.log("\n  Updated framework document counts");
  }

  // ── Summary ─────────────────────────────────────────────────────────────
  if (db && !dryRun) {
    const guidanceCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
    const advisoryCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
    const frameworkCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;
    const guidanceFtsCount = (db.prepare("SELECT count(*) as cnt FROM guidance_fts").get() as { cnt: number }).cnt;
    const advisoryFtsCount = (db.prepare("SELECT count(*) as cnt FROM advisories_fts").get() as { cnt: number }).cnt;

    console.log("\n========================");
    console.log("Database summary:");
    console.log(`  Frameworks:      ${frameworkCount}`);
    console.log(`  Guidance docs:   ${guidanceCount} (FTS entries: ${guidanceFtsCount}) [+${guidanceInserted} this run]`);
    console.log(`  Advisories:      ${advisoryCount} (FTS entries: ${advisoryFtsCount}) [+${advisoriesInserted} this run]`);
    console.log(`\nDatabase ready at ${DB_PATH}`);

    db.close();
  }

  // Clean up progress file on successful full run (not resume)
  if (!resume && !dryRun && existsSync(PROGRESS_FILE)) {
    unlinkSync(PROGRESS_FILE);
    console.log("Cleaned up progress file");
  }

  console.log("\nDone.");
}

main().catch((err) => {
  console.error("\nFatal error:", err);
  process.exit(1);
});
