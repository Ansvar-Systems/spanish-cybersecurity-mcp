/**
 * Ingestion crawler for the CCN-CERT (Centro Criptológico Nacional) website.
 *
 * Scrapes ccn-cert.cni.es and populates the SQLite database with:
 *   - CCN-STIC guidance documents (guías)
 *   - Security advisories (avisos CCN-CERT)
 *   - Security alerts (alertas CCN-CERT)
 *   - Framework metadata (CCN-STIC, ENS, Avisos)
 *
 * Usage:
 *   npx tsx scripts/ingest-ccn.ts                  # full crawl
 *   npx tsx scripts/ingest-ccn.ts --resume          # skip already-ingested references
 *   npx tsx scripts/ingest-ccn.ts --dry-run         # fetch + parse, do not write to DB
 *   npx tsx scripts/ingest-ccn.ts --force           # drop and recreate DB before crawl
 *   npx tsx scripts/ingest-ccn.ts --max-pages 3     # limit listing pages per source
 *   npx tsx scripts/ingest-ccn.ts --advisories-only # only crawl advisories + alerts
 *   npx tsx scripts/ingest-ccn.ts --guides-only     # only crawl guides
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import * as cheerio from "cheerio";
import type { AnyNode } from "domhandler";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BASE_URL = "https://www.ccn-cert.cni.es";
const DB_PATH = process.env["CCN_DB_PATH"] ?? "data/ccn.db";

const RATE_LIMIT_MS = 1_500;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 3_000;
const REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_PAGES = 50;

const USER_AGENT =
  "AnsvarCCNCrawler/1.0 (+https://ansvar.eu; cybersecurity-research)";

// CLI flags
const args = process.argv.slice(2);
const FLAG_RESUME = args.includes("--resume");
const FLAG_DRY_RUN = args.includes("--dry-run");
const FLAG_FORCE = args.includes("--force");
const FLAG_ADVISORIES_ONLY = args.includes("--advisories-only");
const FLAG_GUIDES_ONLY = args.includes("--guides-only");

function parseFlagValue(flag: string): number | undefined {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  const val = Number(args[idx + 1]);
  return Number.isFinite(val) ? val : undefined;
}

const MAX_PAGES = parseFlagValue("--max-pages") ?? DEFAULT_MAX_PAGES;

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(msg: string): void {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${msg}`);
}

function warn(msg: string): void {
  const ts = new Date().toISOString();
  console.warn(`[${ts}] WARN: ${msg}`);
}

function error(msg: string): void {
  const ts = new Date().toISOString();
  console.error(`[${ts}] ERROR: ${msg}`);
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

let lastRequestTime = 0;

async function rateLimit(): Promise<void> {
  const elapsed = Date.now() - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }
  lastRequestTime = Date.now();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchPage(url: string): Promise<string> {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    await rateLimit();
    try {
      const controller = new AbortController();
      const timer = setTimeout(
        () => controller.abort(),
        REQUEST_TIMEOUT_MS,
      );
      const res = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          Accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "es-ES,es;q=0.9,en;q=0.5",
        },
        signal: controller.signal,
        redirect: "follow",
      });
      clearTimeout(timer);

      if (!res.ok) {
        throw new Error(`HTTP ${res.status} ${res.statusText} for ${url}`);
      }
      return await res.text();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (attempt < MAX_RETRIES) {
        const backoff = RETRY_BACKOFF_MS * attempt;
        warn(
          `Attempt ${attempt}/${MAX_RETRIES} failed for ${url}: ${msg}. Retrying in ${backoff}ms...`,
        );
        await sleep(backoff);
      } else {
        error(
          `All ${MAX_RETRIES} attempts failed for ${url}: ${msg}`,
        );
        throw err;
      }
    }
  }
  throw new Error("Unreachable");
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ListingEntry {
  url: string;
  title: string;
  date: string | null;
}

interface ParsedAdvisory {
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null;
  summary: string | null;
  full_text: string;
  cve_references: string | null;
}

interface ParsedGuidance {
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string;
  series: string;
  summary: string | null;
  full_text: string;
  topics: string | null;
  status: string;
}

// ---------------------------------------------------------------------------
// Date parsing (Spanish)
// ---------------------------------------------------------------------------

const SPANISH_MONTHS: Record<string, string> = {
  enero: "01",
  febrero: "02",
  marzo: "03",
  abril: "04",
  mayo: "05",
  junio: "06",
  julio: "07",
  agosto: "08",
  septiembre: "09",
  octubre: "10",
  noviembre: "11",
  diciembre: "12",
  // Abbreviated forms sometimes seen
  ene: "01",
  feb: "02",
  mar: "03",
  abr: "04",
  may: "05",
  jun: "06",
  jul: "07",
  ago: "08",
  sep: "09",
  oct: "10",
  nov: "11",
  dic: "12",
};

/**
 * Parse dates in formats:
 *   "30 Enero 2026", "01/04/2024", "April 1, 2024", "2024-01-12"
 * Returns ISO date string (YYYY-MM-DD) or null.
 */
function parseDate(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const s = raw.trim();

  // ISO format already
  const isoMatch = s.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (isoMatch) return `${isoMatch[1]}-${isoMatch[2]}-${isoMatch[3]}`;

  // DD/MM/YYYY
  const slashMatch = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (slashMatch) {
    const dd = slashMatch[1]!.padStart(2, "0");
    const mm = slashMatch[2]!.padStart(2, "0");
    return `${slashMatch[3]}-${mm}-${dd}`;
  }

  // "DD Month YYYY" (Spanish)
  const spanishMatch = s.match(
    /^(\d{1,2})\s+(\w+)\s+(\d{4})/i,
  );
  if (spanishMatch) {
    const dd = spanishMatch[1]!.padStart(2, "0");
    const monthName = spanishMatch[2]!.toLowerCase();
    const mm = SPANISH_MONTHS[monthName];
    if (mm) return `${spanishMatch[3]}-${mm}-${dd}`;
  }

  // "Month DD, YYYY" (English)
  const englishMonths: Record<string, string> = {
    january: "01", february: "02", march: "03", april: "04",
    may: "05", june: "06", july: "07", august: "08",
    september: "09", october: "10", november: "11", december: "12",
  };
  const engMatch = s.match(
    /^(\w+)\s+(\d{1,2}),?\s+(\d{4})/i,
  );
  if (engMatch) {
    const monthName = engMatch[1]!.toLowerCase();
    const mm = englishMonths[monthName];
    if (mm) {
      const dd = engMatch[2]!.padStart(2, "0");
      return `${engMatch[3]}-${mm}-${dd}`;
    }
  }

  warn(`Could not parse date: "${s}"`);
  return null;
}

// ---------------------------------------------------------------------------
// Reference extraction
// ---------------------------------------------------------------------------

/**
 * Extract the CCN-CERT advisory/alert reference from a title string.
 * E.g. "CCN-CERT AV 01/26 Vulnerabilidades..." => "CCN-CERT-AV-26/001"
 * E.g. "CCN-CERT AL 03/25 ..." => "CCN-CERT-AL-25/003"
 */
function extractAdvisoryReference(title: string): string {
  // Match patterns: "CCN-CERT AV 01/26", "CCN-CERT AL 12/25"
  const match = title.match(
    /CCN-CERT\s+(AV|AL)\s+(\d{1,3})\/(\d{2,4})/i,
  );
  if (match) {
    const type = match[1]!.toUpperCase();
    const num = match[2]!.padStart(2, "0");
    const year = match[3]!.length === 2 ? match[3]! : match[3]!.slice(-2);
    return `CCN-CERT-${type}-${year}/${num}`;
  }
  // Fallback: use a slug of the title
  return `CCN-CERT-${title.slice(0, 60).replace(/\s+/g, "-").replace(/[^A-Za-z0-9-]/g, "")}`;
}

/**
 * Extract CCN-STIC reference from guide title.
 * E.g. "CCN-STIC-807 Criptografía..." => "CCN-STIC-807"
 * E.g. "CCN-STIC-808 Anexo III..." => "CCN-STIC-808-Anexo-III"
 */
function extractGuideReference(title: string): string {
  // Match "CCN-STIC-NNN" or "CCN-CERT-NNN" optionally with suffix
  const match = title.match(
    /(CCN-(?:STIC|CERT)-\d{1,5}[A-Za-z]*(?:\s*[-–]\s*[A-Za-z]+(?:\s+[A-Za-z0-9]+)*)?)/,
  );
  if (match) {
    // Normalise: collapse spaces around dashes, limit length
    let ref = match[1]!.trim();
    // Keep it to a reasonable reference length
    if (ref.length > 40) {
      ref = ref.slice(0, 40).trimEnd();
    }
    return ref.replace(/\s+/g, " ");
  }

  // Try numeric-only: "807", "808 Anexo III"
  const numMatch = title.match(/^(\d{1,5}[A-Za-z]*)/);
  if (numMatch) {
    return `CCN-STIC-${numMatch[1]}`;
  }

  return `CCN-STIC-${title.slice(0, 40).replace(/\s+/g, "-").replace(/[^A-Za-z0-9-]/g, "")}`;
}

// ---------------------------------------------------------------------------
// Series detection
// ---------------------------------------------------------------------------

function detectSeries(reference: string): string {
  const numMatch = reference.match(/CCN-STIC-(\d+)/);
  if (!numMatch) return "CCN-STIC";
  const num = parseInt(numMatch[1]!, 10);
  if (num < 100) return "000-Politicas";
  if (num < 200) return "100-Procedimientos";
  if (num < 300) return "200-Normas";
  if (num < 400) return "300-Instrucciones";
  if (num < 500) return "400-Generales";
  if (num < 600) return "500-Windows";
  if (num < 700) return "600-Otros-entornos";
  if (num < 800) return "700-Otros";
  if (num < 900) return "800-ENS";
  if (num < 1000) return "900-Informes";
  return "1000-PES";
}

function detectType(reference: string, series: string): string {
  if (series.startsWith("800")) return "ens_guide";
  if (series.startsWith("1000")) return "secure_usage_procedure";
  if (series.startsWith("900")) return "technical_report";
  if (series.startsWith("300")) return "technical_instruction";
  if (series.startsWith("000")) return "policy";
  if (series.startsWith("100")) return "procedure";
  if (series.startsWith("200")) return "standard";
  return "technical_guideline";
}

// ---------------------------------------------------------------------------
// Listing page scrapers
// ---------------------------------------------------------------------------

const GUIDE_SERIES_URLS: { series: string; path: string }[] = [
  {
    series: "000-Politicas",
    path: "/es/pdf/guias/series-ccn-stic/guias-de-acceso-publico-ccn-stic.html",
  },
  {
    series: "400-Generales",
    path: "/es/pdf/guias/series-ccn-stic/400-guias-generales.html",
  },
  {
    series: "500-Windows",
    path: "/es/pdf/guias/series-ccn-stic/500-guias-de-entornos-windows.html",
  },
  {
    series: "600-Otros-entornos",
    path: "/es/pdf/guias/series-ccn-stic/600-guias-de-otros-entornos.html",
  },
  {
    series: "800-ENS",
    path: "/es/pdf/guias/series-ccn-stic/800-guia-esquema-nacional-de-seguridad.html",
  },
  {
    series: "1000-PES",
    path: "/es/pdf/guias/series-ccn-stic/1000-procedimientos-de-empleo-seguro.html",
  },
];

/**
 * Scrape a paginated listing page that uses a tablesorter2 or standard
 * link list. Returns all entry URLs + titles found across pages.
 */
async function scrapeListingPages(
  basePath: string,
  maxPages: number,
): Promise<ListingEntry[]> {
  const entries: ListingEntry[] = [];
  const seenUrls = new Set<string>();

  for (let page = 0; page < maxPages; page++) {
    const offset = page * 20;
    const sep = basePath.includes("?") ? "&" : "?";
    const url =
      page === 0
        ? `${BASE_URL}${basePath}`
        : `${BASE_URL}${basePath}${sep}start=${offset}`;

    log(`Fetching listing page ${page + 1}: ${url}`);
    let html: string;
    try {
      html = await fetchPage(url);
    } catch {
      warn(`Failed to fetch listing page ${page + 1}, stopping pagination.`);
      break;
    }

    const $ = cheerio.load(html);
    let foundOnPage = 0;

    // Strategy 1: table rows with links (advisories/alerts use tablesorter2)
    $("table.tablesorter2 tbody tr, table.table tbody tr").each((_, row) => {
      const link = $(row).find("a[href]").first();
      const href = link.attr("href");
      const title = link.text().trim();
      const dateCell = $(row).find("td").last().text().trim();

      if (href && title && !seenUrls.has(href)) {
        seenUrls.add(href);
        const fullUrl = href.startsWith("http")
          ? href
          : `${BASE_URL}${href}`;
        entries.push({
          url: fullUrl,
          title,
          date: parseDate(dateCell),
        });
        foundOnPage++;
      }
    });

    // Strategy 2: standard document links in category listings (guides)
    if (foundOnPage === 0) {
      $(
        "a[href*='/file.html'], a[href*='series-ccn-stic'], a[href*='avisos-ccn-cert'], a[href*='alertas-ccn-cert']",
      ).each((_, el) => {
        const href = $(el).attr("href");
        const title = $(el).text().trim();
        if (
          href &&
          title &&
          title.length > 5 &&
          !seenUrls.has(href) &&
          !href.endsWith("guias.html") &&
          !href.includes("?start=")
        ) {
          seenUrls.add(href);
          const fullUrl = href.startsWith("http")
            ? href
            : `${BASE_URL}${href}`;

          // Try to find an adjacent date
          const parent = $(el).closest("tr, li, div, .item");
          const dateText =
            parent.find(".date, time, .created, td:last-child").text().trim() ||
            null;

          entries.push({
            url: fullUrl,
            title,
            date: parseDate(dateText),
          });
          foundOnPage++;
        }
      });
    }

    log(`  Found ${foundOnPage} entries on page ${page + 1}`);

    if (foundOnPage === 0) {
      log("  No entries found, stopping pagination.");
      break;
    }

    // Check if there is a next page
    const hasNext =
      $(`a[href*="start=${offset + 20}"]`).length > 0 ||
      $("a.pagination-next, a:contains('»'), a:contains('Siguiente')").length >
        0;
    if (!hasNext) {
      log("  No next page link found, stopping pagination.");
      break;
    }
  }

  return entries;
}

// ---------------------------------------------------------------------------
// Detail page parsers
// ---------------------------------------------------------------------------

/**
 * Severity mapping: normalise Spanish severity labels to lowercase English.
 */
function normaliseSeverity(raw: string): string {
  const s = raw.toLowerCase().trim();
  if (s.includes("crític") || s.includes("critical")) return "critical";
  if (s.includes("alt") || s.includes("high")) return "high";
  if (s.includes("medi") || s.includes("medium")) return "medium";
  if (s.includes("baj") || s.includes("low")) return "low";
  if (s.includes("informativ") || s.includes("info")) return "informational";
  return s;
}

/**
 * Extract CVE references from text.
 */
function extractCVEs(text: string): string | null {
  const cves = new Set<string>();
  const pattern = /CVE-\d{4}-\d{4,}/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    cves.add(match[0]);
  }
  return cves.size > 0 ? [...cves].sort().join(", ") : null;
}

/**
 * Parse an advisory or alert detail page.
 */
async function parseAdvisoryPage(
  url: string,
  listingTitle: string,
  listingDate: string | null,
): Promise<ParsedAdvisory | null> {
  let html: string;
  try {
    html = await fetchPage(url);
  } catch {
    error(`Failed to fetch advisory detail: ${url}`);
    return null;
  }

  const $ = cheerio.load(html);

  // Title: prefer h1, fall back to listing title
  const pageTitle =
    $("h1").first().text().trim() ||
    $("h2").first().text().trim() ||
    listingTitle;

  const title = pageTitle || listingTitle;
  const reference = extractAdvisoryReference(title);

  // Date: look for "Publicado:" or "Fecha de publicación" text
  let date = listingDate;
  const datePatterns = [
    /(?:Publicado|Fecha\s+de\s+publicaci[oó]n)[:\s]*(\d{1,2}[\/\s]\w+[\/\s]\d{4})/i,
    /(\d{1,2}\/\d{1,2}\/\d{4})/,
    /(\d{1,2}\s+\w+\s+\d{4})/,
  ];
  const bodyHtml = $.html();
  for (const pattern of datePatterns) {
    const match = bodyHtml.match(pattern);
    if (match?.[1]) {
      const parsed = parseDate(match[1]);
      if (parsed) {
        date = parsed;
        break;
      }
    }
  }

  // Severity: look for "Nivel de peligrosidad" or "Peligrosidad"
  let severity: string | null = null;
  const severityMatch = bodyHtml.match(
    /(?:Nivel\s+de\s+peligrosidad|Peligrosidad)[:\s]*[<>\w\s="'-]*?(CR[ÍI]TICO|ALTO|MEDIO|BAJO|CRITICAL|HIGH|MEDIUM|LOW)/i,
  );
  if (severityMatch?.[1]) {
    severity = normaliseSeverity(severityMatch[1]);
  }

  // Content: extract text from the main article body
  // CCN-CERT uses Joomla; content is typically in .item-page, .com-content-article,
  // or the main sppb-row-container
  const contentSelectors = [
    ".item-page",
    ".com-content-article",
    "article",
    ".sppb-row-container",
    "#sp-component",
    ".item-detail-container",
    "main",
  ];

  let contentEl: cheerio.Cheerio<AnyNode> | null = null;
  for (const sel of contentSelectors) {
    const el = $(sel).first();
    if (el.length > 0 && el.text().trim().length > 100) {
      contentEl = el;
      break;
    }
  }

  const fullText = contentEl
    ? cleanText(contentEl.text())
    : cleanText($("body").text());

  // Summary: first meaningful paragraph
  let summary: string | null = null;
  if (contentEl) {
    contentEl.find("p").each((_, p) => {
      if (summary) return;
      const pText = $(p).text().trim();
      if (pText.length > 80) {
        summary = pText.slice(0, 500);
      }
    });
  }
  if (!summary && fullText.length > 100) {
    summary = fullText.slice(0, 500);
  }

  // Affected products: look for "Recursos afectados" or "Productos afectados" section
  let affectedProducts: string | null = null;
  const affectedMatch = bodyHtml.match(
    /(?:Recursos\s+afectados|Productos?\s+afectados?|Vulnerabilidades\s+y\s+recursos\s+afectados)[^]*?<\/(?:table|ul|ol|p|div)>/i,
  );
  if (affectedMatch) {
    const affected$ = cheerio.load(affectedMatch[0]);
    const affectedText = cleanText(affected$.text());
    if (affectedText.length > 10) {
      affectedProducts = affectedText.slice(0, 1000);
    }
  }

  // CVEs from full text
  const cves = extractCVEs(fullText);

  if (fullText.length < 50) {
    warn(`Advisory body too short for ${reference} (${fullText.length} chars), skipping.`);
    return null;
  }

  return {
    reference,
    title: title.slice(0, 500),
    date,
    severity,
    affected_products: affectedProducts,
    summary,
    full_text: fullText,
    cve_references: cves,
  };
}

/**
 * Parse a guide detail page.
 *
 * Guide pages on CCN-CERT link to PDF files; the listing page itself often
 * has the title and date. For PDF-only guides we store the metadata with the
 * listing information and a note that the full text is in the linked PDF.
 */
async function parseGuidePage(
  url: string,
  listingTitle: string,
  listingDate: string | null,
  seriesHint: string,
): Promise<ParsedGuidance | null> {
  let html: string;
  try {
    html = await fetchPage(url);
  } catch {
    error(`Failed to fetch guide page: ${url}`);
    return null;
  }

  const $ = cheerio.load(html);

  const pageTitle =
    $("h1").first().text().trim() ||
    $("h2").first().text().trim() ||
    listingTitle;

  const title = pageTitle || listingTitle;
  const reference = extractGuideReference(title);

  // Date
  let date = listingDate;
  const datePatterns = [
    /(?:Publicado|Fecha)[:\s]*(\d{1,2}[\/\s]\w+[\/\s]\d{4})/i,
    /(\d{1,2}\/\d{1,2}\/\d{4})/,
  ];
  const bodyHtml = $.html();
  for (const pattern of datePatterns) {
    const match = bodyHtml.match(pattern);
    if (match?.[1]) {
      const parsed = parseDate(match[1]);
      if (parsed) {
        date = parsed;
        break;
      }
    }
  }

  // Series and type
  const series = seriesHint || detectSeries(reference);
  const type = detectType(reference, series);

  // Content: guides may be HTML pages or just PDF landing pages
  const contentSelectors = [
    ".item-page",
    ".com-content-article",
    "article",
    ".sppb-row-container",
    "#sp-component",
    "main",
  ];

  let contentEl: cheerio.Cheerio<AnyNode> | null = null;
  for (const sel of contentSelectors) {
    const el = $(sel).first();
    if (el.length > 0 && el.text().trim().length > 50) {
      contentEl = el;
      break;
    }
  }

  let fullText = contentEl
    ? cleanText(contentEl.text())
    : cleanText($("body").text());

  // If the page is just a PDF download landing page, the text will be short.
  // Construct a meaningful record from the metadata we have.
  if (fullText.length < 100) {
    fullText = `${reference} — ${title}. Guía CCN-STIC del Centro Criptológico Nacional. Serie: ${series}. Tipo: ${type}. Fuente: ${url}`;
  }

  // Summary
  let summary: string | null = null;
  if (contentEl) {
    contentEl.find("p").each((_, p) => {
      if (summary) return;
      const pText = $(p).text().trim();
      if (pText.length > 60) {
        summary = pText.slice(0, 500);
      }
    });
  }

  // Topics: extract from keywords meta tag or title words
  let topics: string | null = null;
  const metaKeywords = $('meta[name="keywords"]').attr("content");
  if (metaKeywords) {
    const kws = metaKeywords
      .split(",")
      .map((k) => k.trim())
      .filter((k) => k.length > 0);
    if (kws.length > 0) {
      topics = JSON.stringify(kws);
    }
  }
  if (!topics) {
    // Derive topics from title and series
    const derivedTopics: string[] = [];
    if (series.includes("ENS")) derivedTopics.push("ENS");
    if (title.toLowerCase().includes("seguridad")) derivedTopics.push("seguridad");
    if (title.toLowerCase().includes("cifrad") || title.toLowerCase().includes("criptol"))
      derivedTopics.push("criptografía");
    if (title.toLowerCase().includes("windows") || title.toLowerCase().includes("active directory"))
      derivedTopics.push("Windows");
    if (title.toLowerCase().includes("linux") || title.toLowerCase().includes("debian"))
      derivedTopics.push("Linux");
    if (title.toLowerCase().includes("cloud") || title.toLowerCase().includes("nube"))
      derivedTopics.push("cloud");
    if (title.toLowerCase().includes("red") || title.toLowerCase().includes("network"))
      derivedTopics.push("redes");
    if (derivedTopics.length > 0) {
      topics = JSON.stringify(derivedTopics);
    }
  }

  // English title: check for English page variant
  let titleEn: string | null = null;
  const enLink = $('a[href*="/en/"]').first().attr("href");
  if (enLink) {
    // We note the English URL but don't fetch it to stay within rate limits
    titleEn = null;
  }

  return {
    reference,
    title: title.slice(0, 500),
    title_en: titleEn,
    date,
    type,
    series,
    summary,
    full_text: fullText,
    topics,
    status: "current",
  };
}

// ---------------------------------------------------------------------------
// Text cleaning
// ---------------------------------------------------------------------------

function cleanText(raw: string): string {
  return raw
    .replace(/\s+/g, " ") // collapse whitespace
    .replace(/\n{3,}/g, "\n\n") // collapse blank lines
    .replace(/^\s+|\s+$/g, "") // trim
    .replace(/\t/g, " ") // tabs to spaces
    .slice(0, 50_000); // cap at 50k chars to prevent DB bloat
}

// ---------------------------------------------------------------------------
// Database operations
// ---------------------------------------------------------------------------

function initDb(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
    log(`Created data directory: ${dir}`);
  }

  if (FLAG_FORCE && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    log(`Deleted existing database (--force).`);
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);

  log(`Database ready at ${DB_PATH}`);
  return db;
}

function getExistingReferences(
  db: Database.Database,
  table: string,
): Set<string> {
  const rows = db
    .prepare(`SELECT reference FROM ${table}`)
    .all() as { reference: string }[];
  return new Set(rows.map((r) => r.reference));
}

function insertGuidance(
  db: Database.Database,
  g: ParsedGuidance,
): void {
  db.prepare(
    `INSERT OR REPLACE INTO guidance
      (reference, title, title_en, date, type, series, summary, full_text, topics, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    g.reference,
    g.title,
    g.title_en,
    g.date,
    g.type,
    g.series,
    g.summary,
    g.full_text,
    g.topics,
    g.status,
  );
}

function insertAdvisory(
  db: Database.Database,
  a: ParsedAdvisory,
): void {
  db.prepare(
    `INSERT OR REPLACE INTO advisories
      (reference, title, date, severity, affected_products, summary, full_text, cve_references)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    a.reference,
    a.title,
    a.date,
    a.severity,
    a.affected_products,
    a.summary,
    a.full_text,
    a.cve_references,
  );
}

function upsertFrameworks(db: Database.Database): void {
  const frameworks = [
    {
      id: "ccn-stic",
      name: "Guías CCN-STIC",
      name_en: "CCN-STIC Technical Guidelines",
      description:
        "Las Guías CCN-STIC son documentos técnicos del Centro Criptológico Nacional (CCN) con recomendaciones y requisitos de seguridad para sistemas de información. Se organizan en series: 000 (Política), 100 (Procedimientos), 200 (Normas), 300 (Instrucciones), 400 (Generales), 500 (Windows), 600 (Otros entornos), 800 (ENS), 900 (Informes), 1000 (PES).",
    },
    {
      id: "ens",
      name: "Esquema Nacional de Seguridad (ENS)",
      name_en: "National Security Framework (ENS)",
      description:
        "El Esquema Nacional de Seguridad (ENS), aprobado por Real Decreto 311/2022, establece la política de seguridad para el uso de medios electrónicos en las Administraciones Públicas. Define categorías ALTA, MEDIA y BÁSICA y medidas de seguridad en tres dimensiones: marco organizativo, marco operacional y medidas de protección.",
    },
    {
      id: "ccn-cert-av",
      name: "Avisos CCN-CERT",
      name_en: "CCN-CERT Advisories",
      description:
        "Los Avisos de Seguridad del CCN-CERT informan sobre vulnerabilidades y amenazas de ciberseguridad. Se clasifican por peligrosidad: CRÍTICO, ALTO, MEDIO, BAJO. Incluyen descripción, productos afectados, solución y referencias CVE.",
    },
    {
      id: "ccn-cert-al",
      name: "Alertas CCN-CERT",
      name_en: "CCN-CERT Alerts",
      description:
        "Las Alertas del CCN-CERT informan sobre vulnerabilidades críticas con explotación activa confirmada o amenazas inminentes que requieren acción inmediata. Mayor urgencia que los avisos.",
    },
  ];

  const stmt = db.prepare(
    `INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count)
     VALUES (?, ?, ?, ?, (SELECT COUNT(*) FROM guidance WHERE series LIKE '%' || ? || '%'))`,
  );

  for (const f of frameworks) {
    // For advisory/alert frameworks, count from advisories table
    if (f.id === "ccn-cert-av" || f.id === "ccn-cert-al") {
      const refPrefix = f.id === "ccn-cert-av" ? "CCN-CERT-AV" : "CCN-CERT-AL";
      const count = (
        db
          .prepare(
            "SELECT COUNT(*) as n FROM advisories WHERE reference LIKE ?",
          )
          .get(`${refPrefix}%`) as { n: number }
      ).n;
      db.prepare(
        "INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
      ).run(f.id, f.name, f.name_en, f.description, count);
    } else {
      // For guidance frameworks, count from guidance table
      const seriesKey = f.id === "ens" ? "ENS" : "CCN-STIC";
      const count = (
        db
          .prepare(
            "SELECT COUNT(*) as n FROM guidance WHERE series LIKE ?",
          )
          .get(`%${seriesKey}%`) as { n: number }
      ).n;
      db.prepare(
        "INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
      ).run(f.id, f.name, f.name_en, f.description, count);
    }
  }

  log("Frameworks updated.");
}

// ---------------------------------------------------------------------------
// Crawl orchestration
// ---------------------------------------------------------------------------

async function crawlAdvisories(
  db: Database.Database,
  basePath: string,
  label: string,
): Promise<{ ingested: number; skipped: number; failed: number }> {
  log(`--- Crawling ${label} ---`);

  const entries = await scrapeListingPages(basePath, MAX_PAGES);
  log(`Found ${entries.length} ${label} listing entries.`);

  const existing = FLAG_RESUME
    ? getExistingReferences(db, "advisories")
    : new Set<string>();

  let ingested = 0;
  let skipped = 0;
  let failed = 0;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]!;
    const reference = extractAdvisoryReference(entry.title);

    if (FLAG_RESUME && existing.has(reference)) {
      skipped++;
      continue;
    }

    log(
      `[${i + 1}/${entries.length}] Parsing ${label}: ${reference} — ${entry.title.slice(0, 80)}`,
    );

    const parsed = await parseAdvisoryPage(
      entry.url,
      entry.title,
      entry.date,
    );

    if (!parsed) {
      failed++;
      continue;
    }

    if (FLAG_DRY_RUN) {
      log(
        `  [dry-run] Would insert: ${parsed.reference} | severity=${parsed.severity} | CVEs=${parsed.cve_references ?? "none"} | ${parsed.full_text.length} chars`,
      );
    } else {
      insertAdvisory(db, parsed);
    }
    ingested++;
  }

  return { ingested, skipped, failed };
}

async function crawlGuides(
  db: Database.Database,
): Promise<{ ingested: number; skipped: number; failed: number }> {
  log(`--- Crawling CCN-STIC Guides ---`);

  const existing = FLAG_RESUME
    ? getExistingReferences(db, "guidance")
    : new Set<string>();

  let totalIngested = 0;
  let totalSkipped = 0;
  let totalFailed = 0;

  for (const seriesDef of GUIDE_SERIES_URLS) {
    log(`\nSeries: ${seriesDef.series}`);

    const entries = await scrapeListingPages(seriesDef.path, MAX_PAGES);
    log(`Found ${entries.length} guide entries in ${seriesDef.series}.`);

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i]!;

      // Skip non-guide links (pagination, breadcrumbs, etc.)
      if (
        entry.url.includes("?start=") ||
        entry.title.length < 5 ||
        entry.url === `${BASE_URL}${seriesDef.path}`
      ) {
        continue;
      }

      const reference = extractGuideReference(entry.title);

      if (FLAG_RESUME && existing.has(reference)) {
        totalSkipped++;
        continue;
      }

      log(
        `[${i + 1}/${entries.length}] Parsing guide: ${reference} — ${entry.title.slice(0, 80)}`,
      );

      const parsed = await parseGuidePage(
        entry.url,
        entry.title,
        entry.date,
        seriesDef.series,
      );

      if (!parsed) {
        totalFailed++;
        continue;
      }

      if (FLAG_DRY_RUN) {
        log(
          `  [dry-run] Would insert: ${parsed.reference} | series=${parsed.series} | type=${parsed.type} | ${parsed.full_text.length} chars`,
        );
      } else {
        insertGuidance(db, parsed);
      }
      totalIngested++;
    }
  }

  return {
    ingested: totalIngested,
    skipped: totalSkipped,
    failed: totalFailed,
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  log("=== CCN-CERT Ingestion Crawler ===");
  log(
    `Flags: resume=${FLAG_RESUME} dry-run=${FLAG_DRY_RUN} force=${FLAG_FORCE} max-pages=${MAX_PAGES}`,
  );

  if (FLAG_ADVISORIES_ONLY && FLAG_GUIDES_ONLY) {
    error("Cannot use --advisories-only and --guides-only together.");
    process.exit(1);
  }

  const db = FLAG_DRY_RUN ? null : initDb();

  // Use a no-op DB for dry runs
  const dbOrDummy = db ?? initDb();

  const stats = {
    advisories: { ingested: 0, skipped: 0, failed: 0 },
    alerts: { ingested: 0, skipped: 0, failed: 0 },
    guides: { ingested: 0, skipped: 0, failed: 0 },
  };

  try {
    // --- Advisories (avisos) ---
    if (!FLAG_GUIDES_ONLY) {
      stats.advisories = await crawlAdvisories(
        dbOrDummy,
        "/es/seguridad-al-dia/avisos-ccn-cert.html",
        "advisories (avisos)",
      );

      // --- Alerts (alertas) --- stored in the same advisories table
      stats.alerts = await crawlAdvisories(
        dbOrDummy,
        "/es/seguridad-al-dia/alertas-ccn-cert.html",
        "alerts (alertas)",
      );
    }

    // --- Guides (guías CCN-STIC) ---
    if (!FLAG_ADVISORIES_ONLY) {
      stats.guides = await crawlGuides(dbOrDummy);
    }

    // --- Update framework counts ---
    if (!FLAG_DRY_RUN) {
      upsertFrameworks(dbOrDummy);
    }
  } finally {
    // Print summary
    log("\n=== Ingestion Summary ===");

    if (!FLAG_GUIDES_ONLY) {
      log(
        `Advisories: ${stats.advisories.ingested} ingested, ${stats.advisories.skipped} skipped, ${stats.advisories.failed} failed`,
      );
      log(
        `Alerts:     ${stats.alerts.ingested} ingested, ${stats.alerts.skipped} skipped, ${stats.alerts.failed} failed`,
      );
    }

    if (!FLAG_ADVISORIES_ONLY) {
      log(
        `Guides:     ${stats.guides.ingested} ingested, ${stats.guides.skipped} skipped, ${stats.guides.failed} failed`,
      );
    }

    if (!FLAG_DRY_RUN) {
      const guidanceCount = (
        dbOrDummy
          .prepare("SELECT COUNT(*) as n FROM guidance")
          .get() as { n: number }
      ).n;
      const advisoryCount = (
        dbOrDummy
          .prepare("SELECT COUNT(*) as n FROM advisories")
          .get() as { n: number }
      ).n;
      const frameworkCount = (
        dbOrDummy
          .prepare("SELECT COUNT(*) as n FROM frameworks")
          .get() as { n: number }
      ).n;

      log(`\nDatabase totals:`);
      log(`  Guidance documents: ${guidanceCount}`);
      log(`  Advisories/Alerts:  ${advisoryCount}`);
      log(`  Frameworks:         ${frameworkCount}`);
    }

    dbOrDummy.close();
    log("\nIngestion complete.");
  }
}

main().catch((err) => {
  error(`Fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
