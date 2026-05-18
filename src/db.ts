/**
 * SQLite database access layer for the Spanish Cybersecurity (CCN-CERT) MCP server.
 *
 * Schema:
 *   - guidance    — CCN-STIC guidelines and technical reports
 *   - advisories  — CCN-CERT security advisories and alerts
 *   - frameworks  — CCN framework series (CCN-STIC, ENS)
 *
 * FTS5 virtual tables back full-text search on guidance and advisories.
 */

import Database from "better-sqlite3";

const DB_PATH = process.env["CCN_DB_PATH"] ?? "data/ccn.db";

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS guidance (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  reference  TEXT    NOT NULL UNIQUE,
  title      TEXT    NOT NULL,
  title_en   TEXT,
  date       TEXT,
  type       TEXT,
  series     TEXT,
  summary    TEXT,
  full_text  TEXT    NOT NULL,
  topics     TEXT,
  status     TEXT    DEFAULT 'current'
);

CREATE INDEX IF NOT EXISTS idx_guidance_date   ON guidance(date);
CREATE INDEX IF NOT EXISTS idx_guidance_type   ON guidance(type);
CREATE INDEX IF NOT EXISTS idx_guidance_series ON guidance(series);
CREATE INDEX IF NOT EXISTS idx_guidance_status ON guidance(status);

CREATE VIRTUAL TABLE IF NOT EXISTS guidance_fts USING fts5(
  reference, title, title_en, summary, full_text,
  content='guidance',
  content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS guidance_ai AFTER INSERT ON guidance BEGIN
  INSERT INTO guidance_fts(rowid, reference, title, title_en, summary, full_text)
  VALUES (new.id, new.reference, new.title, COALESCE(new.title_en, ''), COALESCE(new.summary, ''), new.full_text);
END;

CREATE TRIGGER IF NOT EXISTS guidance_ad AFTER DELETE ON guidance BEGIN
  INSERT INTO guidance_fts(guidance_fts, rowid, reference, title, title_en, summary, full_text)
  VALUES ('delete', old.id, old.reference, old.title, COALESCE(old.title_en, ''), COALESCE(old.summary, ''), old.full_text);
END;

CREATE TRIGGER IF NOT EXISTS guidance_au AFTER UPDATE ON guidance BEGIN
  INSERT INTO guidance_fts(guidance_fts, rowid, reference, title, title_en, summary, full_text)
  VALUES ('delete', old.id, old.reference, old.title, COALESCE(old.title_en, ''), COALESCE(old.summary, ''), old.full_text);
  INSERT INTO guidance_fts(rowid, reference, title, title_en, summary, full_text)
  VALUES (new.id, new.reference, new.title, COALESCE(new.title_en, ''), COALESCE(new.summary, ''), new.full_text);
END;

CREATE TABLE IF NOT EXISTS advisories (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  reference         TEXT    NOT NULL UNIQUE,
  title             TEXT    NOT NULL,
  date              TEXT,
  severity          TEXT,
  affected_products TEXT,
  summary           TEXT,
  full_text         TEXT    NOT NULL,
  cve_references    TEXT
);

CREATE INDEX IF NOT EXISTS idx_advisories_date     ON advisories(date);
CREATE INDEX IF NOT EXISTS idx_advisories_severity ON advisories(severity);

CREATE VIRTUAL TABLE IF NOT EXISTS advisories_fts USING fts5(
  reference, title, summary, full_text,
  content='advisories',
  content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS advisories_ai AFTER INSERT ON advisories BEGIN
  INSERT INTO advisories_fts(rowid, reference, title, summary, full_text)
  VALUES (new.id, new.reference, new.title, COALESCE(new.summary, ''), new.full_text);
END;

CREATE TRIGGER IF NOT EXISTS advisories_ad AFTER DELETE ON advisories BEGIN
  INSERT INTO advisories_fts(advisories_fts, rowid, reference, title, summary, full_text)
  VALUES ('delete', old.id, old.reference, old.title, COALESCE(old.summary, ''), old.full_text);
END;

CREATE TRIGGER IF NOT EXISTS advisories_au AFTER UPDATE ON advisories BEGIN
  INSERT INTO advisories_fts(advisories_fts, rowid, reference, title, summary, full_text)
  VALUES ('delete', old.id, old.reference, old.title, COALESCE(old.summary, ''), old.full_text);
  INSERT INTO advisories_fts(rowid, reference, title, summary, full_text)
  VALUES (new.id, new.reference, new.title, COALESCE(new.summary, ''), new.full_text);
END;

CREATE TABLE IF NOT EXISTS frameworks (
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  name_en        TEXT,
  description    TEXT,
  document_count INTEGER DEFAULT 0
);
`;

// --- Interfaces ---------------------------------------------------------------

export interface Guidance {
  id: number;
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string | null;
  series: string | null;
  summary: string | null;
  full_text: string;
  topics: string | null;
  status: string;
}

export interface Advisory {
  id: number;
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null;
  summary: string | null;
  full_text: string;
  cve_references: string | null;
}

export interface Framework {
  id: string;
  name: string;
  name_en: string | null;
  description: string | null;
  document_count: number;
}

// --- DB singleton -------------------------------------------------------------

let _db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (_db) return _db;
  _db = new Database(DB_PATH, { readonly: true, fileMustExist: true });
  return _db;
}

// --- Guidance queries ---------------------------------------------------------

export interface SearchGuidanceOptions {
  query: string;
  type?: string | undefined;
  series?: string | undefined;
  status?: string | undefined;
  limit?: number | undefined;
}

export function searchGuidance(opts: SearchGuidanceOptions): Guidance[] {
  const db = getDb();
  const limit = opts.limit ?? 20;

  const conditions: string[] = ["guidance_fts MATCH :query"];
  const params: Record<string, unknown> = { query: opts.query, limit };

  if (opts.type) {
    conditions.push("g.type = :type");
    params["type"] = opts.type;
  }
  if (opts.series) {
    conditions.push("g.series = :series");
    params["series"] = opts.series;
  }
  if (opts.status) {
    conditions.push("g.status = :status");
    params["status"] = opts.status;
  }

  const where = conditions.join(" AND ");
  return db
    .prepare(
      `SELECT g.* FROM guidance_fts f
       JOIN guidance g ON g.id = f.rowid
       WHERE ${where}
       ORDER BY rank
       LIMIT :limit`,
    )
    .all(params) as Guidance[];
}

export function getGuidance(reference: string): Guidance | null {
  const db = getDb();
  return (
    (db
      .prepare("SELECT * FROM guidance WHERE reference = ? LIMIT 1")
      .get(reference) as Guidance | undefined) ?? null
  );
}

// --- Advisory queries ---------------------------------------------------------

export interface SearchAdvisoriesOptions {
  query: string;
  severity?: string | undefined;
  limit?: number | undefined;
}

export function searchAdvisories(opts: SearchAdvisoriesOptions): Advisory[] {
  const db = getDb();
  const limit = opts.limit ?? 20;

  const conditions: string[] = ["advisories_fts MATCH :query"];
  const params: Record<string, unknown> = { query: opts.query, limit };

  if (opts.severity) {
    conditions.push("a.severity = :severity");
    params["severity"] = opts.severity;
  }

  const where = conditions.join(" AND ");
  return db
    .prepare(
      `SELECT a.* FROM advisories_fts f
       JOIN advisories a ON a.id = f.rowid
       WHERE ${where}
       ORDER BY rank
       LIMIT :limit`,
    )
    .all(params) as Advisory[];
}

export function getAdvisory(reference: string): Advisory | null {
  const db = getDb();
  return (
    (db
      .prepare("SELECT * FROM advisories WHERE reference = ? LIMIT 1")
      .get(reference) as Advisory | undefined) ?? null
  );
}

// --- Framework queries --------------------------------------------------------

export function listFrameworks(): Framework[] {
  const db = getDb();
  return db
    .prepare("SELECT * FROM frameworks ORDER BY id")
    .all() as Framework[];
}
