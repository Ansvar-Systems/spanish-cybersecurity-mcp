# Known Failures

## NEEDS_REVIEW — 2026-05-17

Flagged by `scripts/apply-mcp-standard.py`. Treatment was skipped pending resolution.

**Reason:** `runtime_db_open_unsafe: src/db.ts contains read-write SQLite operations that fail on read_only:true container rootfs. Smells: pragma("journal_mode = WAL") at runtime; SCHEMA_SQL applied to runtime DB connection; mkdirSync(...) at runtime; DB opened without readonly opts: new Database(DB_PATH). Canonical fix: replace getDb() body with `_db = new Database(DB_PATH, { readonly: true, fileMustExist: true }); return _db;` and remove WAL pragma, schema CREATE, and mkdirSync. Schema creation belongs in offline build:db scripts only. Reference: japan-fsa-guidance-mcp PR #3.`

**Gate state at pre-flight:**
- PASS: (none)
- N/A:  (none)
- FAIL: pre-content

**Profile detected:** `node-native-curated`

**Next steps:** the reason string above maps to a known pattern in
`docs/handover/2026-04-26-golden-standard-next-batch-handover.md` §4. Resolve
on a separate fix branch, then re-run the sweep on a fresh `audit/` branch
once `main` is green.
