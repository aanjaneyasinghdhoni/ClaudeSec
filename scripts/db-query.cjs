#!/usr/bin/env node
/* Read-ONLY spans.db query helper — a safe alternative to a write-capable SQLite
 * MCP. Opens the database with { readonly: true } and refuses anything that is not
 * a single SELECT, so it can never modify or delete data.
 *
 *   node scripts/db-query.cjs "SELECT count(*) FROM spans"
 *   node scripts/db-query.cjs "SELECT name, severity FROM spans ORDER BY startNano DESC LIMIT 20"
 *
 * Respects CLAUDESEC_DB (defaults to spans.db).
 */
const path = require('path');
const Database = require(path.join(__dirname, '..', 'node_modules', 'better-sqlite3'));

const sql = process.argv.slice(2).join(' ').trim();
if (!sql) {
  console.error('Usage: node scripts/db-query.cjs "SELECT ..."');
  process.exit(1);
}
// Read-only guard: must start with SELECT (or a WITH...SELECT CTE) and contain no
// second statement. Blocks INSERT/UPDATE/DELETE/DROP/PRAGMA-write/ATTACH/etc.
const stripped = sql.replace(/;\s*$/, '');
if (/;/.test(stripped) || !/^(?:select|with)\b/i.test(stripped)) {
  console.error('Refused: only a single read-only SELECT (or WITH…SELECT) statement is allowed.');
  process.exit(2);
}

const dbPath = process.env.CLAUDESEC_DB || 'spans.db';
const db = new Database(dbPath, { readonly: true, fileMustExist: true });
try {
  const rows = db.prepare(stripped).all();
  console.log(JSON.stringify(rows, null, 2));
  console.error(`(${rows.length} row(s) from ${dbPath}, read-only)`);
} finally {
  db.close();
}
