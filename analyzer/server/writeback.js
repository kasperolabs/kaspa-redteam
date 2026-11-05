#!/usr/bin/env node
// analyzer/server/writeback.js: write the analyzer's results into the Studio's kcc20_programs table.
// marker kcc20-analyzer-writeback-2026-11-05
//
//   cd /var/www/silverscript && node /path/to/writeback.js /path/to/out/writeback.json           (dry run: prints what it would do)
//   cd /var/www/silverscript && node /path/to/writeback.js /path/to/out/writeback.json --apply   (writes)
//
// Run it from the Studio folder: it reads the database settings from the Studio's .env (or uses the Studio's own db
// module) and never prints a value from .env. It refuses to write when:
//   - the run's corpus check did not pass (every corpus attack must be caught before any label is written back);
//   - a row's analyzer_version differs from the run's;
//   - the table lacks one of the columns it writes.
// It updates only rows still `status = 'queued'` (a later re-queue on a new analyzer version is Session C's job),
// matched by the program hash. Columns written: status ('done' or 'too-complex'), label, report_json,
// analyzer_version. The Studio serves the label of `done` rows for programs nobody pinned.
'use strict';
const fs = require('fs'), path = require('path');
const args = process.argv.slice(2);
const file = args.find(a => !a.startsWith('--'));
const APPLY = args.includes('--apply');
const log = (...a) => console.error('[writeback]', ...a);
if (!file) { log('usage: node writeback.js <writeback.json> [--apply]'); process.exit(2); }
const ROOT = process.cwd();

function readEnv() {
    const env = {};
    try {
        for (const line of fs.readFileSync(path.join(ROOT, '.env'), 'utf8').split('\n')) {
            const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
            if (m) env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
        }
    } catch (_) {}
    return Object.assign(env, process.env);
}
async function connect() {
    for (const c of ['db', 'db.js', 'lib/db', 'config/db', 'src/db', 'database', 'models/db']) {
        const p = path.join(ROOT, c);
        if (!fs.existsSync(p) && !fs.existsSync(p + '.js')) continue;
        try {
            const m = require(p), db = m.pool || m.db || m.default || m;
            if (db && typeof db.query === 'function') { log(`using the Studio's ${c}`); return wrap(db); }
        } catch (e) { log(`${c}: ${e.message}`); }
    }
    const env = readEnv(), pick = (...k) => { for (const x of k) if (env[x]) return env[x]; return undefined; };
    const cfg = { host: pick('DB_HOST', 'MYSQL_HOST') || '127.0.0.1', port: Number(pick('DB_PORT', 'MYSQL_PORT') || 3306),
                  user: pick('DB_USER', 'MYSQL_USER', 'DB_USERNAME'), password: pick('DB_PASSWORD', 'DB_PASS', 'MYSQL_PASSWORD'),
                  database: pick('DB_NAME', 'DB_DATABASE', 'MYSQL_DATABASE') };
    let mysql;
    try { mysql = require(path.join(ROOT, 'node_modules', 'mysql2', 'promise')); }
    catch (_) { log('mysql2 not found: run this from the Studio folder (/var/www/silverscript)'); process.exit(1); }
    const pool = mysql.createPool(Object.assign(cfg, { connectionLimit: 2 }));
    await pool.query('SELECT 1');
    log('using mysql2 with the .env settings');
    return wrap(pool);
}
function wrap(db) {
    return async (sql, p = []) => { const r = await db.query(sql, p); return Array.isArray(r) && Array.isArray(r[0]) ? r[0] : r; };
}

// A report too large for a TEXT column keeps everything but the replayable transactions (the full report stays in the
// analyzer's reports/ folder, and the evidence can be rebuilt by running the analyzer again: same bytes, same report).
function fitReport(report, maxBytes) {
    let s = JSON.stringify(report);
    if (Buffer.byteLength(s) <= maxBytes) return { json: s, trimmed: false };
    const r = JSON.parse(s);
    for (const f of r.findings || []) if (f.evidence && f.evidence.transaction) f.evidence.transaction = { id: f.evidence.transaction.id, note: 'transaction left out to fit the column; rerun the analyzer for it' };
    s = JSON.stringify(r);
    if (Buffer.byteLength(s) <= maxBytes) return { json: s, trimmed: true };
    r.facts = (r.facts || []).slice(0, 20); r.runs = (r.runs || []).slice(0, 6); r.spends = (r.spends || []).slice(0, 6);
    s = JSON.stringify(r);
    return { json: s, trimmed: true, tooBig: Buffer.byteLength(s) > maxBytes };
}

(async () => {
    const wb = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (wb.format !== 'kcc20-analyzer-writeback/1') { log('not an analyzer write-back file'); process.exit(1); }
    const cc = wb.corpus_check || {};
    if (cc.passed !== true) {
        log('REFUSED: the corpus check did not pass (or was not run). Run the analyzer with --corpus <dir> and fix every missed case first.');
        for (const c of cc.cases || []) if (!c.caught) log(`  missed: ${c.name} (expected ${c.expect}, got ${c.got})`);
        process.exit(1);
    }
    log(`analyzer ${wb.analyzer_version}; corpus: ${cc.cases.length} cases, all caught`);
    const q = await connect();
    const cols = (await q('SHOW COLUMNS FROM kcc20_programs')).map(c => ({ name: c.Field, type: String(c.Type).toLowerCase() }));
    const has = n => cols.some(c => c.name === n);
    const keyCol = ['hash', 'code_hash', 'template_hash', 'program_hash'].find(has);
    const missing = ['status', 'label', 'report_json', 'analyzer_version'].filter(n => !has(n));
    if (!keyCol || missing.length) { log(`REFUSED: kcc20_programs lacks ${missing.concat(keyCol ? [] : ['a hash column']).join(', ')}`); process.exit(1); }
    const rj = cols.find(c => c.name === 'report_json').type;
    const maxBytes = rj.includes('json') || rj.includes('longtext') ? 64 * 1024 * 1024 : rj.includes('mediumtext') ? 16 * 1024 * 1024 - 1 : 65535;
    const isJsonCol = rj.includes('json');
    let done = 0, skipped = 0;
    for (const row of wb.rows || []) {
        if (row.analyzer_version !== wb.analyzer_version) { log(`${row.hash.slice(0, 8)}: skipped (analyzer version differs)`); skipped++; continue; }
        if (!['done', 'too-complex'].includes(row.status)) { log(`${row.hash.slice(0, 8)}: skipped (status ${row.status})`); skipped++; continue; }
        if (!['unverified', 'hidden-powers', 'trap'].includes(row.label)) { log(`${row.hash.slice(0, 8)}: skipped (label ${row.label})`); skipped++; continue; }
        const cur = (await q(`SELECT status FROM kcc20_programs WHERE ${keyCol} = ?`, [row.hash]))[0];
        if (!cur) { log(`${row.hash.slice(0, 8)}: no such row`); skipped++; continue; }
        if (cur.status !== 'queued') { log(`${row.hash.slice(0, 8)}: left alone (status is ${cur.status}, not queued)`); skipped++; continue; }
        const fit = fitReport(row.report_json, maxBytes);
        if (fit.tooBig) { log(`${row.hash.slice(0, 8)}: skipped (report too large for report_json even trimmed)`); skipped++; continue; }
        log(`${row.hash.slice(0, 8)}: ${APPLY ? 'set' : 'would set'} status=${row.status} label=${row.label} (${fit.json.length} bytes${fit.trimmed ? ', evidence trimmed' : ''})`);
        if (APPLY) {
            await q(`UPDATE kcc20_programs SET status = ?, label = ?, report_json = ${isJsonCol ? 'CAST(? AS JSON)' : '?'}, analyzer_version = ? WHERE ${keyCol} = ? AND status = 'queued'`,
                    [row.status, row.label, fit.json, row.analyzer_version, row.hash]);
        }
        done++;
    }
    log(`${APPLY ? 'wrote' : 'would write'} ${done} rows, skipped ${skipped}${APPLY ? '' : ' (dry run: add --apply to write)'}`);
    process.exit(0);
})().catch(e => { log(e.stack || e.message); process.exit(1); });
