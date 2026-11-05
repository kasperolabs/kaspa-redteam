#!/usr/bin/env node
// analyzer/server/queue-complete.js: make every cached spend in an analyzer queue export complete, so the analyzer
// can rebuild it. marker kcc20-analyzer-queue-complete-2026-11-05
//
//   node queue-complete.js kcc20-analyzer-queue.json > queue-complete.json
//   node queue-complete.js --only-verified kcc20-analyzer-queue.json > queue-complete.json
//   node queue-complete.js --only-verified --follow 6 kcc20-analyzer-queue.json > queue-complete.json
//
// --follow N: for a program with fewer than N spends, follow the program's own next coin (the output bound to the
// spent coin's covenant and authorized by it) to the transaction that spent it, until N spends are collected.
// More real spends means more paths for the analyzer to mutate (a pool's buys and sells, not only its launch).
//
// A copy is complete when every input says what it spent: amount, script (or address) and covenant id (null for a
// plain coin). Copies cached from address histories or before the REST API reported input covenant ids lack some of
// that; those are fetched again from api.kaspa.org with resolve_previous_outpoints=light. Read-only: no database, no
// keys. Set KASPA_API to use another kaspa-rest-server.
'use strict';
const fs = require('fs');
const API = (process.env.KASPA_API || 'https://api.kaspa.org').replace(/\/$/, '');
const args = process.argv.slice(2);
const onlyVerified = args.includes('--only-verified');
const followIdx = args.indexOf('--follow');
const follow = followIdx >= 0 ? Number(args[followIdx + 1]) || 6 : 0;
const file = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--follow');
if (!file) { console.error('usage: node queue-complete.js [--only-verified] <queue.json>'); process.exit(2); }
const log = (...a) => console.error('[complete]', ...a);

const sleep = ms => new Promise(r => setTimeout(r, ms));
async function get(path) {
    for (let attempt = 1; attempt <= 4; attempt++) {
        try {
            const r = await fetch(API + path, { headers: { accept: 'application/json' } });
            if (r.status === 404) return null;
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return await r.json();
        } catch (e) {
            if (attempt === 4) throw e;
            await sleep(500 * attempt);
        }
    }
}
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
function complete(tx) {
    if (!tx || !Array.isArray(tx.inputs) || !Array.isArray(tx.outputs)) return false;
    return tx.inputs.every(i => (i.previous_outpoint_amount != null && i.previous_outpoint_amount !== 'None')
        && (i.previous_outpoint_address || i.previous_outpoint_script)
        && has(i, 'covenant_id'));
}

(async () => {
    const q = JSON.parse(fs.readFileSync(file, 'utf8'));
    const programs = Array.isArray(q) ? q : q.programs;
    let fetched = 0, kept = 0, failed = 0;
    for (const p of programs) {
        if (onlyVerified && Number(p.verified) !== 1) continue;
        const spends = p.spends || p.transactions || p.txs || [];
        for (const s of spends) {
            const txid = s.txid || (s.tx && s.tx.transaction_id);
            if (complete(s.tx)) { kept++; continue; }
            try {
                const t = await get(`/transactions/${txid}?inputs=true&outputs=true&resolve_previous_outpoints=light`);
                if (!t) { failed++; s.fetch_error = 'not found'; log(`${txid}: not found`); continue; }
                s.tx = t; s.refetched = new Date().toISOString(); fetched++;
                // Some API answers leave the input covenant ids out. Each one is the covenant of the output it spent,
                // which the previous transaction states (null for a plain coin).
                for (const i of t.inputs || []) {
                    if (has(i, 'covenant_id')) continue;
                    const prev = await get(`/transactions/${i.previous_outpoint_hash}?inputs=false&outputs=true&resolve_previous_outpoints=no`);
                    const o = prev && (prev.outputs || []).find(x => Number(x.index) === Number(i.previous_outpoint_index));
                    if (!o) continue;
                    if (!i.previous_outpoint_script && o.script_public_key) i.previous_outpoint_script = o.script_public_key;
                    i.covenant_id = o.covenant_id && o.covenant_id !== 'None' ? o.covenant_id : null;
                    i.covenant_id_from = 'previous transaction output';
                    await sleep(80);
                }
                if (!complete(t)) { s.fetch_error = 'still incomplete after fetch'; log(`${txid}: still incomplete`); }
            } catch (e) { failed++; s.fetch_error = e.message; log(`${txid}: ${e.message}`); }
            await sleep(120);
        }
    }
    let followed = 0;
    if (follow) for (const p of programs) {
        if (onlyVerified && Number(p.verified) !== 1) continue;
        const spends = p.spends || (p.spends = []);
        const have = new Set(spends.map(s => s.txid));
        const queue = spends.slice();
        while (spends.length < follow && queue.length) {
            const s = queue.shift(), t = s.tx;
            if (!t || !t.inputs) continue;
            // inputs that spent this program: their covenant's outputs authorized by them are the next coins
            const nexts = [];
            t.inputs.forEach((i, k) => {
                if (!i.covenant_id) return;
                for (const o of t.outputs) if (o.covenant_id === i.covenant_id && Number(o.covenant_authorizing_input) === k) nexts.push(o);
            });
            for (const o of nexts) {
                if (spends.length >= follow) break;
                const addr = o.script_public_key_address;
                if (!addr) continue;
                let hist;
                try { hist = await get(`/addresses/${addr}/full-transactions?limit=20&offset=0&resolve_previous_outpoints=light`); } catch (e) { log(`${addr}: ${e.message}`); continue; }
                const spender = (hist || []).find(h => (h.inputs || []).some(i => i.previous_outpoint_hash === (t.transaction_id || s.txid) && Number(i.previous_outpoint_index) === Number(o.index)));
                if (!spender || have.has(spender.transaction_id)) continue;
                // the history copy can lack input covenant ids: fetch the transaction itself
                let full = await get(`/transactions/${spender.transaction_id}?inputs=true&outputs=true&resolve_previous_outpoints=light`);
                if (!full) continue;
                for (const i of full.inputs || []) {
                    if (has(i, 'covenant_id')) continue;
                    const prev = await get(`/transactions/${i.previous_outpoint_hash}?inputs=false&outputs=true&resolve_previous_outpoints=no`);
                    const po = prev && (prev.outputs || []).find(x => Number(x.index) === Number(i.previous_outpoint_index));
                    if (!po) continue;
                    if (!i.previous_outpoint_script && po.script_public_key) i.previous_outpoint_script = po.script_public_key;
                    i.covenant_id = po.covenant_id && po.covenant_id !== 'None' ? po.covenant_id : null;
                }
                const ns = { txid: full.transaction_id, tx: full, followed_from: s.txid };
                spends.push(ns); queue.push(ns); have.add(full.transaction_id); followed++;
                await sleep(120);
            }
        }
    }
    log(`${kept} already complete, ${fetched} fetched again, ${failed} failed, ${followed} found by following next coins`);
    process.stdout.write(JSON.stringify(q) + '\n');
})().catch(e => { log(e.stack || e.message); process.exit(1); });
