// API Tabungan Cikande Hub — satu fungsi Netlify untuk /api/member/* dan /api/staff/*
// Data disimpan di Netlify Database (Postgres).
import crypto from "node:crypto";
import { promisify } from "node:util";
import { getDatabase } from "@netlify/database";
const pbkdf2 = promisify(crypto.pbkdf2);
const PBKDF2_ITER = 150_000;
const STAFF_TTL = 12 * 3600;
const MEMBER_TTL = 30 * 60;
const DUMMY_SALT = crypto.randomBytes(16).toString("hex");

class ApiError extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}

const nowS = () => Math.floor(Date.now() / 1000);
const nowMs = () => Date.now();
const num = (v) => Number(v);
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
const newSalt = () => crypto.randomBytes(16).toString("hex");
const newTxId = () => "tx-" + crypto.randomBytes(6).toString("hex");

async function hashSecret(secret, saltHex) {
  const buf = await pbkdf2(String(secret), Buffer.from(saltHex, "hex"), PBKDF2_ITER, 32, "sha256");
  return buf.toString("hex");
}
function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function clean(v, maxlen, def = "") {
  if (v === null || v === undefined) return def;
  const s = String(v).trim();
  return s ? s.slice(0, maxlen) : def;
}
function normalizeId(v) {
  const s = String(v ?? "").toUpperCase().replace(/\s+/g, "");
  const m = s.match(/^(?:NSB)?-?(\d{1,6})$/);
  return m ? "NSB-" + m[1].padStart(3, "0") : s.slice(0, 20);
}
function pinProblem(pin) {
  if (typeof pin !== "string" || !/^\d{6}$/.test(pin)) return "PIN harus 6 angka.";
  if (/^(\d)\1{5}$/.test(pin)) return "PIN terlalu mudah ditebak (angka sama semua).";
  if ("0123456789".includes(pin) || "9876543210".includes(pin)) return "PIN terlalu mudah ditebak (angka berurutan).";
  return "";
}
const isNum = (v) => typeof v === "number" && Number.isFinite(v);

function json(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
    },
  });
}

async function bulkInsert(t, table, cols, rows, chunk = 300) {
  for (let i = 0; i < rows.length; i += chunk) {
    const part = rows.slice(i, i + chunk);
    const params = [];
    const values = part.map((r) => {
      const ph = r.map((v) => { params.push(v); return "$" + params.length; });
      return "(" + ph.join(",") + ")";
    });
    await t.query(`INSERT INTO ${table} (${cols.join(",")}) VALUES ${values.join(",")}`, params);
  }
}

function createHandler(db) {
  /* ---------------- pembatasan percobaan ---------------- */
  async function lockLeft(key) {
    const r = await db.query("SELECT until FROM fails WHERE key=$1", [key]);
    return r.length ? Math.max(0, Math.ceil(num(r[0].until) - nowS())) : 0;
  }
  async function addFail(key, maxFail, lockSec) {
    const r = await db.query("SELECT count, until FROM fails WHERE key=$1", [key]);
    let count = 0;
    if (r.length && !(num(r[0].until) && num(r[0].until) <= nowS())) count = num(r[0].count);
    count += 1;
    let until = 0;
    if (count >= maxFail) { count = 0; until = nowS() + lockSec; }
    await db.query(
      "INSERT INTO fails(key,count,until) VALUES($1,$2,$3) ON CONFLICT(key) DO UPDATE SET count=EXCLUDED.count, until=EXCLUDED.until",
      [key, count, until]);
    return until > 0;
  }
  const clearFail = (key) => db.query("DELETE FROM fails WHERE key=$1", [key]);

  async function throttle(key, limit, windowSec) {
    const t = nowS();
    const r = await db.query("SELECT window_start, count FROM hits WHERE key=$1", [key]);
    let ws = t, c = 1;
    if (r.length && t - num(r[0].window_start) < windowSec) { ws = num(r[0].window_start); c = num(r[0].count) + 1; }
    await db.query(
      "INSERT INTO hits(key,window_start,count) VALUES($1,$2,$3) ON CONFLICT(key) DO UPDATE SET window_start=EXCLUDED.window_start, count=EXCLUDED.count",
      [key, ws, c]);
    return c <= limit;
  }

  /* ---------------- sesi ---------------- */
  const staffFingerprint = () => sha256("staff:" + (process.env.STAFF_PASSWORD || "")).slice(0, 24);

  async function makeSession(role, subject, ttl) {
    const tok = crypto.randomBytes(32).toString("base64url");
    await db.query("INSERT INTO sessions(token_hash,role,subject,expires) VALUES($1,$2,$3,$4)",
      [sha256(tok), role, subject, nowS() + ttl]);
    await db.query("DELETE FROM sessions WHERE expires < $1", [nowS()]);
    return tok;
  }
  async function getSession(token) {
    if (!token) return null;
    const h = sha256(token);
    const r = await db.query("SELECT role, subject, expires FROM sessions WHERE token_hash=$1", [h]);
    if (!r.length || num(r[0].expires) < nowS()) return null;
    const { role, subject } = r[0];
    if (role === "staff" && subject !== staffFingerprint()) return null;   // password diganti -> sesi lama tidak berlaku
    if (role === "member") await db.query("UPDATE sessions SET expires=$1 WHERE token_hash=$2", [nowS() + MEMBER_TTL, h]);
    return { role, subject };
  }
  const dropSession = (token) => token ? db.query("DELETE FROM sessions WHERE token_hash=$1", [sha256(token)]) : null;

  /* ---------------- data ---------------- */
  const txRow = (r) => ({ id: r.id, ts: num(r.ts), type: r.type, amount: num(r.amount), note: r.note });

  async function staffData() {
    const [wr, txs, pins, reps] = await Promise.all([
      db.query("SELECT id, nama, alamat, phone, created_at FROM warga ORDER BY created_at, id"),
      db.query("SELECT id, warga_id, ts, type, amount, note FROM tx ORDER BY ts, id"),
      db.query("SELECT warga_id FROM pin"),
      db.query("SELECT warga_id, bulan, ts FROM reports"),
    ]);
    const by = new Map();
    for (const t of txs) { if (!by.has(t.warga_id)) by.set(t.warga_id, []); by.get(t.warga_id).push(txRow(t)); }
    const hasPin = new Set(pins.map((p) => p.warga_id));
    return {
      warga: wr.map((w) => ({ id: w.id, nama: w.nama, alamat: w.alamat, phone: w.phone,
        createdAt: num(w.created_at), tx: by.get(w.id) || [], hasPin: hasPin.has(w.id) })),
      _reports: Object.fromEntries(reps.map((r) => [r.warga_id, { bulan: r.bulan, ts: num(r.ts) }])),
    };
  }

  async function restoreAll(data) {
    if (!data || typeof data !== "object" || !Array.isArray(data.warga)) throw new ApiError(400, "Format backup tidak valid.");
    if (data.warga.length > 5000) throw new ApiError(400, "Data terlalu besar.");
    const seenW = new Set(), seenT = new Set(), wrows = [], trows = [];
    for (const w of data.warga) {
      if (!w || typeof w !== "object") throw new ApiError(400, "Format backup tidak valid.");
      const wid = clean(w.id, 20);
      if (!/^[A-Za-z0-9_-]{1,20}$/.test(wid) || seenW.has(wid)) throw new ApiError(400, `ID warga tidak valid: ${wid || "(kosong)"}`);
      seenW.add(wid);
      const nama = clean(w.nama, 100);
      if (!nama) throw new ApiError(400, `Nama kosong pada ${wid}`);
      const ca = isNum(w.createdAt) && w.createdAt > 0 ? Math.floor(w.createdAt) : nowMs();
      wrows.push([wid, nama, clean(w.alamat, 200, "Desa Cikande"), clean(w.phone, 30), ca]);
      for (const t of Array.isArray(w.tx) ? w.tx : []) {
        if (!t || typeof t !== "object") continue;
        if (!["SETOR", "TARIK"].includes(t.type) || !isNum(t.amount) || !(t.amount > 0 && t.amount < 1e13)) continue;
        let tid = clean(t.id, 40);
        if (!tid || seenT.has(tid)) tid = newTxId();
        seenT.add(tid);
        const ts = isNum(t.ts) && t.ts > 0 ? Math.floor(t.ts) : nowMs();
        trows.push([tid, wid, ts, t.type, t.amount, clean(t.note, 200)]);
      }
    }
    const reps = data._reports && typeof data._reports === "object" ? data._reports : {};
    await db.tx(async (t) => {
      await t.lock(3);
      const oldPins = await t.query("SELECT warga_id, salt, hash, updated_at FROM pin");
      await t.query("DELETE FROM tx"); await t.query("DELETE FROM reports");
      await t.query("DELETE FROM pin"); await t.query("DELETE FROM warga");
      await bulkInsert(t, "warga", ["id", "nama", "alamat", "phone", "created_at"], wrows);
      await bulkInsert(t, "tx", ["id", "warga_id", "ts", "type", "amount", "note"], trows);
      await bulkInsert(t, "pin", ["warga_id", "salt", "hash", "updated_at"],
        oldPins.filter((p) => seenW.has(p.warga_id)).map((p) => [p.warga_id, p.salt, p.hash, num(p.updated_at)]));
      const rrows = Object.entries(reps).filter(([id, r]) => seenW.has(id) && r && typeof r === "object")
        .map(([id, r]) => [id, clean(r.bulan, 40), isNum(r.ts) ? Math.floor(r.ts) : nowMs()]);
      await bulkInsert(t, "reports", ["warga_id", "bulan", "ts"], rrows);
    });
    return { ok: true, warga: wrows.length, tx: trows.length };
  }

  /* ---------------- rute ---------------- */
  async function route(method, path, body, token, ip) {
    const parts = path.replace(/^\/+|\/+$/g, "").split("/").map(decodeURIComponent);
    if (parts[0] !== "api") throw new ApiError(404, "Tidak ditemukan.");
    const p = parts.slice(1);

    if (method === "GET" && p.length === 1 && p[0] === "healthz") return { ok: true };

    /* ---- publik: warga ---- */
    if (p[0] === "member" && p.length === 2 && ["start", "create-pin", "login"].includes(p[1]) && method === "POST") {
      if (!(await throttle("pub:" + ip, 40, 60))) throw new ApiError(429, "Terlalu banyak permintaan. Coba sebentar lagi.");
      const wid = normalizeId(body.id);
      if (!wid) throw new ApiError(400, "Masukkan nomor ID.");
      const exists = (await db.query("SELECT 1 AS x FROM warga WHERE id=$1", [wid])).length > 0;
      const hasPin = (await db.query("SELECT 1 AS x FROM pin WHERE warga_id=$1", [wid])).length > 0;

      if (p[1] === "start") return { mode: exists && !hasPin ? "create" : "enter" };

      if (p[1] === "create-pin") {
        const prob = pinProblem(body.pin);
        if (prob) throw new ApiError(400, prob);
        if (!exists || hasPin) throw new ApiError(409, "PIN tidak dapat dibuat untuk ID ini. Hubungi petugas.");
        const salt = newSalt(), hash = await hashSecret(body.pin, salt);
        const ins = await db.query(
          "INSERT INTO pin(warga_id,salt,hash,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(warga_id) DO NOTHING RETURNING warga_id",
          [wid, salt, hash, nowMs()]);
        if (!ins.length) throw new ApiError(409, "PIN sudah dibuat.");
        return { token: await makeSession("member", wid, MEMBER_TTL) };
      }

      // login
      const kid = "member:" + wid, kip = "ip:" + ip;
      const wait = Math.max(await lockLeft(kid), await lockLeft(kip));
      if (wait) throw new ApiError(429, `Terlalu banyak percobaan. Coba lagi dalam ${wait} detik.`);
      const pin = typeof body.pin === "string" ? body.pin : "";
      const rec = (await db.query("SELECT salt, hash FROM pin WHERE warga_id=$1", [wid]))[0];
      const calc = await hashSecret(pin, rec ? rec.salt : DUMMY_SALT);
      if (!(rec && /^\d{6}$/.test(pin) && safeEqual(calc, rec.hash))) {
        await addFail(kip, 15, 300);
        const locked = await addFail(kid, 5, 120);
        throw new ApiError(locked ? 429 : 401, locked ? "Terlalu banyak salah. PIN terkunci 2 menit." : "ID atau PIN salah.");
      }
      await clearFail(kid); await clearFail(kip);
      return { token: await makeSession("member", wid, MEMBER_TTL) };
    }

    /* ---- publik: login petugas ---- */
    if (method === "POST" && p.length === 2 && p[0] === "staff" && p[1] === "login") {
      const env = process.env.STAFF_PASSWORD || "";
      if (env.length < 8) throw new ApiError(503, "Password petugas belum diatur di server (STAFF_PASSWORD).");
      const key = "staff:" + ip;
      const wait = await lockLeft(key);
      if (wait) throw new ApiError(429, `Terlalu banyak percobaan. Coba lagi dalam ${wait} detik.`);
      const pw = typeof body.password === "string" ? body.password : "";
      if (!safeEqual(sha256(pw), sha256(env))) {
        const locked = await addFail(key, 5, 300);
        throw new ApiError(locked ? 429 : 401, locked ? "Terlalu banyak percobaan. Coba lagi dalam 300 detik." : "Password salah.");
      }
      await clearFail(key);
      return { token: await makeSession("staff", staffFingerprint(), STAFF_TTL) };
    }

    /* ---- butuh login ---- */
    const sess = await getSession(token);
    if (!sess) throw new ApiError(401, "Sesi berakhir. Silakan masuk kembali.");
    const { role, subject } = sess;

    if (p[0] === "member") {
      if (role !== "member") throw new ApiError(403, "Tidak diizinkan.");
      if (method === "GET" && p.length === 2 && p[1] === "me") {
        const w = (await db.query("SELECT id, nama, alamat, created_at FROM warga WHERE id=$1", [subject]))[0];
        if (!w) throw new ApiError(401, "Data warga tidak ditemukan.");
        const txs = await db.query("SELECT id, ts, type, amount, note FROM tx WHERE warga_id=$1 ORDER BY ts, id", [subject]);
        return { warga: { id: w.id, nama: w.nama, alamat: w.alamat, createdAt: num(w.created_at) }, tx: txs.map(txRow) };
      }
      if (method === "POST" && p[1] === "logout") { await dropSession(token); return { ok: true }; }
      if (method === "POST" && p[1] === "change-pin") {
        const oldP = body.oldPin, newP = body.newPin;
        const kid = "member:" + subject, wait = await lockLeft(kid);
        if (wait) throw new ApiError(429, `PIN terkunci sementara. Coba lagi dalam ${wait} detik.`);
        const rec = (await db.query("SELECT salt, hash FROM pin WHERE warga_id=$1", [subject]))[0];
        if (!rec) throw new ApiError(409, "PIN belum dibuat.");
        const okOld = typeof oldP === "string" && safeEqual(await hashSecret(oldP, rec.salt), rec.hash);
        if (!okOld) {
          const locked = await addFail(kid, 5, 120);
          throw new ApiError(locked ? 429 : 401, locked ? "Terlalu banyak salah. PIN terkunci 2 menit." : "PIN lama salah.");
        }
        const prob = pinProblem(newP);
        if (prob) throw new ApiError(400, prob);
        if (newP === oldP) throw new ApiError(400, "PIN baru harus berbeda dari PIN lama.");
        await clearFail(kid);
        const salt = newSalt();
        await db.query("UPDATE pin SET salt=$1, hash=$2, updated_at=$3 WHERE warga_id=$4",
          [salt, await hashSecret(newP, salt), nowMs(), subject]);
        return { ok: true };
      }
      throw new ApiError(404, "Tidak ditemukan.");
    }

    if (p[0] === "staff") {
      if (role !== "staff") throw new ApiError(403, "Tidak diizinkan.");
      const q = p.slice(1);
      if (method === "POST" && q.length === 1 && q[0] === "logout") { await dropSession(token); return { ok: true }; }
      if (method === "GET" && q.length === 1 && (q[0] === "data" || q[0] === "backup")) return staffData();
      if (method === "POST" && q.length === 1 && q[0] === "restore") return restoreAll(body);

      if (method === "POST" && q.length === 1 && q[0] === "warga") {
        const nama = clean(body.nama, 100);
        if (!nama) throw new ApiError(400, "Masukkan nama warga!");
        const alamat = clean(body.alamat, 200, "Desa Cikande"), phone = clean(body.phone, 30), ca = nowMs();
        const wid = await db.tx(async (t) => {
          await t.lock(1);
          let mx = 0;
          for (const r of await t.query("SELECT id FROM warga")) {
            const m = /^NSB-(\d+)$/.exec(r.id); if (m) mx = Math.max(mx, parseInt(m[1], 10));
          }
          const id = "NSB-" + String(mx + 1).padStart(3, "0");
          await t.query("INSERT INTO warga(id,nama,alamat,phone,created_at) VALUES($1,$2,$3,$4,$5)", [id, nama, alamat, phone, ca]);
          return id;
        });
        return { id: wid, nama, alamat, phone, createdAt: ca, tx: [], hasPin: false };
      }

      if (method === "DELETE" && q.length === 2 && q[0] === "warga") {
        const del = await db.query("DELETE FROM warga WHERE id=$1 RETURNING id", [q[1]]);
        if (!del.length) throw new ApiError(404, "Warga tidak ditemukan.");
        await db.query("DELETE FROM sessions WHERE role='member' AND subject=$1", [q[1]]);
        return { ok: true };
      }

      if (method === "POST" && q.length === 3 && q[0] === "warga" && q[2] === "reset-pin") {
        if (!(await db.query("SELECT 1 AS x FROM warga WHERE id=$1", [q[1]])).length) throw new ApiError(404, "Warga tidak ditemukan.");
        await db.query("DELETE FROM pin WHERE warga_id=$1", [q[1]]);
        await db.query("DELETE FROM sessions WHERE role='member' AND subject=$1", [q[1]]);
        await clearFail("member:" + q[1]);
        return { ok: true };
      }

      if (method === "POST" && q.length === 1 && q[0] === "tx") {
        const wid = clean(body.wargaId, 20), typ = body.type, amt = body.amount;
        if (!["SETOR", "TARIK"].includes(typ)) throw new ApiError(400, "Jenis transaksi tidak valid.");
        if (!isNum(amt) || !(amt > 0 && amt < 1e13)) throw new ApiError(400, "Masukkan nominal yang valid!");
        const amount = Math.round(amt * 100) / 100;
        const id = newTxId(), ts = nowMs(), note = clean(body.note, 200);
        await db.tx(async (t) => {
          await t.lock(2);
          if (!(await t.query("SELECT 1 AS x FROM warga WHERE id=$1", [wid])).length) throw new ApiError(404, "Warga tidak ditemukan.");
          const bal = num((await t.query(
            "SELECT COALESCE(SUM(CASE WHEN type='SETOR' THEN amount ELSE -amount END),0) AS b FROM tx WHERE warga_id=$1", [wid]))[0].b);
          if (typ === "TARIK" && amount > bal + 1e-9) throw new ApiError(400, "Saldo tidak mencukupi untuk penarikan ini!");
          await t.query("INSERT INTO tx(id,warga_id,ts,type,amount,note) VALUES($1,$2,$3,$4,$5,$6)", [id, wid, ts, typ, amount, note]);
        });
        return { id, ts, type: typ, amount, note };
      }

      if (method === "DELETE" && q.length === 2 && q[0] === "tx") {
        const del = await db.query("DELETE FROM tx WHERE id=$1 RETURNING id", [q[1]]);
        if (!del.length) throw new ApiError(404, "Transaksi tidak ditemukan.");
        return { ok: true };
      }

      if (method === "PUT" && q.length === 2 && q[0] === "reports") {
        if (!(await db.query("SELECT 1 AS x FROM warga WHERE id=$1", [q[1]])).length) throw new ApiError(404, "Warga tidak ditemukan.");
        await db.query(
          "INSERT INTO reports(warga_id,bulan,ts) VALUES($1,$2,$3) ON CONFLICT(warga_id) DO UPDATE SET bulan=EXCLUDED.bulan, ts=EXCLUDED.ts",
          [q[1], clean(body.bulan, 40), nowMs()]);
        return { ok: true };
      }
    }
    throw new ApiError(404, "Tidak ditemukan.");
  }

  /* ---------------- pintu masuk fungsi ---------------- */
  return async (req, context) => {
    try {
      const url = new URL(req.url);
      const method = req.method.toUpperCase();
      let body = {};
      if (method === "POST" || method === "PUT") {
        const raw = await req.text();
        if (raw) {
          try { body = JSON.parse(raw); } catch { throw new ApiError(400, "Format data tidak valid."); }
          if (!body || typeof body !== "object" || Array.isArray(body)) body = {};
        }
      }
      const auth = req.headers.get("authorization") || "";
      const token = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
      const ip = (req.headers.get("x-nf-client-connection-ip") || context?.ip || "unknown").slice(0, 64);
      return json(200, await route(method, url.pathname, body, token, ip));
    } catch (e) {
      if (e instanceof ApiError) return json(e.status, { error: e.message });
      console.error("API error:", e);
      return json(500, { error: "Terjadi kesalahan di server." });
    }
  };
}

/* ---------------- penghubung Postgres (Netlify Database) ---------------- */
let _db;
const pg = () => (_db ||= getDatabase());

const pgAdapter = {
  async query(text, params = []) {
    const r = await pg().pool.query(text, params);
    return r.rows;
  },
  async tx(fn) {
    const c = await pg().pool.connect();
    try {
      await c.query("BEGIN");
      const t = {
        query: async (q, p = []) => (await c.query(q, p)).rows,
        lock: async (k) => { await c.query("SELECT pg_advisory_xact_lock($1)", [k]); },
      };
      const r = await fn(t);
      await c.query("COMMIT");
      return r;
    } catch (e) {
      try { await c.query("ROLLBACK"); } catch {}
      throw e;
    } finally {
      c.release();
    }
  },
};

// (globalThis.__CH_TEST_DB__ hanya dipakai untuk uji lokal; di Netlify selalu kosong)
const adapter = {
  query: (...a) => (globalThis.__CH_TEST_DB__ || pgAdapter).query(...a),
  tx: (...a) => (globalThis.__CH_TEST_DB__ || pgAdapter).tx(...a),
};

export default createHandler(adapter);
export const config = { path: "/api/*" };
