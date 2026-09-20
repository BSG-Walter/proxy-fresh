/* Proxies frescos de paises objetivo que conectan a un TARGET https.
 * Standalone (solo stdlib node): descarga por pais (proxyscrape+geonode) + 10
 * listas bulk filtradas ANTES por rangos locales (ip-zones), pre-filtra TCP y
 * comprueba cada proxy con CONNECT + TLS + GET / al TARGET. Sin cuentas ni keys.
 *
 * Uso:
 *   node check.js
 *   node check.js --target www.google.com --jobs 60 --timeout 6000
 *   node check.js --no-bulk   (solo fuentes por-pais, mas rapido)
 *   node check.js --extra lista-propia.txt
 */
const fs = require("fs");
const net = require("net");
const tls = require("tls");
const path = require("path");

const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 && args[i + 1] ? args[i + 1] : d; };
const has = (n) => args.includes(n);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const TARGET = opt("--target", "www.example.com");
const PS = (cc) => `https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=${cc}&ssl=all&anonymity=all`;
const GEO = (cc, page = 1) => `https://proxylist.geonode.com/api/proxy-list?limit=200&page=${page}&sort_by=lastChecked&sort_type=desc&country=${cc}`;
const BULKS = [
  "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
  "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
  "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
  "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
  "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt",
  "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
  "https://api.openproxylist.xyz/http.txt",
  "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
  "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
  "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
];

async function fetchText(url, ms = 20000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try { return await (await fetch(url, { signal: ctl.signal })).text(); }
  finally { clearTimeout(t); }
}
function clean(lines) {
  const out = new Set();
  for (let s of lines) {
    s = String(s || "").trim().replace(/^https?:\/\//i, "").split(/\s/)[0];
    if (!s || s.includes("@") || s.includes("/")) continue;
    const i = s.lastIndexOf(":");
    if (i < 0) continue;
    const ip = s.slice(0, i), port = s.slice(i + 1);
    if (!/^\d{1,5}$/.test(port) || +port < 1 || +port > 65535) continue;
    if (!/^[\d.]+$/.test(ip) || ip.split(".").length !== 4) continue;
    out.add(`${ip}:${port}`);
  }
  return [...out];
}
function tcpOpen(p, ms) {
  return new Promise((resolve) => {
    const i = p.lastIndexOf(":");
    const s = net.connect(+p.slice(i + 1), p.slice(0, i));
    const t = setTimeout(() => { try { s.destroy(); } catch (_) {} resolve(null); }, ms);
    s.once("error", () => { clearTimeout(t); resolve(null); });
    s.once("connect", () => { clearTimeout(t); try { s.destroy(); } catch (_) {} resolve(p); });
  });
}
function parseProxy(p) {
  let s = String(p || "").trim().replace(/^https?:\/\//i, "");
  let auth = null;
  const at = s.lastIndexOf("@");
  if (at >= 0) { auth = s.slice(0, at); s = s.slice(at + 1); }
  const i = s.lastIndexOf(":");
  if (i < 0) throw new Error("proxy sin puerto");
  return { host: s.slice(0, i), port: parseInt(s.slice(i + 1), 10) || 8080, auth };
}
// Check real: CONNECT al proxy + TLS + GET / al TARGET. true si hay respuesta HTTP.
function targetCheck(p, timeoutMs) {
  return new Promise((resolve) => {
    let proxy;
    try { proxy = parseProxy(p); } catch (_) { resolve(false); return; }
    let done = false;
    const ok = (v) => { if (!done) { done = true; clearTimeout(t); try { sock.destroy(); } catch (_) {} resolve(v); } };
    const t = setTimeout(() => ok(false), timeoutMs);
    const sock = net.connect(proxy.port, proxy.host);
    let stage = "tunnel", buf = "";
    sock.once("error", () => ok(false));
    sock.once("connect", () => {
      let req = `CONNECT ${TARGET}:443 HTTP/1.1\r\nHost: ${TARGET}:443\r\n`;
      if (proxy.auth) req += `Proxy-Authorization: Basic ${Buffer.from(proxy.auth).toString("base64")}\r\n`;
      sock.write(req + "\r\n");
    });
    sock.on("data", onData);
    function onData(c) {
      if (stage !== "tunnel") return;
      buf += c.toString("latin1");
      if (!buf.includes("\r\n\r\n")) return;
      if (!/^HTTP\/1\.[01] 200/i.test(buf)) { ok(false); return; }
      sock.off("data", onData); // sin esto el listener crudo le roba el handshake al TLS
      stage = "tls";
      const sec = tls.connect({ socket: sock, servername: TARGET }, () => {
        sec.write(`GET / HTTP/1.1\r\nHost: ${TARGET}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`);
      });
      sec.once("error", () => ok(false));
      let h = "";
      sec.on("data", (d) => {
        h += d.toString("latin1");
        if (h.includes("\r\n\r\n") || h.length > 8192) {
          const m = h.match(/HTTP\/1\.[01] (\d+)/);
          const st = m ? +m[1] : 0;
          try { sec.destroy(); } catch (_) {}
          ok(st >= 200 && st < 500);
        }
      });
    }
  });
}
// ip -> int
const ipInt = (ip) => ip.split(".").reduce((a, b) => a * 256 + +b, 0) >>> 0;
let ranges = null;
function loadZones() {
  if (ranges) return ranges;
  ranges = [];
  const dir = path.join(__dirname, "ip-zones");
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith(".zone")) continue;
    const cc = f.slice(0, -5).toUpperCase();
    for (const line of fs.readFileSync(path.join(dir, f), "utf8").split("\n")) {
      const m = line.trim().match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
      if (!m) continue;
      const base = ipInt(m[1]), bits = +m[2];
      const size = bits >= 32 ? 1 : 2 ** (32 - bits);
      ranges.push([base, base + size - 1, cc]);
    }
  }
  ranges.sort((a, b) => a[0] - b[0]);
  return ranges;
}
function countryOf(ip) {
  const v = ipInt(ip), r = loadZones();
  let lo = 0, hi = r.length - 1, ans = -1;
  while (lo <= hi) { const m = (lo + hi) >> 1; if (r[m][0] <= v) { ans = m; lo = m + 1; } else hi = m - 1; }
  for (const j of [ans - 1, ans, ans + 1]) // rangos disjuntos; reviso vecinos por seguridad
    if (j >= 0 && j < r.length && r[j][0] <= v && v <= r[j][1]) return r[j][2];
  return "??";
}

(async () => {
  const jobs = Math.min(parseInt(opt("--jobs", "60"), 10) || 60, 100);
  const timeoutMs = parseInt(opt("--timeout", "6000"), 10) || 6000;
  const outFile = path.resolve(opt("--out", "proxies-valid.txt"));
  const byCountryFile = path.join(path.dirname(outFile), "proxies-by-country.json");
  const want = new Set(fs.readFileSync(path.join(__dirname, "countries.txt"), "utf8").split(/[\s]+/).filter(Boolean));
  console.log(`Paises objetivo (${want.size}): ${[...want].join(",")}`);

  // 1. pool por pais (serie + pausa: geonode rate-limitea en rafaga)
  const tag = new Map(); // proxy -> cc
  for (const cc of want) {
    try { clean((await fetchText(PS(cc))).split(/[\r\n]+/)).forEach((p) => tag.set(p, cc)); } catch (_) {}
    for (let pg = 1; pg <= 2; pg++) {
      try {
        const j = JSON.parse(await fetchText(GEO(cc, pg)));
        ((j && j.data) || []).map((x) => `${x.ip}:${x.port}`).filter((s) => clean([s]).length).forEach((p) => tag.set(p, cc));
      } catch (_) {}
      await sleep(400);
    }
    process.stdout.write(`\r bajando por-pais ${tag.size} proxies... ${cc}`);
    await sleep(400);
  }
  console.log(`\n por-pais: ${tag.size} proxies`);
  // 2. bulk: filtro ANTES por rangos locales, solo paises objetivo
  if (!has("--no-bulk")) {
    let n = 0, kept = 0;
    for (const u of BULKS) {
      try {
        for (const p of clean((await fetchText(u)).split(/[\r\n]+/))) {
          if (tag.has(p)) continue;
          n++;
          const cc = countryOf(p.split(":")[0]);
          if (want.has(cc)) { tag.set(p, cc); kept++; }
        }
      } catch (e) { console.log(` bulk ${u.slice(-30)}: - (${e.message})`); }
    }
    console.log(` bulk: ${kept}/${n} en paises objetivo`);
  }
  const extra = opt("--extra", "");
  if (extra) {
    let n = 0;
    for (const p of clean(fs.readFileSync(path.resolve(extra), "utf8").split(/[\r\n]+/))) {
      if (tag.has(p)) continue;
      const cc = countryOf(p.split(":")[0]);
      if (want.has(cc)) { tag.set(p, cc); n++; }
    }
    console.log(` extra ${extra}: ${n} en paises objetivo`);
  }
  const all = [...tag.keys()];
  console.log(`Total a probar: ${all.length}`);

  // 3. TCP rapido (descarta muertos sin costo TLS)
  const open = [];
  for (let k = 0; k < all.length; k += 1000) {
    const r = await Promise.all(all.slice(k, k + 1000).map((p) => tcpOpen(p, 1500)));
    r.forEach((p) => p && open.push(p));
    process.stdout.write(`\r tcp ${Math.min(k + 1000, all.length)}/${all.length} abiertos=${open.length}`);
  }
  console.log(`\nTCP abiertos: ${open.length}/${all.length}`);

  // 4. check real contra TARGET
  const ok = [];
  let n = 0;
  const q = [...open];
  const worker = async () => {
    while (q.length) {
      const p = q.shift();
      n++;
      if (await targetCheck(p, timeoutMs)) { ok.push(p); console.log(`[${n}/${open.length}] ${p} OK (${tag.get(p)})`); }
      else if (n % 100 === 0) console.log(` ... ${n}/${open.length} ok=${ok.length}`);
    }
  };
  await Promise.all(Array.from({ length: Math.min(jobs, q.length || 1) }, worker));

  // 5. guardar
  const byCc = {};
  for (const p of ok) {
    const cc = tag.get(p) || countryOf(p.split(":")[0]);
    if (!want.has(cc)) continue;
    (byCc[cc] = byCc[cc] || []).push(p);
  }
  const valid = Object.values(byCc).flat();
  try { if (fs.existsSync(outFile)) fs.copyFileSync(outFile, outFile + ".bak"); } catch (_) {}
  fs.writeFileSync(outFile, valid.join("\n") + (valid.length ? "\n" : ""));
  fs.writeFileSync(byCountryFile, JSON.stringify(byCc, null, 1));
  console.log(`\nFIN: ${valid.length}/${ok.length} en paises objetivo -> ${outFile}`);
  for (const cc of Object.keys(byCc).sort()) console.log(`  ${cc}: ${byCc[cc].length}`);
  console.log(`Descartados fuera de objetivo: ${ok.length - valid.length}`);
  process.exit(0); // sin esto Node se queda colgado por sockets/timers abiertos
})().catch((e) => { console.error("ERROR", e.message); process.exit(1); });
