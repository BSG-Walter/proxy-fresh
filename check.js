/*
 * Proxies frescos de paises objetivo que conectan a un TARGET https.
 *
 * Optimizado para grandes cantidades de proxies:
 *   - Descargas por-pais concurrentes y con limite.
 *   - Filtro bulk por IP antes de cualquier conexion.
 *   - TCP y target-check con workers persistentes, sin bloques de 1000.
 *   - Cola mediante indice (sin Array.shift()).
 *   - Menos salida por consola.
 *   - CONNECT + TLS + GET contra TARGET.
 *
 * Uso:
 *   node check.js
 *   node check.js --target www.google.com --jobs 150 --tcp-jobs 300 --timeout 6000
 *   node check.js --no-bulk
 *   node check.js --extra lista-propia.txt
 *
 * Opciones adicionales:
 *   --jobs N          Concurrencia del check real (default 120)
 *   --tcp-jobs N      Concurrencia TCP (default 300)
 *   --tcp-timeout N   Timeout TCP en ms (default 1200)
 *   --timeout N       Timeout total del check real en ms (default 6000)
 *   --source-jobs N   Concurrencia de descargas por-pais (default 4)
 *   --progress N      Mostrar progreso cada N checks (default 100)
 */

const fs = require("fs");
const net = require("net");
const tls = require("tls");
const path = require("path");

const args = process.argv.slice(2);
const opt = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 && args[i + 1] ? args[i + 1] : d;
};
const has = (n) => args.includes(n);

const intOpt = (name, def, min, max) => {
  const n = parseInt(opt(name, String(def)), 10);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, n));
};

const TARGET = opt("--target", "www.example.com");

const PS = (cc) =>
  `https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=${cc}&ssl=all&anonymity=all`;

const GEO = (cc, page = 1) =>
  `https://proxylist.geonode.com/api/proxy-list?limit=200&page=${page}&sort_by=lastChecked&sort_type=desc&country=${cc}`;

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
  const timer = setTimeout(() => ctl.abort(), ms);

  try {
    const res = await fetch(url, {
      signal: ctl.signal,
      headers: {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/plain, application/json, */*",
      },
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

/*
 * Devuelve proxies unicos.
 * Se mantiene deliberadamente compatible con el formato original:
 * IP:PORT, sin dominios, paths ni credenciales.
 */
function clean(lines) {
  const out = new Set();

  for (let s of lines) {
    s = String(s || "").trim();

    if (!s) continue;

    // Elimina protocolo.
    s = s.replace(/^https?:\/\//i, "");

    // Solo la primera columna.
    const sp = s.search(/\s/);
    if (sp >= 0) s = s.slice(0, sp);

    if (!s || s.includes("@") || s.includes("/")) continue;

    const i = s.lastIndexOf(":");
    if (i < 0) continue;

    const ip = s.slice(0, i);
    const port = s.slice(i + 1);

    if (!/^\d{1,5}$/.test(port)) continue;

    const pn = Number(port);
    if (pn < 1 || pn > 65535) continue;

    // Solo IPv4, igual que el programa original.
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) continue;

    const oct = ip.split(".");
    if (oct.some((x) => Number(x) > 255)) continue;

    out.add(`${ip}:${port}`);
  }

  return [...out];
}

/*
 * TCP check.
 * El socket se destruye inmediatamente al conectar:
 * solo nos interesa saber si el endpoint acepta TCP.
 */
function tcpOpen(p, ms) {
  return new Promise((resolve) => {
    const i = p.lastIndexOf(":");
    const host = p.slice(0, i);
    const port = Number(p.slice(i + 1));

    let finished = false;

    const sock = net.connect({
      host,
      port,
      timeout: ms,
    });

    const done = (value) => {
      if (finished) return;
      finished = true;

      try {
        sock.destroy();
      } catch (_) {}

      resolve(value);
    };

    sock.once("connect", () => done(p));
    sock.once("timeout", () => done(null));
    sock.once("error", () => done(null));
  });
}

function parseProxy(p) {
  let s = String(p || "").trim().replace(/^https?:\/\//i, "");
  let auth = null;

  const at = s.lastIndexOf("@");

  if (at >= 0) {
    auth = s.slice(0, at);
    s = s.slice(at + 1);
  }

  const i = s.lastIndexOf(":");

  if (i < 0) {
    throw new Error("proxy sin puerto");
  }

  const host = s.slice(0, i);
  const port = parseInt(s.slice(i + 1), 10);

  if (!host || !Number.isFinite(port) || port < 1 || port > 65535) {
    throw new Error("proxy invalido");
  }

  return { host, port, auth };
}

/*
 * Check real:
 *
 *   TCP al proxy
 *   CONNECT TARGET:443
 *   TLS handshake
 *   GET /
 *
 * Se considera valido cualquier HTTP 2xx-4xx recibido del TARGET.
 */
function targetCheck(p, timeoutMs) {
  return new Promise((resolve) => {
    let proxy;

    try {
      proxy = parseProxy(p);
    } catch (_) {
      resolve(false);
      return;
    }

    let finished = false;
    let timer = null;
    let sock = null;
    let sec = null;

    const finish = (value) => {
      if (finished) return;
      finished = true;

      if (timer) clearTimeout(timer);

      try {
        if (sec) sec.destroy();
      } catch (_) {}

      try {
        if (sock) sock.destroy();
      } catch (_) {}

      resolve(value);
    };

    timer = setTimeout(() => finish(false), timeoutMs);

    sock = net.connect({
      host: proxy.host,
      port: proxy.port,
    });

    sock.once("error", () => finish(false));

    sock.once("connect", () => {
      let req =
        `CONNECT ${TARGET}:443 HTTP/1.1\r\n` +
        `Host: ${TARGET}:443\r\n` +
        `Proxy-Connection: Keep-Alive\r\n`;

      if (proxy.auth) {
        req +=
          `Proxy-Authorization: Basic ` +
          Buffer.from(proxy.auth).toString("base64") +
          "\r\n";
      }

      req += "\r\n";

      try {
        sock.write(req);
      } catch (_) {
        finish(false);
      }
    });

    let buf = "";

    const onProxyData = (c) => {
      buf += c.toString("latin1");

      // Evita acumular respuestas enormes de proxies defectuosos.
      if (buf.length > 16384 && !buf.includes("\r\n\r\n")) {
        finish(false);
        return;
      }

      const end = buf.indexOf("\r\n\r\n");
      if (end < 0) return;

      if (!/^HTTP\/1\.[01]\s+200\b/i.test(buf)) {
        finish(false);
        return;
      }

      // Muy importante:
      // quitamos el listener ANTES de entregar el socket a TLS.
      sock.off("data", onProxyData);

      try {
        sec = tls.connect({
          socket: sock,
          servername: TARGET,
          rejectUnauthorized: true,
        });

        sec.once("error", () => finish(false));

        sec.once("secureConnect", () => {
          try {
            sec.write(
              `GET / HTTP/1.1\r\n` +
              `Host: ${TARGET}\r\n` +
              `User-Agent: Mozilla/5.0\r\n` +
              `Accept: */*\r\n` +
              `Connection: close\r\n\r\n`
            );
          } catch (_) {
            finish(false);
          }
        });

        let h = "";

        sec.on("data", (d) => {
          h += d.toString("latin1");

          // Basta con recibir headers.
          if (h.includes("\r\n\r\n") || h.length > 8192) {
            const m = h.match(/^HTTP\/1\.[01]\s+(\d+)/m);
            const st = m ? Number(m[1]) : 0;

            finish(st >= 200 && st < 500);
          }
        });
      } catch (_) {
        finish(false);
      }
    };

    sock.on("data", onProxyData);
  });
}

/*
 * ip -> uint32
 */
const ipInt = (ip) =>
  ip.split(".").reduce((a, b) => a * 256 + Number(b), 0) >>> 0;

let ranges = null;

function loadZones() {
  if (ranges) return ranges;

  ranges = [];

  const dir = path.join(__dirname, "ip-zones");

  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith(".zone")) continue;

    const cc = f.slice(0, -5).toUpperCase();
    const data = fs.readFileSync(path.join(dir, f), "utf8");

    for (const line of data.split("\n")) {
      const m = line.trim().match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);

      if (!m) continue;

      const base = ipInt(m[1]);
      const bits = Number(m[2]);

      const size = bits >= 32 ? 1 : 2 ** (32 - bits);

      ranges.push([base, base + size - 1, cc]);
    }
  }

  ranges.sort((a, b) => a[0] - b[0]);

  return ranges;
}

function countryOf(ip) {
  const v = ipInt(ip);
  const r = loadZones();

  let lo = 0;
  let hi = r.length - 1;
  let ans = -1;

  while (lo <= hi) {
    const m = (lo + hi) >> 1;

    if (r[m][0] <= v) {
      ans = m;
      lo = m + 1;
    } else {
      hi = m - 1;
    }
  }

  // Los rangos son disjuntos, pero mantenemos la comprobacion vecina
  // por compatibilidad con la version original.
  for (const j of [ans - 1, ans, ans + 1]) {
    if (
      j >= 0 &&
      j < r.length &&
      r[j][0] <= v &&
      v <= r[j][1]
    ) {
      return r[j][2];
    }
  }

  return "??";
}

/*
 * Ejecuta una funcion sobre una lista usando workers persistentes.
 * No usa shift(), por lo que la cola sigue siendo O(1) por elemento.
 */
async function runWorkers(items, workerCount, fn) {
  if (!items.length) return [];

  const results = [];
  let index = 0;

  const worker = async () => {
    while (true) {
      const i = index++;

      if (i >= items.length) return;

      try {
        const result = await fn(items[i], i);

        if (result !== null && result !== undefined && result !== false) {
          results.push(result);
        }
      } catch (_) {}
    }
  };

  const n = Math.min(workerCount, items.length);

  await Promise.all(
    Array.from({ length: n }, () => worker())
  );

  return results;
}

/*
 * Descarga las fuentes de un pais.
 *
 * ProxyScrape + 2 paginas de GeoNode se ejecutan en paralelo.
 * Solo se limita la cantidad de paises simultaneos para no golpear
 * las APIs con una rafaga enorme.
 */
async function fetchCountry(cc) {
  const promises = [
    fetchText(PS(cc))
      .then((txt) => clean(txt.split(/[\r\n]+/)))
      .catch(() => []),

    fetchText(GEO(cc, 1))
      .then((txt) => {
        const j = JSON.parse(txt);
        return ((j && j.data) || [])
          .map((x) => `${x.ip}:${x.port}`)
          .filter((s) => clean([s]).length);
      })
      .catch(() => []),

    fetchText(GEO(cc, 2))
      .then((txt) => {
        const j = JSON.parse(txt);
        return ((j && j.data) || [])
          .map((x) => `${x.ip}:${x.port}`)
          .filter((s) => clean([s]).length);
      })
      .catch(() => []),
  ];

  const [ps, geo1, geo2] = await Promise.all(promises);

  return [...new Set([...ps, ...geo1, ...geo2])];
}

(async () => {
  const jobs = intOpt("--jobs", 120, 1, 1000);
  const tcpJobs = intOpt("--tcp-jobs", 300, 1, 2000);
  const tcpTimeout = intOpt("--tcp-timeout", 1200, 100, 10000);
  const timeoutMs = intOpt("--timeout", 6000, 500, 30000);
  const sourceJobs = intOpt("--source-jobs", 4, 1, 20);
  const progressEvery = intOpt("--progress", 100, 1, 10000);

  const outFile = path.resolve(
    opt("--out", "proxies-valid.txt")
  );

  const byCountryFile = path.join(
    path.dirname(outFile),
    "proxies-by-country.json"
  );

  const countriesFile = path.join(
    __dirname,
    "countries.txt"
  );

  const want = new Set(
    fs
      .readFileSync(countriesFile, "utf8")
      .split(/[\s]+/)
      .filter(Boolean)
      .map((x) => x.toUpperCase())
  );

  console.log(
    `Paises objetivo (${want.size}): ${[...want].join(",")}`
  );

  console.log(
    `Configuracion: tcp-jobs=${tcpJobs}, jobs=${jobs}, ` +
    `tcp-timeout=${tcpTimeout}ms, timeout=${timeoutMs}ms`
  );

  /*
   * 1. Fuentes por pais
   */
  const tag = new Map();

  const countries = [...want];

  let countryDone = 0;

  await runWorkers(
    countries,
    sourceJobs,
    async (cc) => {
      const proxies = await fetchCountry(cc);

      for (const p of proxies) {
        if (!tag.has(p)) {
          tag.set(p, cc);
        }
      }

      countryDone++;

      process.stdout.write(
        `\r fuentes por-pais: ${countryDone}/${countries.length} ` +
        `proxies=${tag.size}`
      );

      return null;
    }
  );

  console.log(
    `\n por-pais: ${tag.size} proxies`
  );

  /*
   * 2. Bulk:
   * descargamos las listas en paralelo.
   *
   * El filtro por pais se hace antes de agregarlas al pool.
   */
  if (!has("--no-bulk")) {
    console.log(`Descargando ${BULKS.length} listas bulk...`);

    const bulkResults = await Promise.all(
      BULKS.map(async (u) => {
        try {
          return clean(
            (await fetchText(u)).split(/[\r\n]+/)
          );
        } catch (e) {
          console.log(
            `\n bulk ${u.slice(-45)}: error (${e.message})`
          );
          return [];
        }
      })
    );

    let bulkSeen = 0;
    let bulkKept = 0;

    for (const list of bulkResults) {
      for (const p of list) {
        if (tag.has(p)) continue;

        bulkSeen++;

        const cc = countryOf(
          p.slice(0, p.lastIndexOf(":"))
        );

        if (want.has(cc)) {
          tag.set(p, cc);
          bulkKept++;
        }
      }
    }

    console.log(
      ` bulk: ${bulkKept}/${bulkSeen} en paises objetivo`
    );
  }

  /*
   * 3. Extra
   */
  const extra = opt("--extra", "");

  if (extra) {
    let n = 0;

    const extraList = clean(
      fs
        .readFileSync(path.resolve(extra), "utf8")
        .split(/[\r\n]+/)
    );

    for (const p of extraList) {
      if (tag.has(p)) continue;

      const cc = countryOf(
        p.slice(0, p.lastIndexOf(":"))
      );

      if (want.has(cc)) {
        tag.set(p, cc);
        n++;
      }
    }

    console.log(
      ` extra ${extra}: ${n} en paises objetivo`
    );
  }

  const all = [...tag.keys()];

  console.log(`Total a probar: ${all.length}`);

  /*
   * 4. TCP rapido
   *
   * Antes habia bloques de 1000:
   *
   *   esperar 1000 -> esperar -> siguientes 1000
   *
   * Ahora tenemos workers persistentes:
   *
   *   termina uno -> inmediatamente entra otro.
   */
  console.log(
    `TCP check: ${tcpJobs} conexiones simultaneas...`
  );

  let tcpDone = 0;

  const open = [];

  await runWorkers(
    all,
    tcpJobs,
    async (p) => {
      const r = await tcpOpen(p, tcpTimeout);

      tcpDone++;

      if (r) open.push(r);

      if (
        tcpDone % progressEvery === 0 ||
        tcpDone === all.length
      ) {
        process.stdout.write(
          `\r tcp ${tcpDone}/${all.length} abiertos=${open.length}`
        );
      }

      return null;
    }
  );

  console.log(
    `\nTCP abiertos: ${open.length}/${all.length}`
  );

  /*
   * 5. Check real contra TARGET
   */
  console.log(
    `Check TARGET ${TARGET}: ${jobs} conexiones simultaneas...`
  );

  const ok = [];
  let checked = 0;

  await runWorkers(
    open,
    jobs,
    async (p) => {
      const good = await targetCheck(p, timeoutMs);

      checked++;

      if (good) {
        ok.push(p);
      }

      if (
        checked % progressEvery === 0 ||
        checked === open.length
      ) {
        process.stdout.write(
          `\r target ${checked}/${open.length} ` +
          `validos=${ok.length}`
        );
      }

      return null;
    }
  );

  console.log(
    `\nTARGET validos: ${ok.length}/${open.length}`
  );

  /*
   * 6. Guardar
   */
  const byCc = {};

  for (const p of ok) {
    const cc =
      tag.get(p) ||
      countryOf(p.slice(0, p.lastIndexOf(":")));

    if (!want.has(cc)) continue;

    (byCc[cc] ||= []).push(p);
  }

  const valid = Object.values(byCc).flat();

  try {
    if (fs.existsSync(outFile)) {
      fs.copyFileSync(
        outFile,
        outFile + ".bak"
      );
    }
  } catch (_) {}

  fs.writeFileSync(
    outFile,
    valid.join("\n") +
      (valid.length ? "\n" : "")
  );

  fs.writeFileSync(
    byCountryFile,
    JSON.stringify(byCc, null, 1)
  );

  console.log(
    `\nFIN: ${valid.length}/${ok.length} ` +
    `en paises objetivo -> ${outFile}`
  );

  for (const cc of Object.keys(byCc).sort()) {
    console.log(
      `  ${cc}: ${byCc[cc].length}`
    );
  }

  console.log(
    `Descartados fuera de objetivo: ` +
    `${ok.length - valid.length}`
  );

  /*
   * Forzar salida para evitar que algun socket/timer residual
   * mantenga vivo el proceso.
   */
  process.exit(0);
})().catch((e) => {
  console.error("ERROR", e);
  process.exit(1);
});
