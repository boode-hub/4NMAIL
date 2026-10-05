// Speed check: the whole analysis pipeline over deliberately heavy messages.
// Run: node tests/perf.bench.mjs
// Not part of CI timing assertions except a generous ceiling per case, so a
// regression that makes the app hang is caught.

import { parseHeaders } from "../scripts/parse-headers.js";
import { parseAuth } from "../scripts/parse-auth.js";
import { parseBody } from "../scripts/parse-body.js";
import { extractIOCs, refreshIOCs } from "../scripts/extract-iocs.js";
import { inspectContainers } from "../scripts/inspect-files.js";
import { sha256Bytes, md5Bytes } from "../scripts/hash-utils.js";
import { analyzeLanguage } from "../scripts/analyze-language.js";
import { analyzeIdentity } from "../scripts/analyze-identity.js";
import { analyzeThread } from "../scripts/analyze-thread.js";
import { analyzeUnicode } from "../scripts/analyze-unicode.js";
import { calculateScore } from "../scripts/score.js";
import { buildHtmlReport, buildCsvReport, buildJsonReport, buildStixBundle, buildMispEvent } from "../scripts/report.js";

const CEILING_MS = Number(process.env.PERF_CEILING_MS || 8000);

async function pipeline(raw) {
  const t = {};
  let last = performance.now();
  const lap = (name) => {
    const now = performance.now();
    t[name] = Math.round(now - last);
    last = now;
  };
  const headers = parseHeaders(raw);
  lap("headers");
  const auth = parseAuth(headers);
  lap("auth");
  const body = parseBody(raw);
  lap("body");
  const iocs = extractIOCs(headers, body);
  lap("iocs");
  await inspectContainers(iocs, body);
  refreshIOCs(iocs);
  lap("inside files");
  for (const a of iocs.attachments) {
    if (!a.bytes?.length) continue;
    a.sha256 = await sha256Bytes(a.bytes);
    a.md5 = md5Bytes(a.bytes);
  }
  lap("hashes");
  const lang = body?.text ? analyzeLanguage(body.text) : null;
  lap("language");
  const identity = analyzeIdentity(headers);
  const thread = analyzeThread(headers, body);
  identity.findings.push(...thread.findings);
  lap("identity+thread");
  identity.findings.push(...analyzeUnicode(headers, body, iocs.attachments));
  lap("unicode");
  const score = calculateScore(auth, iocs, lang, headers, identity);
  lap("score");
  const analysis = { headers, auth, body, iocs, languageAnalysis: lang, identity, thread, score };
  buildHtmlReport(analysis);
  buildCsvReport(analysis);
  buildJsonReport(analysis);
  await buildStixBundle(analysis);
  buildMispEvent(analysis);
  lap("exports");
  return { t, analysis };
}

const b64 = (buf) => Buffer.from(buf).toString("base64").replace(/.{76}/g, "$&\r\n");
const words = "please verify your account payment invoice urgent password bank wire transfer team meeting tomorrow report attached thanks regards".split(" ");
const prose = (n) => Array.from({ length: n }, (_, i) => words[(i * 7) % words.length]).join(" ");

const cases = {
  "big HTML body (3 MB, 5,000 links)": () => {
    const links = Array.from({ length: 5000 }, (_, i) => `<a href="https://site${i % 900}.example/p/${i}?u=${i}">link ${i}</a> ${prose(40)}`).join("<br>");
    return `From: a@b.test\r\nTo: c@d.test\r\nSubject: big\r\nMIME-Version: 1.0\r\nContent-Type: text/html\r\n\r\n<html><body>${links}</body></html>`;
  },
  "big plain body (4 MB prose)": () => `From: a@b.test\r\nTo: c@d.test\r\nSubject: prose\r\nContent-Type: text/plain\r\n\r\n${prose(600000)}`,
  "20 MB binary attachment": () => {
    const bin = new Uint8Array(20 * 1024 * 1024).map((_, i) => (i * 31) & 255);
    return `From: a@b.test\r\nSubject: att\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="B"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--B\r\nContent-Type: application/octet-stream; name="data.bin"\r\nContent-Disposition: attachment; filename="data.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64(bin)}\r\n--B--\r\n`;
  },
  "300 Received headers": () => {
    const hops = Array.from({ length: 300 }, (_, i) => `Received: from h${i}.relay.test (h${i}.relay.test [198.51.100.${i % 250}]) by h${i + 1}.relay.test; Mon, 5 Oct 2026 09:${String(i % 60).padStart(2, "0")}:00 +0000`).join("\r\n");
    return `${hops}\r\nFrom: a@b.test\r\nSubject: hops\r\n\r\nhello`;
  },
  "long quoted thread (200 replies)": () => {
    const thread = Array.from({ length: 200 }, (_, i) => `\r\nFrom: person${i}@corp.test\r\nSent: Monday, October ${(i % 28) + 1}, 2026 9:00 AM\r\nTo: team@corp.test\r\nSubject: RE: project\r\n\r\n${prose(60)}\r\n`).join("");
    return `From: a@corp.test\r\nSubject: RE: project\r\nIn-Reply-To: <x@corp.test>\r\n\r\nLatest reply${thread}`;
  },
};

let failed = 0;
for (const [name, make] of Object.entries(cases)) {
  const raw = make();
  const start = performance.now();
  const { t } = await pipeline(raw);
  const total = Math.round(performance.now() - start);
  const slowest = Object.entries(t).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => `${k} ${v}`).join(", ");
  const ok = total < CEILING_MS;
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "SLOW"} ${String(total).padStart(6)} ms  ${name}  — ${slowest}`);
}
process.exit(failed ? 1 : 0);
