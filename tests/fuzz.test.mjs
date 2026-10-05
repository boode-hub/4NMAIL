// Robustness: thousands of corrupted inputs through every parser.
// Run: node tests/fuzz.test.mjs
//
// Hostile files are the normal case for this tool. Each corrupted input must
// finish quickly and either produce a result or fail with an ordinary error —
// never hang, overflow the stack or allocate without bound. Seeded, so a
// failure reproduces.

import assert from "node:assert/strict";
import { deflateRawSync, deflateSync } from "node:zlib";
import { parseHeaders } from "../scripts/parse-headers.js";
import { parseAuth } from "../scripts/parse-auth.js";
import { parseBody } from "../scripts/parse-body.js";
import { extractIOCs, refreshIOCs } from "../scripts/extract-iocs.js";
import { inspectContainers } from "../scripts/inspect-files.js";
import { msgToEml } from "../scripts/msg-parser.js";
import { analyzeLanguage } from "../scripts/analyze-language.js";
import { analyzeThread } from "../scripts/analyze-thread.js";
import { analyzeUnicode } from "../scripts/analyze-unicode.js";
import { zipEncrypted, crc32, decodeToBytes } from "../scripts/file-export.js";
import { readFileSync } from "node:fs";

let seed = 0x5eed;
const rand = () => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32);
const pick = (n) => Math.floor(rand() * n);

/** Flip, overwrite, truncate, duplicate and splice — the usual corruption. */
function mutate(src) {
  let b = new Uint8Array(src);
  const ops = 1 + pick(6);
  for (let k = 0; k < ops; k++) {
    const op = pick(6);
    if (op === 0 && b.length) b[pick(b.length)] ^= 1 << pick(8);
    else if (op === 1 && b.length) b[pick(b.length)] = [0, 0xff, 0x7f, 0x80][pick(4)];
    else if (op === 2 && b.length) {
      // a 32-bit field set to an extreme value: sizes, offsets, counts
      const at = pick(Math.max(1, b.length - 4));
      const v = [0xffffffff, 0x7fffffff, 0, 0xfffffffe, b.length * 7][pick(5)];
      for (let i = 0; i < 4 && at + i < b.length; i++) b[at + i] = (v >>> (i * 8)) & 0xff;
    } else if (op === 3) b = b.slice(0, pick(b.length + 1));
    else if (op === 4 && b.length) {
      const at = pick(b.length);
      const len = pick(Math.min(512, b.length - at) + 1);
      const out = new Uint8Array(b.length + len);
      out.set(b.subarray(0, at + len));
      out.set(b.subarray(at), at + len);
      b = out;
    } else if (op === 5 && b.length > 8) {
      const a = pick(b.length);
      const c = pick(b.length);
      const len = pick(Math.min(64, b.length - Math.max(a, c)) + 1);
      b.copyWithin(a, c, c + len);
    }
  }
  return b;
}

const enc = (s) => new TextEncoder().encode(s);

function zipOf(files, deflate) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const bytes = enc(content);
    const data = deflate ? new Uint8Array(deflateRawSync(bytes)) : bytes;
    const n = enc(name);
    const l = new DataView(new ArrayBuffer(30));
    l.setUint32(0, 0x04034b50, true);
    l.setUint16(8, deflate ? 8 : 0, true);
    l.setUint32(14, crc32(bytes), true);
    l.setUint32(18, data.length, true);
    l.setUint32(22, bytes.length, true);
    l.setUint16(26, n.length, true);
    const c = new DataView(new ArrayBuffer(46));
    c.setUint32(0, 0x02014b50, true);
    c.setUint16(10, deflate ? 8 : 0, true);
    c.setUint32(16, crc32(bytes), true);
    c.setUint32(20, data.length, true);
    c.setUint32(24, bytes.length, true);
    c.setUint16(28, n.length, true);
    c.setUint32(42, offset, true);
    locals.push(new Uint8Array(l.buffer), n, data);
    centrals.push(new Uint8Array(c.buffer), n);
    offset += 30 + n.length + data.length;
  }
  const cd = centrals.reduce((s, p) => s + p.length, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(8, centrals.length / 2, true);
  end.setUint16(10, centrals.length / 2, true);
  end.setUint32(12, cd, true);
  end.setUint32(16, offset, true);
  const parts = [...locals, ...centrals, new Uint8Array(end.buffer)];
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function pdfOf() {
  const stream = new Uint8Array(deflateSync(enc("<< /URI (https://inner.test/x) /S /JavaScript >>")));
  const head = enc(`%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /URI /URI (https://a.test/) >> >>\nendobj\n2 0 obj\n<< /Length ${stream.length} /Filter /FlateDecode >>\nstream\n`);
  const tail = enc("\nendstream\nendobj\n3 0 obj\n<< /Subtype /Image /Width 8 /Height 8 /BitsPerComponent 1 /ColorSpace /DeviceGray /Length 8 >>\nstream\n\x00\xff\x00\xff\x00\xff\x00\xff\nendstream\nendobj\n%%EOF\n");
  const out = new Uint8Array(head.length + stream.length + tail.length);
  out.set(head);
  out.set(stream, head.length);
  out.set(tail, head.length + stream.length);
  return out;
}

// The .msg writer from msg.test.mjs is reused through its sample file builder.
const msgSource = readFileSync(new URL("./msg.test.mjs", import.meta.url), "utf8");
const { sampleMsg } = await import(
  "data:text/javascript," +
    encodeURIComponent(
      msgSource
        .split("// ===== tests =====")[0]
        .replace(/^import .*$/gm, "")
        .replace(/^let passed[\s\S]*?^function test[\s\S]*?^}\n/m, "") + "\nexport { sampleMsg };",
    )
);

const SEEDS = {
  zip: zipOf({ "a.txt": "hello", "b/run.exe": "MZ....", "[Content_Types].xml": "<Types/>", "word/_rels/x.rels": '<Relationship Type="x/attachedTemplate" Target="http://t.test/a" TargetMode="External"/>' }, true),
  zipStored: zipOf({ "a.txt": "hello world", "c.js": "WScript" }, false),
  zipEncrypted: zipEncrypted("p.exe", enc("MZ payload"), "4455"),
  pdf: pdfOf(),
  rtf: enc('{\\rtf1{\\object\\objupdate{\\*\\objclass Equation.3}{\\*\\objdata 0105}}{\\field{\\*\\fldinst HYPERLINK "http://r.test/"}}}'),
  ics: enc("BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nDESCRIPTION:go to https://cal.te\r\n st/x\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"),
  ole: new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, ...enc("_\0V\0B\0A\0_\0P\0R\0O\0J\0E\0C\0T\0 AutoOpen")]),
  msg: sampleMsg(),
};
const EML = readFileSync(new URL("../sample-data/phishing-spoofed.eml", import.meta.url), "utf8");

// The seeds must be valid, or the mutations never reach the deep code paths.
{
  assert.match(msgToEml(SEEDS.msg), /paypa1\.com/);
  const body = { text: "the password is 4455", links: [], attachments: Object.entries(SEEDS).map(([k, bytes]) => ({ filename: `${k}.${{ zip: "docx", zipStored: "zip", zipEncrypted: "zip", pdf: "pdf", rtf: "rtf", ics: "ics", ole: "doc", msg: "msg" }[k]}`, size: bytes.length, bytes })) };
  const iocs = extractIOCs({}, body);
  await inspectContainers(iocs, body);
  refreshIOCs(iocs);
  const types = new Set(iocs.attachments.flatMap((a) => (a.risks || []).map((r) => r.type)));
  for (const t of ["archive-executable", "remote-template", "archive-password", "pdf-javascript", "rtf-equation", "calendar-links", "macros"]) assert.ok(types.has(t), `seed finding ${t}: ${[...types]}`);
  assert.ok(iocs.attachments.some((a) => a.value === "msg.eml"), "seed .msg converted");
}

let runs = 0;
const problems = [];
const SLOW_MS = 3000;

function isBadError(e) {
  return e instanceof RangeError || /call stack|array length|out of memory/i.test(e?.message || "");
}

async function check(label, fn) {
  const start = performance.now();
  try {
    await fn();
  } catch (e) {
    if (isBadError(e)) problems.push(`${label}: ${e.constructor.name}: ${e.message}`);
  }
  const ms = performance.now() - start;
  if (ms > SLOW_MS) problems.push(`${label}: took ${Math.round(ms)} ms`);
  runs++;
}

// 1. Corrupted attachments through the full inspection path.
for (const [kind, src] of Object.entries(SEEDS)) {
  for (let i = 0; i < 150; i++) {
    const bytes = mutate(src);
    const name = { zip: "a.docx", zipStored: "a.zip", zipEncrypted: "a.zip", pdf: "a.pdf", rtf: "a.rtf", ics: "a.ics", ole: "a.doc", msg: "a.msg" }[kind];
    await check(`${kind} #${i}`, async () => {
      const body = { text: "the password is 4455", links: [], attachments: [{ filename: name, contentType: "application/octet-stream", size: bytes.length, bytes }] };
      const iocs = extractIOCs({ from: { email: "a@b.test" } }, body);
      await inspectContainers(iocs, body);
      refreshIOCs(iocs);
    });
  }
}

// 2. Corrupted .msg files straight into the converter.
for (let i = 0; i < 300; i++) {
  const bytes = mutate(SEEDS.msg);
  await check(`msgToEml #${i}`, () => msgToEml(bytes));
}

// 3. Corrupted email text through the text parsers.
for (let i = 0; i < 300; i++) {
  const raw = new TextDecoder().decode(mutate(enc(EML)));
  await check(`eml #${i}`, () => {
    const headers = parseHeaders(raw);
    parseAuth(headers);
    const body = parseBody(raw);
    extractIOCs(headers, body);
    analyzeLanguage(body?.text || "");
    analyzeThread(headers, body);
    analyzeUnicode(headers, body, []);
  });
}

// 4. Garbage into the hex/Base64 decoder.
for (let i = 0; i < 200; i++) {
  const text = new TextDecoder().decode(mutate(enc("4d5a9000 0300 0000 0400 data:application/octet-stream;base64,TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAA")));
  await check(`decode #${i}`, () => decodeToBytes(text, ["auto", "hex", "base64"][i % 3]));
}

console.log(`${runs} corrupted inputs, ${problems.length} problems`);
for (const p of problems.slice(0, 20)) console.error(`  FAIL  ${p}`);
assert.ok(runs > 1000);
process.exit(problems.length ? 1 : 0);
