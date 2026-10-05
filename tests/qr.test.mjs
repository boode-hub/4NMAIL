// QR codes in images and PDFs ("quishing").
// Run: node tests/qr.test.mjs
//
// The codes are made by a small encoder written here from the QR
// specification (version 2, error correction L, byte mode, mask 0), so the
// decoder is checked against codes it had no part in producing.

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { deflateSync } from "node:zlib";
import { decodeQr, pdfImagePixels, inspectContainers } from "../scripts/inspect-files.js";
import { extractIOCs, refreshIOCs } from "../scripts/extract-iocs.js";
import { calculateScore } from "../scripts/score.js";
import { analyzeLanguage } from "../scripts/analyze-language.js";

globalThis.jsQR = createRequire(import.meta.url)("../vendor/jsQR.js");

let passed = 0;
const failures = [];
async function test(name, fn) {
  try {
    await fn();
    passed++;
  } catch (e) {
    failures.push({ name, message: e.message });
  }
}

// ===== a QR encoder: version 2-L, byte mode, mask 0 =====

function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

function reedSolomon(data, degree) {
  const divisor = new Array(degree).fill(0);
  divisor[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      divisor[j] = gfMul(divisor[j], root);
      if (j + 1 < degree) divisor[j] ^= divisor[j + 1];
    }
    root = gfMul(root, 2);
  }
  const result = new Array(degree).fill(0);
  for (const b of data) {
    const factor = b ^ result.shift();
    result.push(0);
    for (let i = 0; i < degree; i++) result[i] ^= gfMul(divisor[i], factor);
  }
  return result;
}

/** A 25×25 matrix (true = dark) encoding `text` (at most 32 bytes). */
function qrMatrix(text) {
  const bytes = [...new TextEncoder().encode(text)];
  assert.ok(bytes.length <= 32, "version 2-L holds 32 bytes");
  const bits = [];
  const put = (value, n) => {
    for (let i = n - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  put(0b0100, 4);
  put(bytes.length, 8);
  for (const b of bytes) put(b, 8);
  put(0, Math.min(4, 34 * 8 - bits.length));
  while (bits.length % 8) bits.push(0);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(""), 2));
  for (let pad = 0xec; data.length < 34; pad ^= 0xec ^ 0x11) data.push(pad);
  const codewords = [...data, ...reedSolomon(data, 10)];

  const size = 25;
  const dark = Array.from({ length: size }, () => new Array(size).fill(false));
  const fixed = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, v) => {
    dark[y][x] = v;
    fixed[y][x] = true;
  };
  for (let i = 0; i < size; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, d !== 2 && d !== 4);
      }
    }
  }
  for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(18 + dx, 18 + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);

  // Format information: level L (01), mask 0.
  const formatData = (1 << 3) | 0;
  let rem = formatData;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const format = ((formatData << 10) | rem) ^ 0x5412;
  const fbit = (i) => ((format >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) set(8, i, fbit(i));
  set(8, 7, fbit(6));
  set(8, 8, fbit(7));
  set(7, 8, fbit(8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, fbit(i));
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, fbit(i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, fbit(i));
  set(8, size - 8, true);

  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!fixed[y][x] && i < codewords.length * 8) {
          dark[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) === 1;
          i++;
        }
      }
    }
  }
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fixed[y][x] && (x + y) % 2 === 0) dark[y][x] = !dark[y][x];
  return dark;
}

/** The matrix as 8-bit grey pixels, `scale` px per module, 4-module quiet zone. */
function qrGrey(text, scale = 4) {
  const m = qrMatrix(text);
  const n = (m.length + 8) * scale;
  const px = new Uint8Array(n * n).fill(255);
  for (let y = 0; y < m.length; y++)
    for (let x = 0; x < m.length; x++)
      if (m[y][x]) for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) px[((y + 4) * scale + dy) * n + (x + 4) * scale + dx] = 0;
  return { px, n };
}

function greyToRgba(px) {
  const out = new Uint8ClampedArray(px.length * 4);
  px.forEach((v, i) => out.set([v, v, v, 255], i * 4));
  return out;
}

/** PNG "Up" prediction on each row, as PDF writers store images. */
function predictUp(px, stride) {
  const rows = px.length / stride;
  const out = new Uint8Array(rows * (stride + 1));
  for (let y = 0; y < rows; y++) {
    out[y * (stride + 1)] = 2;
    for (let i = 0; i < stride; i++) out[y * (stride + 1) + 1 + i] = (px[y * stride + i] - (y ? px[(y - 1) * stride + i] : 0)) & 255;
  }
  return out;
}

function pdfWithImage(dict, data) {
  const enc = (s) => new TextEncoder().encode(s);
  const parts = [enc("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n2 0 obj\n"), enc(`${dict}\nstream\n`), data, enc("\nendstream\nendobj\n%%EOF\n")];
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

// ===== tests =====

const URL_TEXT = "https://qr-phish.test/login?id=7";

await test("the decoder reads a code made from the specification", async () => {
  const { px, n } = qrGrey(URL_TEXT);
  assert.equal(await decodeQr(greyToRgba(px), n, n), URL_TEXT);
});

await test("PDF images are decoded: 8-bit grey with PNG prediction, and 1-bit", () => {
  const { px, n } = qrGrey("hello");
  const grey = pdfImagePixels(predictUp(px, n), `<< /Type /XObject /Subtype /Image /Width ${n} /Height ${n} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /DecodeParms << /Predictor 15 /Columns ${n} >> >>`);
  assert.deepEqual([...grey.rgba.subarray(0, 4)], [255, 255, 255, 255]);
  assert.deepEqual(grey.rgba.filter((_, i) => i % 4 === 0), Uint8ClampedArray.from(px));

  const stride = Math.ceil(n / 8);
  const packed = new Uint8Array(stride * n);
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (px[y * n + x]) packed[y * stride + (x >> 3)] |= 0x80 >> (x & 7);
  const mono = pdfImagePixels(packed, `<< /Subtype /Image /Width ${n} /Height ${n} /BitsPerComponent 1 /ColorSpace /DeviceGray >>`);
  assert.deepEqual(mono.rgba.filter((_, i) => i % 4 === 0), Uint8ClampedArray.from(px));
});

await test("a QR code inside a PDF attachment becomes a flagged URL indicator", async () => {
  const { px, n } = qrGrey(URL_TEXT);
  const data = new Uint8Array(deflateSync(predictUp(px, n)));
  const pdf = pdfWithImage(`<< /Type /XObject /Subtype /Image /Width ${n} /Height ${n} /ColorSpace /DeviceGray /BitsPerComponent 8 /Length ${data.length} /Filter /FlateDecode /DecodeParms << /Predictor 15 /Columns ${n} >> >>`, data);
  const body = { text: "Scan the code to keep your mailbox active.", links: [], attachments: [{ filename: "notice.pdf", contentType: "application/pdf", size: pdf.length, bytes: pdf }] };
  const iocs = extractIOCs({ from: { email: "a@b.test" } }, body);
  await inspectContainers(iocs, body);
  refreshIOCs(iocs);
  const url = iocs.urls.find((u) => u.value === URL_TEXT);
  assert.ok(url, iocs.urls.map((u) => u.value).join());
  assert.equal(url.source, "QR code in notice.pdf");
  assert.ok(url.riskFlags.some((f) => f.label === "From a QR code"));
  assert.ok(iocs.domains.some((d) => d.value === "qr-phish.test"));
  const doc = iocs.attachments.find((a) => a.value === "notice.pdf");
  assert.ok(doc.risks.some((r) => r.type === "qr-code"));
  assert.ok(doc.containerInfo.entries.includes(`QR code: ${URL_TEXT}`));
});

await test("a QR link plus pressure is at least Suspicious and named as QR code phishing; a QR link alone is not", async () => {
  const { px, n } = qrGrey(URL_TEXT);
  const data = new Uint8Array(deflateSync(predictUp(px, n)));
  const pdf = pdfWithImage(`<< /Subtype /Image /Width ${n} /Height ${n} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /DecodeParms << /Predictor 15 /Columns ${n} >> >>`, data);
  const auth = { mechanisms: { spf: { status: "pass" }, dkim: { status: "pass" }, dmarc: { status: "pass" } }, domainAlignment: { dmarcAligned: true, mismatches: [] }, trust: { warnings: [] }, anomalies: [] };
  const run = async (text) => {
    const body = { text, links: [], attachments: [{ filename: "n.pdf", contentType: "application/pdf", size: pdf.length, bytes: pdf }] };
    const iocs = extractIOCs({ from: { email: "a@b.test" } }, body);
    await inspectContainers(iocs, body);
    refreshIOCs(iocs);
    return calculateScore(auth, iocs, analyzeLanguage(body.text), {});
  };
  const quish = await run("Your MFA expires today. Scan the code with your phone.");
  assert.notEqual(quish.tier, "Low Risk");
  assert.ok(quish.attackTypes.includes("QR code phishing"));
  assert.match(quish.reasons[0], /QR code hides a link/);
  const ticket = await run("Here is your ticket for Saturday's concert.");
  assert.equal(ticket.tier, "Low Risk");
});

await test("an image that is not a QR code yields nothing", async () => {
  const noise = new Uint8ClampedArray(100 * 100 * 4).map((_, i) => (i % 4 === 3 ? 255 : (i * 7919) % 256));
  assert.equal(await decodeQr(noise, 100, 100), null);
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
