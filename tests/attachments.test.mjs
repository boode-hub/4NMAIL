// Attachment extraction and hashing tests.
// Run: node tests/attachments.test.mjs
//
// The hashes here are checked against node:crypto, not against a value this
// codebase produced. A self-consistent wrong hash is exactly the failure mode
// that made VirusTotal file lookups useless.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { parseBody } from "../scripts/parse-body.js";
import { sha256Bytes, md5Bytes } from "../scripts/hash-utils.js";

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

// A payload that deliberately contains bytes above 0x7F — the range that the
// old string-based hashing silently corrupted via UTF-8 re-encoding.
const payload = new Uint8Array(512);
for (let i = 0; i < payload.length; i++) payload[i] = (i * 7 + 13) % 256;
const payloadB64 = Buffer.from(payload).toString("base64");
const trueSha = createHash("sha256").update(payload).digest("hex");
const trueMd5 = createHash("md5").update(payload).digest("hex");

// A real 1x1 PNG, so at least one case is a genuine image file.
const pngB64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
const pngBytes = new Uint8Array(Buffer.from(pngB64, "base64"));
const pngSha = createHash("sha256").update(pngBytes).digest("hex");

const wrap = (body) => `From: sender@example.com
To: victim@example.com
Subject: test
${body}`;

await test("binary attachment bytes survive decoding intact", async () => {
  const eml = wrap(`Content-Type: multipart/mixed; boundary="B1"

--B1
Content-Type: text/plain

hello
--B1
Content-Type: application/octet-stream; name="payload.bin"
Content-Disposition: attachment; filename="payload.bin"
Content-Transfer-Encoding: base64

${payloadB64}
--B1--`);
  const body = parseBody(eml);
  assert.equal(body.attachments.length, 1);
  const att = body.attachments[0];
  assert.equal(att.filename, "payload.bin");
  assert.equal(att.size, payload.length, "size must be byte length");
  assert.deepEqual([...att.bytes], [...payload], "bytes must round-trip");
});

await test("SHA-256 and MD5 match node:crypto for a binary attachment", async () => {
  const eml = wrap(`Content-Type: multipart/mixed; boundary="B1"

--B1
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="payload.bin"
Content-Transfer-Encoding: base64

${payloadB64}
--B1--`);
  const att = parseBody(eml).attachments[0];
  assert.equal(await sha256Bytes(att.bytes), trueSha, "SHA-256 mismatch");
  assert.equal(md5Bytes(att.bytes), trueMd5, "MD5 mismatch");
});

await test("a real PNG hashes correctly", async () => {
  const eml = wrap(`Content-Type: multipart/mixed; boundary="B1"

--B1
Content-Type: image/png; name="logo.png"
Content-Disposition: attachment; filename="logo.png"
Content-Transfer-Encoding: base64

${pngB64}
--B1--`);
  const att = parseBody(eml).attachments[0];
  assert.equal(att.contentType, "image/png");
  assert.equal(await sha256Bytes(att.bytes), pngSha);
});

await test("inline images with a Content-ID are collected, not skipped", async () => {
  const eml = wrap(`Content-Type: multipart/related; boundary="B1"

--B1
Content-Type: text/html

<html><body><img src="cid:pixel1"></body></html>
--B1
Content-Type: image/gif
Content-Disposition: inline
Content-ID: <pixel1>
Content-Transfer-Encoding: base64

${pngB64}
--B1--`);
  const body = parseBody(eml);
  assert.equal(
    body.attachments.length,
    1,
    "inline image was previously dropped entirely",
  );
  assert.equal(body.attachments[0].inline, true);
  assert.equal(body.attachments[0].contentId, "pixel1");
});

await test("nested multipart/mixed > multipart/alternative is traversed", async () => {
  const eml = wrap(`Content-Type: multipart/mixed; boundary="OUTER"

--OUTER
Content-Type: multipart/alternative; boundary="INNER"

--INNER
Content-Type: text/plain

plain version
--INNER
Content-Type: text/html

<p>html version with <a href="https://evil.test/x">a link</a></p>
--INNER--
--OUTER
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

${payloadB64}
--OUTER--`);
  const body = parseBody(eml);
  assert.match(body.text, /plain version/, "inner text part must be found");
  assert.match(body.html, /html version/, "inner html part must be found");
  assert.equal(body.attachments.length, 1);
  assert.equal(body.attachments[0].filename, "invoice.pdf");
  assert.equal(body.links.length, 1, "links inside nested parts must be found");
});

await test("quoted-printable attachments decode to the right bytes", async () => {
  const eml = wrap(`Content-Type: multipart/mixed; boundary="B1"

--B1
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="qp.bin"
Content-Transfer-Encoding: quoted-printable

=00=01=FF=80hello
--B1--`);
  const att = parseBody(eml).attachments[0];
  const expected = [0x00, 0x01, 0xff, 0x80, ...Buffer.from("hello")];
  assert.deepEqual([...att.bytes].slice(0, expected.length), expected);
});

await test("RFC 2047 encoded filenames are decoded", async () => {
  const eml = wrap(`Content-Type: multipart/mixed; boundary="B1"

--B1
Content-Type: application/pdf
Content-Disposition: attachment; filename="=?utf-8?B?${Buffer.from("factura-año.pdf").toString("base64")}?="
Content-Transfer-Encoding: base64

${payloadB64}
--B1--`);
  const att = parseBody(eml).attachments[0];
  assert.equal(att.filename, "factura-año.pdf");
});

await test("an HTML-only message still yields plain text for language analysis", async () => {
  const eml = wrap(`Content-Type: text/html

<html><body><p>Act now, your account will be suspended.</p></body></html>`);
  const body = parseBody(eml);
  assert.match(body.text, /Act now/, "HTML-only mail must still produce text");
});

await test("a message with no attachments reports none", async () => {
  const body = parseBody(wrap(`Content-Type: text/plain

just text`));
  assert.equal(body.attachments.length, 0);
  assert.match(body.text, /just text/);
});

// ===== text encodings =====

await test("unencoded UTF-8 text survives: dashes, smart quotes, Arabic, Cyrillic, CJK, emoji, accents", () => {
  const text = "Urgent — ’quotes’ مرحبا Привет 你好 😀 café naïve";
  // Pasted, or read from a file as UTF-8: the browser has already decoded it.
  const pasted = parseBody(`From: a@b.test\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${text}`);
  assert.equal(pasted.text.trim(), text);
  // No charset declared.
  assert.equal(parseBody(`From: a@b.test\r\nContent-Type: text/plain\r\n\r\ncafé — naïve`).text.trim(), "café — naïve");
  // HTML parts too.
  assert.match(parseBody(`From: a@b.test\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>${text}</p>`).html, /مرحبا Привет 你好 😀/);
  // Raw characters inside quoted-printable.
  assert.equal(parseBody("From: a@b.test\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=C3=A9 — ok").text.trim(), "café — ok");
});

await test("byte strings and declared charsets still decode as before", () => {
  const bytes = Buffer.from("café — 你好").toString("latin1");
  assert.equal(parseBody(`From: a@b.test\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${bytes}`).text.trim(), "café — 你好");
  assert.equal(parseBody("From: a@b.test\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\ncafé").text.trim(), "café");
  // A binary part sent unencoded keeps its exact bytes.
  const bin = String.fromCharCode(0x89, 0x50, 0x4e, 0x47, 0xff, 0x00, 0xc3);
  const att = parseBody(`From: a@b.test\r\nContent-Type: multipart/mixed; boundary="B"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename="x.png"\r\nContent-Transfer-Encoding: binary\r\n\r\n${bin}\r\n--B--\r\n`).attachments[0];
  assert.deepEqual([...att.bytes], [0x89, 0x50, 0x4e, 0x47, 0xff, 0x00, 0xc3]);
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
