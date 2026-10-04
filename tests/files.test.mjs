// Saving files out of the analyzer: the protected ZIP, hex/Base64 decoding,
// and safe file names.
// Run: node tests/files.test.mjs

import assert from "node:assert/strict";
import { zipEncrypted, crc32, decodeToBytes, safeFilename, isExecutableName, ZIP_PASSWORD } from "../scripts/file-export.js";

let passed = 0;
const failures = [];
function test(name, fn) {
  try {
    fn();
    passed++;
  } catch (e) {
    failures.push({ name, message: e.message });
  }
}

// ===== an independent ZIP reader, written from the PKWARE specification =====

function crcByte(crc, b) {
  let c = (crc ^ b) & 0xff;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return (c ^ (crc >>> 8)) >>> 0;
}

function readZip(zip, password) {
  const v = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  assert.equal(v.getUint32(0, true), 0x04034b50, "local header signature");
  const flags = v.getUint16(6, true);
  const method = v.getUint16(8, true);
  const crc = v.getUint32(14, true);
  const csize = v.getUint32(18, true);
  const usize = v.getUint32(22, true);
  const nameLen = v.getUint16(26, true);
  const extraLen = v.getUint16(28, true);
  const name = new TextDecoder().decode(zip.slice(30, 30 + nameLen));
  const data = zip.slice(30 + nameLen + extraLen, 30 + nameLen + extraLen + csize);

  // End of central directory points at the central directory.
  const eocd = zip.length - 22;
  assert.equal(v.getUint32(eocd, true), 0x06054b50, "end-of-central-directory signature");
  const cdOffset = v.getUint32(eocd + 16, true);
  assert.equal(v.getUint32(cdOffset, true), 0x02014b50, "central directory signature");

  let k0 = 0x12345678, k1 = 0x23456789, k2 = 0x34567890;
  const update = (b) => {
    k0 = crcByte(k0, b);
    k1 = (Math.imul((k1 + (k0 & 0xff)) >>> 0, 134775813) + 1) >>> 0;
    k2 = crcByte(k2, k1 >>> 24);
  };
  for (const c of new TextEncoder().encode(password)) update(c);
  const plain = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    const t = (k2 | 2) & 0xffff;
    const p = data[i] ^ ((Math.imul(t, t ^ 1) >>> 8) & 0xff);
    plain[i] = p;
    update(p);
  }
  return { name, flags, method, crc, usize, headerCheck: plain[11], content: plain.slice(12) };
}

test("the ZIP is encrypted, stored, and decrypts to the exact bytes", () => {
  const original = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, ...Array.from({ length: 500 }, (_, i) => i & 0xff)]);
  const z = readZip(zipEncrypted("Invoice.pdf.exe", original), ZIP_PASSWORD);
  assert.equal(z.name, "Invoice.pdf.exe");
  assert.equal(z.flags & 1, 1, "encryption flag set");
  assert.equal(z.method, 0, "stored, not compressed");
  assert.equal(z.usize, original.length);
  assert.deepEqual([...z.content], [...original]);
  assert.equal(z.crc, crc32(original));
  assert.equal(z.headerCheck, z.crc >>> 24, "the password check byte matches");
});

test("the default password is the analysis convention, and a wrong one fails the check", () => {
  assert.equal(ZIP_PASSWORD, "infected");
  const zip = zipEncrypted("x.bin", new Uint8Array(64).fill(7));
  let wrongAccepted = 0;
  for (const pw of ["wrong", "Infected", "infected!", "password", "malware"]) {
    const z = readZip(zip, pw);
    if (z.headerCheck === z.crc >>> 24 && crc32(z.content) === z.crc) wrongAccepted++;
  }
  assert.equal(wrongAccepted, 0);
});

test("CRC-32 matches the standard check value", () => {
  assert.equal(crc32(new TextEncoder().encode("123456789")), 0xcbf43926);
});

test("non-ASCII file names survive", () => {
  assert.equal(readZip(zipEncrypted("Rechnung_März.pdf", new Uint8Array([1, 2, 3])), ZIP_PASSWORD).name, "Rechnung_März.pdf");
});

// ===== decoding =====

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

test("every common way of writing hex decodes to the same bytes", () => {
  for (const input of [
    "4d 5a 90 00",
    "4D5A9000",
    "0x4d,0x5a,0x90,0x00",
    "\\x4d\\x5a\\x90\\x00",
    "4d:5a:90:00",
    "4d-5a-90-00",
    "00000000  4d 5a 90 00                                       |MZ..|",
  ]) {
    const r = decodeToBytes(input);
    assert.ok(!r.error, `${input}: ${r.error}`);
    assert.equal(hex(r.bytes), "4d5a9000", input);
    assert.equal(r.mode, "hex", input);
  }
});

test("Base64 decodes with line breaks, without padding, as base64url and as a data: URI", () => {
  const expected = "4d5a90000300000004000000ffff0000";
  for (const input of ["TVqQAAMAAAAEAAAA//8AAA==", "TVqQAAMA\nAAAEAAAA\n//8AAA==", "TVqQAAMAAAAEAAAA__8AAA", "data:application/octet-stream;base64,TVqQAAMAAAAEAAAA//8AAA=="]) {
    const r = decodeToBytes(input);
    assert.ok(!r.error, `${input}: ${r.error}`);
    assert.equal(hex(r.bytes), expected, input);
  }
});

test("the mode can be forced, and bad input says what is wrong", () => {
  assert.equal(decodeToBytes("4d5a", "base64").mode, "base64", "4d5a is valid Base64 too");
  assert.match(decodeToBytes("4d5a9", "hex").error, /pairs/);
  assert.match(decodeToBytes("not hex at all ###").error, /neither hex nor valid Base64/);
  assert.match(decodeToBytes("   ").error, /Paste/);
});

// ===== names =====

test("file names lose paths and control characters", () => {
  assert.equal(safeFilename("../../evil.pdf"), "_.._evil.pdf");
  assert.equal(safeFilename("C:\\Windows\\a.txt"), "C__Windows_a.txt");
  assert.equal(safeFilename("in\u0000vo\u001fice.pdf"), "invoice.pdf");
  assert.equal(safeFilename(""), "file");
  assert.equal(safeFilename('a<b>c:"d|e?.txt'), "a_b_c__d_e_.txt");
});

test("a raw download never keeps an extension that runs on double-click", () => {
  assert.equal(safeFilename("Invoice.pdf.exe", { raw: true }), "Invoice.pdf.exe.bin");
  assert.equal(safeFilename("macro.docm", { raw: true }), "macro.docm.bin");
  assert.equal(safeFilename("disk.iso", { raw: true }), "disk.iso.bin");
  assert.equal(safeFilename("noextension", { raw: true }), "noextension.bin");
  assert.equal(safeFilename("photo.png", { raw: true }), "photo.png");
  assert.equal(isExecutableName("run.ps1"), true);
  assert.equal(isExecutableName("report.pdf"), false);
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
