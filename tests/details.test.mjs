// Recipients, URL encoding descriptions and file details.
// Run: node tests/details.test.mjs

import assert from "node:assert/strict";
import { parseHeaders } from "../scripts/parse-headers.js";
import { recipientSummary, analyzeIdentity, setProtectedDomains } from "../scripts/analyze-identity.js";
import { classifyAttack } from "../scripts/score.js";
import { describeEncodings } from "../scripts/url-decode.js";
import { describeFile, entropy } from "../scripts/file-type.js";

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

const headers = (lines) => parseHeaders(`${lines.join("\r\n")}\r\nSubject: s\r\n\r\nbody`);

// ===== recipients =====

test("every To and Cc address is read, quoted commas and folded lines included", () => {
  const h = headers(['From: a@b.test', 'To: "Doe, Jane" <jane@contoso.com>, bob@contoso.com,', " carol@fabrikam.co.uk", "Cc: x@y.test, x@y.test", "Delivered-To: me@contoso.com"]);
  assert.deepEqual(h.recipients.to.map((a) => a.email), ["jane@contoso.com", "bob@contoso.com", "carol@fabrikam.co.uk"]);
  assert.equal(h.recipients.to[0].name, "Doe, Jane");
  assert.deepEqual(h.recipients.cc.map((a) => a.email), ["x@y.test"], "duplicates collapse");
  assert.equal(h.recipients.deliveredTo, "me@contoso.com");
  const r = recipientSummary(h);
  assert.deepEqual(r.domains, ["contoso.com", "fabrikam.co.uk", "y.test"]);
});

test("undisclosed and missing recipients are called out", () => {
  const undisclosed = recipientSummary(headers(["From: a@evil.test", "To: undisclosed-recipients:;", "Delivered-To: me@corp.test"]));
  assert.deepEqual(undisclosed.to, []);
  assert.match(undisclosed.notes[0].text, /Undisclosed recipients/);
  assert.equal(undisclosed.deliveredTo, "me@corp.test");
  assert.match(recipientSummary(headers(["From: a@evil.test"])).notes[0].text, /No visible recipient/);
});

test("a sending domain imitating the recipient's is high; real colleagues and webmail are not", () => {
  const level = (from, to) => recipientSummary(headers([`From: x@${from}`, `To: y@${to}`])).notes.map((n) => n.level);
  assert.deepEqual(level("c0ntoso.com", "contoso.com"), ["high"]);
  assert.deepEqual(level("contoso.co", "contoso.com"), ["high"]);
  assert.deepEqual(level("contoso.com", "contoso.com"), ["ok"]);
  assert.deepEqual(level("mail.contoso.com", "contoso.com"), ["ok"]);
  assert.deepEqual(level("gmail.com", "hotmail.com"), []);
  assert.deepEqual(level("fabrikam.com", "contoso.com"), []);
});

test("the recipient lookalike reaches the verdict once, and names the attack Impersonation", () => {
  const h = headers(["From: payroll@c0ntoso.com", "To: finance@contoso.com"]);
  const ids = analyzeIdentity(h).findings.map((f) => f.id);
  assert.ok(ids.includes("recipient-lookalike"), ids.join());
  assert.ok(classifyAttack({ mechanisms: {} }, { urls: [], attachments: [] }, null, analyzeIdentity(h)).includes("Impersonation"));
  setProtectedDomains(["contoso.com"]);
  try {
    const own = analyzeIdentity(h).findings.map((f) => f.id);
    assert.ok(!own.includes("recipient-lookalike"), "not repeated when your-domains already caught it");
  } finally {
    setProtectedDomains([]);
  }
  assert.ok(!analyzeIdentity(headers(["From: a@contoso.com", "To: b@contoso.com"])).findings.some((f) => f.id === "recipient-lookalike"));
});

test("mass mailings and a delivery address outside To/Cc are noted", () => {
  const many = Array.from({ length: 12 }, (_, i) => `u${i}@corp.test`).join(", ");
  assert.ok(recipientSummary(headers(["From: a@b.test", `To: ${many}`])).notes.some((n) => /12 recipients/.test(n.text)));
  assert.ok(recipientSummary(headers(["From: a@b.test", "To: list@corp.test", "Delivered-To: me@corp.test"])).notes.some((n) => /not in To or Cc/.test(n.text)));
});

// ===== URL encodings =====

test("each encoding in a URL is named, explained, and shows what it hides", () => {
  const wrapped =
    "https://nam12.safelinks.protection.outlook.com/?url=" +
    encodeURIComponent(`https://evil.test/verify#${Buffer.from("cfo@target.test").toString("base64")}`) +
    "&data=x";
  const found = describeEncodings(wrapped);
  const byId = Object.fromEntries(found.map((e) => [e.id, e]));
  assert.ok(byId.unwrap && /Safe Links/.test(byId.unwrap.found));
  assert.ok(byId.percent && /encoded character/.test(byId.percent.found));
  assert.ok(byId.base64 && /cfo@target\.test/.test(byId.base64.found));
  assert.match(byId.base64.found, /targeted recipient/);
  for (const e of found) assert.ok(e.name && e.what, e.id);
  assert.match(describeEncodings("https://xn--pypal-4ve.com/")[0].found, /Displays as/);
  assert.deepEqual(describeEncodings("https://example.com/plain/path"), []);
});

// ===== file details =====

test("file details see through a disguised program and read what is inside", () => {
  const pe = new Uint8Array(512);
  pe.set([0x4d, 0x5a]);
  const v = new DataView(pe.buffer);
  v.setUint32(0x3c, 0x80, true);
  v.setUint32(0x80, 0x4550, true);
  v.setUint16(0x84, 0x8664, true);
  v.setUint32(0x88, 1700000000, true);
  v.setUint16(0x96, 0x2000, true); // DLL
  pe.set(new TextEncoder().encode("beacon http://c2.evil.test/gate.php 203.0.113.5 admin@evil.test"), 200);
  const d = describeFile(pe, "Invoice.pdf", "application/pdf");
  assert.equal(d.detected, "Windows executable (PE)");
  assert.equal(d.nameCheck.ok, false);
  assert.match(d.nameCheck.text, /\.pdf" does not match/);
  assert.deepEqual([d.pe.arch, d.pe.kind, d.pe.built.toISOString()], ["x64 (64-bit)", "DLL (library)", "2023-11-14T22:13:20.000Z"]);
  assert.deepEqual(d.urls, ["http://c2.evil.test/gate.php"]);
  assert.deepEqual(d.ips, ["203.0.113.5"]);
  assert.deepEqual(d.emails, ["admin@evil.test"]);
  assert.equal(d.head.length, 64);
});

test("name checks and entropy read correctly", () => {
  const pdf = new TextEncoder().encode("%PDF-1.7 hello world hello world");
  assert.equal(describeFile(pdf, "a.pdf").nameCheck.ok, true);
  assert.equal(describeFile(pdf, "a").nameCheck.ok, false);
  assert.equal(describeFile(new TextEncoder().encode("just text"), "a.txt").nameCheck.ok, null);
  assert.equal(entropy(new Uint8Array(1000)), 0);
  const random = new Uint8Array(65536);
  for (let i = 0; i < random.length; i++) random[i] = (Math.imul(i, 2654435761) >>> 13) & 0xff;
  assert.ok(entropy(random) > 7.5);
  assert.match(describeFile(random, "x.bin").entropyNote, /compressed, encrypted or packed/);
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
