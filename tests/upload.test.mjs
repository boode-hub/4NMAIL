// Password-protected uploads: emails inside ZIPs, and the AES behind them.
// Run: node tests/upload.test.mjs
//
// The archives in tests/fixtures were made by 7-Zip, not by this code:
//   aes256.zip          AES-256, password "S3cret!", two emails
//   aes128-infected.zip AES-128, password "infected"
//   zipcrypto.zip       ZipCrypto, password "S3cret!"
//   plain.zip           no password
//   noemail.zip         a PDF and no email

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { emailsFromUpload } from "../scripts/upload.js";
import { expandKey, encryptBlock } from "../scripts/aes.js";
import { parseHeaders } from "../scripts/parse-headers.js";

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

const fixture = (name) => new File([readFileSync(new URL(`./fixtures/${name}`, import.meta.url))], name);
/** A stand-in for the password dialog: answers in turn, recording each call. */
function answers(...replies) {
  const calls = [];
  const ask = async (archive, wrongBefore) => {
    calls.push({ archive, wrongBefore });
    return replies.shift() ?? null;
  };
  return { ask, calls };
}
const noPrompt = async () => {
  throw new Error("asked for a password it should not need");
};

// ===== AES =====

await test("AES encrypts the FIPS-197 test vectors at every key size", () => {
  const hex = (s) => Uint8Array.from(s.match(/../g), (h) => parseInt(h, 16));
  const out = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  const pt = hex("00112233445566778899aabbccddeeff");
  const key = (n) => hex([...Array(n).keys()].map((i) => i.toString(16).padStart(2, "0")).join(""));
  assert.equal(out(encryptBlock(expandKey(key(16)), pt)), "69c4e0d86a7b0430d8cdb78070b4c55a");
  assert.equal(out(encryptBlock(expandKey(key(24)), pt)), "dda97ca4864cdfe06eaf70a0ec0d7191");
  assert.equal(out(encryptBlock(expandKey(key(32)), pt)), "8ea2b7ca516745bfeafc49904b496089");
});

// ===== uploads =====

await test("an AES-256 ZIP asks for its password, retries on a wrong one, and yields every email", async () => {
  const { ask, calls } = answers("wrong", "S3cret!");
  const emails = await emailsFromUpload(fixture("aes256.zip"), ask);
  assert.deepEqual(calls, [
    { archive: "aes256.zip", wrongBefore: false },
    { archive: "aes256.zip", wrongBefore: true },
  ]);
  assert.deepEqual(emails.map((e) => e.name).sort(), ["phishing-spoofed.eml", "second.eml"]);
  assert.ok(emails.every((e) => e.archive === "aes256.zip"));
  const spoofed = emails.find((e) => e.name === "phishing-spoofed.eml");
  assert.equal(parseHeaders(spoofed.text).from.email, "security@paypa1.com");
});

await test('"infected" is tried first, so the usual sample archive opens without a prompt', async () => {
  const emails = await emailsFromUpload(fixture("aes128-infected.zip"), noPrompt);
  assert.equal(emails.length, 1);
  assert.match(emails[0].text, /^From: security@paypa1\.com/);
});

await test("a ZipCrypto archive opens with its password", async () => {
  const emails = await emailsFromUpload(fixture("zipcrypto.zip"), answers("S3cret!").ask);
  assert.match(emails[0].text, /paypa1\.com/);
});

await test("cancelling the password prompt opens nothing", async () => {
  assert.deepEqual(await emailsFromUpload(fixture("aes256.zip"), answers(null).ask), []);
});

await test("an unprotected ZIP needs no password; a ZIP without emails says so", async () => {
  assert.equal((await emailsFromUpload(fixture("plain.zip"), noPrompt)).length, 1);
  await assert.rejects(emailsFromUpload(fixture("noemail.zip"), noPrompt), /no \.eml, \.msg or \.txt/);
});

await test("an ordinary email file passes straight through", async () => {
  const file = new File(["From: a@b.test\r\nSubject: hi\r\n\r\nbody"], "plain.eml");
  assert.deepEqual(await emailsFromUpload(file, noPrompt), [{ name: "plain.eml", text: "From: a@b.test\r\nSubject: hi\r\n\r\nbody" }]);
});

// ===== 7z (archives made by 7-Zip) =====
//   7z-pw-lzma2.7z   AES-256 + LZMA2, "S3cret!", three emails (one of 400 KB)
//   7z-pw-headers.7z the same with encrypted file names (-mhe=on)
//   7z-infected.7z   "infected", encrypted file names
//   7z-plain.7z / 7z-lzma.7z / 7z-copy.7z   no password; LZMA2, LZMA, stored

const lf = (s) => s.replace(/\r\n/g, "\n");
const SPOOFED = lf(readFileSync(new URL("../sample-data/phishing-spoofed.eml", import.meta.url), "utf8"));

await test("7z: AES-256 with LZMA2 asks for the password and extracts every email intact", async () => {
  const { ask, calls } = answers("nope", "S3cret!");
  const emails = await emailsFromUpload(fixture("7z-pw-lzma2.7z"), ask);
  assert.deepEqual(calls.map((c) => c.wrongBefore), [false, true]);
  assert.deepEqual(emails.map((e) => e.name).sort(), ["large-thread.eml", "legitimate-email.eml", "phishing-spoofed.eml"]);
  assert.equal(lf(emails.find((e) => e.name === "phishing-spoofed.eml").text), SPOOFED);
  const large = emails.find((e) => e.name === "large-thread.eml").text;
  assert.ok(large.length > 400000 && large.includes("-- part 100 "), "the 400 KB email decompresses fully");
});

await test("7z: encrypted file names, and the 'infected' convention, both open", async () => {
  const emails = await emailsFromUpload(fixture("7z-pw-headers.7z"), answers("S3cret!").ask);
  assert.deepEqual(emails.map((e) => e.name).sort(), ["legitimate-email.eml", "phishing-spoofed.eml"]);
  const infected = await emailsFromUpload(fixture("7z-infected.7z"), noPrompt);
  assert.equal(lf(infected[0].text), SPOOFED);
});

await test("7z: unprotected LZMA2, LZMA and stored archives need no password", async () => {
  for (const name of ["7z-plain.7z", "7z-lzma.7z", "7z-copy.7z"]) {
    const emails = await emailsFromUpload(fixture(name), noPrompt);
    assert.equal(lf(emails.find((e) => e.name === "phishing-spoofed.eml").text), SPOOFED, name);
  }
});

await test("7z: cancelling the prompt opens nothing", async () => {
  assert.deepEqual(await emailsFromUpload(fixture("7z-pw-headers.7z"), answers(null).ask), []);
});

await test("an archive inside an archive is opened too, and labelled with both names", async () => {
  const emails = await emailsFromUpload(fixture("nested-7z-in-zip.zip"), noPrompt);
  assert.equal(emails.length, 1);
  assert.equal(emails[0].archive, "nested-7z-in-zip.zip › infected.7z");
  assert.equal(lf(emails[0].text), SPOOFED);
});

await test("a gzip-compressed email is unpacked", async () => {
  const gz = gzipSync(Buffer.from("From: a@b.test\r\nSubject: zipped\r\n\r\nbody"));
  const emails = await emailsFromUpload(new File([gz], "mail.eml.gz"), noPrompt);
  assert.deepEqual(emails, [{ name: "mail.eml", text: "From: a@b.test\r\nSubject: zipped\r\n\r\nbody", archive: "mail.eml.gz" }]);
});

await test("binary that is not an email is refused with its name, never loaded as text", async () => {
  const rar = new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, 0, 0, 0]);
  await assert.rejects(emailsFromUpload(new File([rar], "PAYMENT.rar"), noPrompt), /RAR archive, which the browser cannot open/);
  const pdf = new Uint8Array([...new TextEncoder().encode("%PDF-1.7\n"), 0, 1, 2]);
  await assert.rejects(emailsFromUpload(new File([pdf], "doc.eml"), noPrompt), /doc\.eml is a PDF document, not an email/);
  await assert.rejects(emailsFromUpload(new File([new Uint8Array([1, 0, 2, 0])], "x.eml"), noPrompt), /binary data, not an email/);
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
