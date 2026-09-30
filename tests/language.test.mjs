// Language analysis tests.
// Run: node tests/language.test.mjs

import assert from "node:assert/strict";
import { analyzeLanguage } from "../scripts/analyze-language.js";
import { calculateScore } from "../scripts/score.js";

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

const found = (text, category) =>
  (analyzeLanguage(text).categories[category]?.matches || []).map((m) => m.phrase.toLowerCase());

const strongOf = (text, category) =>
  (analyzeLanguage(text).categories[category]?.matches || [])
    .filter((m) => m.tier === "strong")
    .map((m) => m.phrase.toLowerCase());

test("keywords match whole words, not fragments of ordinary words", () => {
  const benign =
    "Good morning, please find attached the first payment. Kindly confirm receipt at your earliest convenience. We define the terms swiftly as a courtesy, theirs and ours.";
  const r = analyzeLanguage(benign);
  for (const [cat, c] of Object.entries(r.categories)) {
    // Broad words ("payment", "kindly") are expected in ordinary mail; red flags are not.
    assert.equal(c.strongCount, 0, `${cat} flagged ${c.matches.filter((m) => m.tier === "strong").map((m) => m.phrase)} in ordinary text`);
    // And nothing is ever found inside a longer word.
    for (const m of c.matches) {
      assert.ok(!["irs", "court", "fine", "swift"].includes(m.phrase.toLowerCase()), `fragment matched: ${m.phrase}`);
    }
  }
});

test("the real words still match", () => {
  const authority = found("Notice from the IRS about a court date.", "authority");
  assert.ok(authority.includes("irs"), authority.join());
  assert.ok(authority.some((p) => p.startsWith("court")), authority.join());
  assert.ok(found("Send it by SWIFT today.", "financial").includes("swift"));
});

test("keywords with punctuation still match", () => {
  assert.ok(found("Please don't mention this to anyone.", "bec").includes("don't mention this"));
  assert.ok(found("Arrange a same-day payment.", "bec").some((p) => p.includes("same-day payment")));
});

test("invoice fraud: changed bank details are detected", () => {
  const text =
    "Please note our bank account has changed. Kindly use the updated bank details below for the overdue invoice and send proof of payment once you process the payment.";
  const hits = found(text, "bec");
  for (const phrase of [
    "our bank account has changed",
    "updated bank details",
    "overdue invoice",
    "proof of payment",
    "process the payment",
  ]) {
    assert.ok(hits.includes(phrase), `missed "${phrase}"; got ${hits}`);
  }
});

test("CEO fraud: availability, secrecy and gift-card requests are detected", () => {
  const text =
    "Are you available? I need a favor. I'm in a meeting and can't talk right now. Please purchase gift cards for the team and send me the codes. Keep this confidential.";
  const hits = found(text, "bec");
  for (const phrase of [
    "are you available",
    "i need a favor",
    "i'm in a meeting",
    "can't talk right now",
    "purchase gift cards",
    "send me the codes",
    "keep this confidential",
  ]) {
    assert.ok(hits.includes(phrase), `missed "${phrase}"; got ${hits}`);
  }
});

test("payroll diversion is detected", () => {
  assert.ok(found("I would like to update my direct deposit before the next payroll.", "bec").includes("update my direct deposit"));
});

test("BEC has its own label and appears in the score reasons", () => {
  const lang = analyzeLanguage("Please use the new bank details for this urgent payment.");
  assert.equal(lang.categories.bec.label, "BEC / Payment Fraud");
  const auth = {
    mechanisms: { spf: { status: "pass" }, dkim: { status: "pass" }, dmarc: { status: "pass" } },
    domainAlignment: { dmarcAligned: true, mismatches: [] },
    trust: { warnings: [] },
  };
  const s = calculateScore(auth, { urls: [], domains: [], ips: [], emails: [], attachments: [] }, lang);
  assert.ok(s.reasons.some((r) => /BEC \/ payment-fraud phrase/.test(r)), `reasons: ${s.reasons}`);
  assert.ok(s.breakdown.language > 0);
});

// ===== the expanded word lists =====

import { CATEGORIES } from "../scripts/keywords.js";

const cleanAuth = {
  mechanisms: { spf: { status: "pass" }, dkim: { status: "pass" }, dmarc: { status: "pass" } },
  domainAlignment: { dmarcAligned: true, mismatches: [] },
  trust: { warnings: [] },
  anomalies: [],
};
const noIocs = { urls: [], domains: [], ips: [], emails: [], attachments: [] };
const tokensOf = (t) => (t.match(/[\p{L}\p{N}]+(?:'[\p{L}]+)*/gu) || []).map((x) => x.toLowerCase()).join(" ");

test("every category has a comprehensive list in both tiers", () => {
  let total = 0;
  for (const [key, c] of Object.entries(CATEGORIES)) {
    assert.ok(c.strong.length >= 60, `${key} has only ${c.strong.length} strong terms`);
    assert.ok(c.broad.length >= 40, `${key} has only ${c.broad.length} broad terms`);
    total += c.strong.length + c.broad.length;
  }
  assert.ok(total >= 2000, `only ${total} terms in all`);
  for (const key of ["urgency", "authority", "financial", "credential", "bec", "lure", "advancefee", "social", "extortion"]) {
    assert.ok(CATEGORIES[key], `category missing: ${key}`);
  }
});

test("no term is a single everyday word, and none sits in both tiers", () => {
  const COMMON = new Set("the a an to us it i is on in of and or you your we our me my be do now today please help call message dear hi hello thanks".split(" "));
  for (const [key, c] of Object.entries(CATEGORIES)) {
    const strong = new Set(c.strong.map(tokensOf));
    for (const t of [...c.strong, ...c.broad]) {
      const tokens = tokensOf(t);
      assert.ok(tokens, `${key}: "${t}" has no words`);
      assert.ok(!COMMON.has(tokens), `${key}: "${t}" would match nearly every email`);
    }
    for (const t of c.broad) assert.ok(!strong.has(tokensOf(t)), `${key}: "${t}" is in both tiers`);
  }
});

test("money words are all found: VAT, fees, account numbers, amounts, wallets", () => {
  const text =
    "Invoice #4411: total $4,500.00 inc. VAT. A processing fee and customs duty apply. Pay by wire transfer to account number 12345678, sort code 20-00-00, IBAN GB29 NWBK 6016 1331 9268 19, or BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh. Gift cards accepted.";
  const words = found(text, "financial");
  for (const expected of ["invoice", "$4,500.00", "vat", "processing fee", "customs duty", "wire transfer", "account number", "sort code", "gb29 nwbk 6016 1331 9268 19", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "gift cards"]) {
    assert.ok(words.includes(expected), `missing "${expected}" in ${words.join(" | ")}`);
  }
});

test("phrases are found across line breaks, hyphens, curly quotes and plurals", () => {
  assert.ok(found("please send the\nwire\ntransfer today", "financial").includes("wire\ntransfer"));
  assert.ok(found("an urgent wire-transfer", "financial").includes("wire-transfer"));
  assert.ok(found("Don’t tell anyone about this", "bec").includes("don’t tell anyone"));
  assert.ok(found("The fees are waived", "financial").includes("fees"));
});

test("broad words are shown but never move the score", () => {
  const invoiceMail =
    "Hi team, attached is the invoice for March. The payment is due on the 30th; VAT and the service fee are itemised. Our bank account and account statement are unchanged. Kindly confirm receipt.";
  const lang = analyzeLanguage(invoiceMail);
  const broad = Object.values(lang.categories).reduce((n, c) => n + c.broadCount, 0);
  const strong = Object.values(lang.categories).reduce((n, c) => n + c.strongCount, 0);
  assert.ok(broad >= 8, `expected many broad terms, got ${broad}`);
  assert.equal(strong, 0, "ordinary invoice mail has no red flags");
  assert.equal(lang.totalScore, 0);
  const s = calculateScore(cleanAuth, noIocs, lang, {});
  assert.equal(s.breakdown.language, 0);
  assert.equal(s.tier, "Low Risk");
  assert.match(lang.summary, /^No suspicious phrases detected\. Also noted: \d+ broader/);
});

test("sextortion is recognised and floored at Suspicious", () => {
  const text =
    "I hacked your device and I recorded you through your webcam while you were watching adult websites. Transfer $1500 to my bitcoin address within 48 hours. You have 48 hours. Once I receive the payment I will delete the video. Don't go to the police.";
  const lang = analyzeLanguage(text);
  assert.ok(lang.categories.extortion.strongCount >= 3, lang.categories.extortion.matches.map((m) => m.phrase).join(" | "));
  const s = calculateScore(cleanAuth, noIocs, lang, {});
  assert.notEqual(s.tier, "Low Risk");
  assert.ok(s.caveats.some((c) => /extortion or sextortion/.test(c)));
});

test("an advance-fee letter is recognised and floored at Suspicious", () => {
  const text =
    "Dear Friend, I am Barrister James, attorney to my late client who died intestate. As next of kin you are the sole beneficiary of the sum of 10.5 million US dollars held by a diplomatic courier. Can I trust you? Kindly reconfirm the following and the fund will be released after the clearance certificate fee.";
  const lang = analyzeLanguage(text);
  assert.ok(lang.categories.advancefee.strongCount >= 3, lang.categories.advancefee.matches.map((m) => m.phrase).join(" | "));
  const s = calculateScore(cleanAuth, noIocs, lang, {});
  assert.notEqual(s.tier, "Low Risk");
  assert.ok(s.caveats.some((c) => /advance-fee/.test(c)));
});

test("lures, credential bait and social engineering are each found", () => {
  assert.ok(strongOf("Congratulations you have won! Claim your prize now, no strings attached.", "lure").length >= 2);
  assert.ok(strongOf("Your mailbox is full. Verify your account to release pending messages.", "credential").length >= 2);
  assert.ok(strongOf("Dear valued customer, if you did not authorize this charge call us immediately at +1 (888) 555-0199.", "social").length >= 2);
});

test("a security newsletter mentioning ransomware does not trip the extortion floor", () => {
  const text =
    "This month's security newsletter: ransomware groups keep targeting hospitals, spyware was found in a popular app, and blackmail scams are rising. Keep your software patched.";
  const lang = analyzeLanguage(text);
  assert.ok(lang.categories.extortion.broadCount >= 3);
  assert.equal(lang.categories.extortion.strongCount, 0);
  assert.equal(calculateScore(cleanAuth, noIocs, lang, {}).tier, "Low Risk");
});

test("the body highlighting marks strong and broad matches differently, and escapes the rest", () => {
  const html = analyzeLanguage("Pay the <b>invoice</b> by wire transfer & don't delay").highlightedText;
  assert.match(html, /<mark class="highlight-financial broad"[^>]*>invoice<\/mark>/);
  assert.match(html, /<mark class="highlight-financial"[^>]*>wire transfer<\/mark>/);
  assert.ok(html.includes("&lt;b&gt;") && html.includes("&amp;"), "text is escaped");
  assert.ok(!/<b>/.test(html), "no raw markup from the email");
});

test("a large message is analysed quickly", () => {
  const big = "Kindly remit the outstanding invoice by wire transfer within 24 hours or your account will be suspended. ".repeat(6000);
  const t = Date.now();
  analyzeLanguage(big);
  assert.ok(Date.now() - t < 5000, `took ${Date.now() - t} ms for ${(big.length / 1024).toFixed(0)} KB`);
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
