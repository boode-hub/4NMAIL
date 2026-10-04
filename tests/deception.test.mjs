// Your own domains, Unicode tricks, and the attack-type line.
// Run: node tests/deception.test.mjs

import assert from "node:assert/strict";
import { setProtectedDomains, parseDomainList, lookalikeOf, analyzeIdentity, protectedDomains } from "../scripts/analyze-identity.js";
import { analyzeUnicode, revealControls, stripControls, mixedScriptWords, invisibleInWords } from "../scripts/analyze-unicode.js";
import { extractIOCs } from "../scripts/extract-iocs.js";
import { calculateScore, classifyAttack } from "../scripts/score.js";
import { analyzeLanguage } from "../scripts/analyze-language.js";

let passed = 0;
const failures = [];
function test(name, fn) {
  try {
    fn();
    passed++;
  } catch (e) {
    failures.push({ name, message: e.message });
  } finally {
    setProtectedDomains([]); // never leak into the next test
  }
}

const cleanAuth = {
  mechanisms: { spf: { status: "pass" }, dkim: { status: "pass" }, dmarc: { status: "pass" } },
  domainAlignment: { dmarcAligned: true, mismatches: [] },
  trust: { warnings: [] },
  anomalies: [],
};
const noIocs = { urls: [], domains: [], ips: [], emails: [], attachments: [] };

// ===== your own domains =====

test("the domain list accepts any number, in any common form, and names what it ignored", () => {
  const { valid, invalid } = parseDomainList("https://www.Contoso.com/login\nfabrikam.co.uk, ceo@northwind.io;  not-a-domain");
  assert.deepEqual(valid, ["contoso.com", "fabrikam.co.uk", "northwind.io"]);
  assert.deepEqual(invalid, ["not-a-domain"]);
  assert.deepEqual(parseDomainList("").valid, []);
});

test("lookalikes of your domains are caught in every shape", () => {
  setProtectedDomains(["contoso.com", "fabrikam.co.uk"]);
  assert.deepEqual(protectedDomains(), ["contoso.com", "fabrikam.co.uk"]);
  const kind = (h) => lookalikeOf(h)?.kind;
  assert.equal(kind("c0ntoso.com"), "confusable");
  assert.equal(kind("contosso.com"), "typosquat");
  assert.equal(kind("contoso.co"), "tld-swap");
  assert.equal(kind("contoso-payroll.com"), "contains");
  assert.equal(kind("fabrikam.com"), "tld-swap");
  assert.equal(lookalikeOf("c0ntoso.com").own, true);
});

test("your own domains and their subdomains are never flagged", () => {
  setProtectedDomains(["contoso.com", "fabrikam.co.uk"]);
  for (const h of ["contoso.com", "mail.contoso.com", "fabrikam.co.uk", "hr.fabrikam.co.uk", "example.com"]) {
    assert.equal(lookalikeOf(h), null, h);
  }
});

test("with no domains set, the feature is off", () => {
  setProtectedDomains([]);
  assert.equal(lookalikeOf("c0ntoso.com"), null);
  assert.deepEqual(analyzeIdentity({ from: { email: "ceo@c0ntoso.com", name: "Contoso CEO" } }).findings, []);
});

test("impersonating your organisation is a high finding, worded as yours", () => {
  setProtectedDomains(["contoso.com"]);
  const findings = analyzeIdentity({
    from: { email: "ceo@c0ntoso.com", name: "Contoso CEO" },
  }).findings;
  const titles = findings.map((f) => f.title);
  assert.ok(titles.includes("The sending domain imitates your organization's domain"), titles.join(" | "));
  assert.ok(titles.some((t) => /your organization \(contoso\)/.test(t)), titles.join(" | "));
  assert.ok(findings.every((f) => f.severity === "high"));
});

test("a Reply-To on a lookalike of your domain is caught even when From is clean", () => {
  setProtectedDomains(["contoso.com"]);
  const ids = analyzeIdentity({ from: { email: "someone@gmail.com" }, replyTo: { email: "payroll@contoso-hr.com" } }).findings.map((f) => f.id);
  assert.ok(ids.includes("own-lookalike-replyto"), ids.join());
});

test("links to a lookalike of your domain are flagged", () => {
  setProtectedDomains(["contoso.com"]);
  const iocs = extractIOCs({ from: { email: "a@b.test" } }, { text: "Sign in at https://login.c0ntoso.com/sso", links: [], attachments: [] });
  const labels = iocs.urls[0].riskFlags.map((f) => f.label);
  assert.ok(labels.includes("Imitates your domain"), labels.join());
});

// ===== Unicode tricks =====

test("a right-to-left override in a file name is revealed, flagged, and decisive", () => {
  const name = "invoice‮fdp.exe";
  assert.equal(revealControls(name), "invoice[U+202E RLO]fdp.exe");
  assert.equal(stripControls(name), "invoicefdp.exe");
  const iocs = extractIOCs({}, { text: "", links: [], attachments: [{ filename: name, contentType: "application/pdf", size: 3, bytes: new Uint8Array([1, 2, 3]) }] });
  const att = iocs.attachments[0];
  assert.ok(att.riskFlags.some((f) => f.label === "Hidden extension (RTLO)"));
  assert.ok(att.riskFlags.some((f) => f.label === "Risky: .exe"), "the real extension is judged, not the displayed one");
  const s = calculateScore(cleanAuth, iocs, null, {});
  assert.equal(s.tier, "High Risk");
  assert.match(s.reasons[0], /hides its real extension/);
});

test("invisible characters only count inside words", () => {
  assert.deepEqual(invisibleInWords("Pa​ypal veri‍fy"), ["a​y", "i‍f"]);
  assert.deepEqual(invisibleInWords("preheader ‌ ‌  padding"), []);
});

test("mixed alphabets inside one word are found; a fully foreign word is not", () => {
  assert.deepEqual(mixedScriptWords("Your Pаypal account").map((m) => m.word), ["Pаypal"]);
  assert.deepEqual(mixedScriptWords("Привет мир, hello world"), []);
});

test("Unicode tricks in the subject and sender name are reported", () => {
  const ids = analyzeUnicode(
    { subject: "Urgent: Pаypal notice‮", from: { name: "Micro​soft" } },
    { text: "" },
    [],
  ).map((f) => f.id);
  assert.ok(ids.includes("unicode-mixed-script"));
  assert.ok(ids.includes("unicode-bidi"));
  assert.ok(ids.includes("unicode-invisible"));
});

test("ordinary mail raises no Unicode findings", () => {
  assert.deepEqual(
    analyzeUnicode({ subject: "Team lunch on Friday", from: { name: "José Müller" } }, { text: "See you there ‌ ‌ — café at noon." }, [{ value: "menu.pdf" }]),
    [],
  );
});

// ===== attack type =====

test("the attack type names what the signals add up to", () => {
  const lang = analyzeLanguage("I'm currently in a meeting. Please process a wire transfer today. Account: 12345678. Do not delay.");
  assert.ok(classifyAttack(cleanAuth, noIocs, lang, { findings: [] }).includes("BEC / payment fraud"));

  const phishLang = analyzeLanguage("Verify your account now or it will be suspended.");
  const iocs = { ...noIocs, urls: [{ value: "https://evil.test/login", risks: [] }] };
  assert.ok(classifyAttack(cleanAuth, iocs, phishLang, { findings: [] }).includes("Credential phishing"));

  const spoofAuth = { ...cleanAuth, mechanisms: { ...cleanAuth.mechanisms, dmarc: { status: "fail" } } };
  assert.ok(classifyAttack(spoofAuth, noIocs, null, { findings: [] }).includes("Sender spoofing"));

  const callback = analyzeLanguage("Your subscription renewed for $499. If you did not authorize this charge call us at +1 (888) 555-0199.");
  assert.ok(classifyAttack(cleanAuth, noIocs, callback, { findings: [] }).includes("Callback phishing"));
});

test("an ordinary message has no attack type", () => {
  const lang = analyzeLanguage("Hi team, lunch is at noon on Friday. See you there.");
  assert.deepEqual(classifyAttack(cleanAuth, noIocs, lang, { findings: [] }), []);
  assert.deepEqual(calculateScore(cleanAuth, noIocs, lang, {}).attackTypes, []);
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
