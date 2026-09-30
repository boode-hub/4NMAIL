// Fabricated conversation threads (BEC trust trick).
// Run: node tests/thread.test.mjs

import assert from "node:assert/strict";
import { analyzeThread, parseClaimedDate, extractQuotedMessages, htmlToLines } from "../scripts/analyze-thread.js";
import { parseHeaders } from "../scripts/parse-headers.js";
import { parseAuth } from "../scripts/parse-auth.js";
import { parseBody } from "../scripts/parse-body.js";
import { extractIOCs } from "../scripts/extract-iocs.js";
import { analyzeLanguage } from "../scripts/analyze-language.js";
import { analyzeIdentity } from "../scripts/analyze-identity.js";
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

const msg = (lines) => lines.join("\r\n");
const run = (raw) => {
  const headers = parseHeaders(raw);
  const body = parseBody(raw);
  return { headers, body, thread: analyzeThread(headers, body) };
};
const ids = (raw) => run(raw).thread.findings.map((f) => f.id);

// 15 Jan 2024 was a Monday, 16 Jan a Tuesday, 18 Jan a Thursday.
const FAKE = msg([
  'From: "Sarah Collins" <sarah.collins@acrne-corp.com>',
  "To: ap@victim.test",
  "Subject: RE: Invoice INV-2291 - updated banking details",
  "Date: Thu, 18 Jan 2024 09:14:00 +0000",
  "Content-Type: text/plain",
  "",
  "Hi, following the approval below please process the payment today to our new bank account.",
  "",
  "From: Sarah Collins <sarah.collins@acme-corp.com>",
  "Sent: Monday, January 16, 2024 3:10 PM",
  "To: Mark Evans <mark.evans@victim.test>",
  "Subject: RE: Invoice INV-2291",
  "",
  "Mark, please note our bank details have changed; use the new account for INV-2291.",
  "",
  "From: Mark Evans <mark.evans@victim.test>",
  "Sent: Monday, January 15, 2024 11:02 AM",
  "To: Sarah Collins <sarah.collins@acme-corp.com>",
  "Subject: Invoice INV-2291",
  "",
  "Approved. Please send the invoice.",
]);

test("every quoted message in an Outlook-style thread is read", () => {
  const { thread } = run(FAKE);
  assert.equal(thread.messages.length, 2);
  assert.equal(thread.messages[0].from.email, "sarah.collins@acme-corp.com");
  assert.equal(thread.messages[1].subject, "Invoice INV-2291");
});

test("a fabricated thread is exposed from every angle", () => {
  const found = ids(FAKE);
  for (const id of ["thread-fake-reply", "thread-bad-date", "thread-impersonation", "thread-lookalike", "thread-payment"]) {
    assert.ok(found.includes(id), `missing ${id}: ${found}`);
  }
});

test("a fabricated thread sets the verdict to at least Suspicious, with the reason first", () => {
  const headers = parseHeaders(FAKE);
  const body = parseBody(FAKE);
  const identity = analyzeIdentity(headers);
  identity.findings.push(...analyzeThread(headers, body).findings);
  const auth = {
    mechanisms: { spf: { status: "pass" }, dkim: { status: "pass" }, dmarc: { status: "pass" } },
    domainAlignment: { dmarcAligned: true, mismatches: [] },
    trust: { warnings: [] },
    anomalies: [],
  };
  const s = calculateScore(auth, extractIOCs(headers, body), analyzeLanguage(body.text), headers, identity);
  assert.notEqual(s.tier, "Low Risk");
  assert.match(s.reasons[0], /quoted conversation looks fabricated/);
});

test("a genuine reply thread raises nothing", () => {
  const real = msg([
    "From: Sarah Collins <sarah.collins@acme-corp.com>",
    "To: mark.evans@victim.test",
    "Subject: RE: Invoice INV-2291",
    "Date: Wed, 17 Jan 2024 10:00:00 +0000",
    "In-Reply-To: <abc@victim.test>",
    "References: <abc@victim.test>",
    "Content-Type: text/plain",
    "",
    "Thanks Mark, invoice attached.",
    "",
    "From: Mark Evans <mark.evans@victim.test>",
    "Sent: Tuesday, January 16, 2024 3:10 PM",
    "To: Sarah Collins <sarah.collins@acme-corp.com>",
    "Subject: Invoice INV-2291",
    "",
    "Hi Sarah, could you send the invoice?",
  ]);
  assert.deepEqual(ids(real), []);
});

test("a forward is not accused of pasting a thread", () => {
  const fwd = msg([
    "From: Mark Evans <mark.evans@victim.test>",
    "To: sec@victim.test",
    "Subject: FW: Strange request",
    "Date: Wed, 17 Jan 2024 10:00:00 +0000",
    "Content-Type: text/plain",
    "",
    "Can you check this one?",
    "",
    "---------- Forwarded message ---------",
    "From: Someone <someone@elsewhere.test>",
    "Date: Tuesday, January 16, 2024 3:10 PM",
    "Subject: Strange request",
    "To: <mark.evans@victim.test>",
  ]);
  const found = ids(fwd);
  assert.ok(!found.includes("thread-pasted") && !found.includes("thread-fake-reply"), found.join());
});

test("Gmail and Thunderbird attribution lines are read, weekday included", () => {
  const { messages } = extractQuotedMessages(
    "Sounds good.\n\nOn Mon, Jan 15, 2024 at 9:02 AM John Smith <john@acme.com> wrote:\n> Can you confirm?",
  );
  assert.equal(messages.length, 1);
  assert.equal(messages[0].from.email, "john@acme.com");
  assert.equal(messages[0].from.name, "John Smith");
  const d = parseClaimedDate(messages[0].date);
  assert.equal(d.weekdayClaimed, d.weekdayActual, "15 Jan 2024 really was a Monday");
});

test("quoted headers inside HTML (Outlook divs and line breaks) are read", () => {
  const html =
    '<div><p>Please pay today.</p><div style="border-top:solid #E1E1E1 1.0pt"><p><b>From:</b> Sarah &lt;sarah@acme.com&gt;<br><b>Sent:</b> Tuesday, January 16, 2024 3:10 PM<br><b>To:</b> Mark<br><b>Subject:</b> RE: Invoice</p></div></div>';
  const { messages } = extractQuotedMessages(htmlToLines(html));
  assert.equal(messages.length, 1);
  assert.equal(messages[0].from.email, "sarah@acme.com");
  assert.equal(messages[0].subject, "RE: Invoice");
});

test("localized header labels are read", () => {
  const { messages } = extractQuotedMessages(
    "Merci\n\nDe : Paul Martin <paul@exemple.fr>\nEnvoyé : mardi 16 janvier 2024 15:10\nÀ : Marc\nObjet : Facture",
  );
  assert.equal(messages.length, 1);
  assert.equal(messages[0].subject, "Facture");
});

test("weekday checks are exact, and ambiguous dates are never judged", () => {
  assert.equal(parseClaimedDate("Monday, January 15, 2024 9:02 AM").weekdayActual, 1);
  const wrong = parseClaimedDate("Mon, 16 Jan 2024 10:00");
  assert.notEqual(wrong.weekdayClaimed, wrong.weekdayActual);
  assert.equal(parseClaimedDate("Mon 01/02/2024 10:00"), null, "01/02 could be January or February");
  assert.equal(parseClaimedDate("Thursday, February 30, 2024").valid, false);
});

test("a RE: subject with no reply headers is flagged even without a quote", () => {
  const found = run(
    msg(["From: a@b.test", "Subject: RE: Payment", "Date: Wed, 17 Jan 2024 10:00:00 +0000", "Content-Type: text/plain", "", "Please pay."]),
  ).thread.findings;
  assert.equal(found[0].id, "thread-fake-reply");
  assert.equal(found[0].severity, "medium");
});

test("a quoted message dated after the email itself is impossible", () => {
  const found = ids(
    msg([
      "From: a@acme.test",
      "Subject: Payment",
      "Date: Mon, 15 Jan 2024 10:00:00 +0000",
      "Content-Type: text/plain",
      "",
      "See below.",
      "",
      "From: b@acme.test",
      "Sent: Friday, January 19, 2024 3:10 PM",
      "To: a@acme.test",
      "Subject: Payment",
    ]),
  );
  assert.ok(found.includes("thread-future-date"), found.join());
});

test("quoted messages out of order are noticed", () => {
  const found = ids(
    msg([
      "From: a@acme.test",
      "Subject: RE: Payment",
      "In-Reply-To: <x@acme.test>",
      "Date: Mon, 22 Jan 2024 10:00:00 +0000",
      "Content-Type: text/plain",
      "",
      "From: b@acme.test",
      "Sent: Monday, January 15, 2024 3:10 PM",
      "To: a@acme.test",
      "Subject: RE: Payment",
      "",
      "From: a@acme.test",
      "Sent: Thursday, January 18, 2024 9:00 AM",
      "To: b@acme.test",
      "Subject: Payment",
    ]),
  );
  assert.ok(found.includes("thread-order"), found.join());
});

test("a sender absent from the conversation they continue is noticed", () => {
  const found = ids(
    msg([
      "From: finance@payments-desk.test",
      "Subject: Invoice follow-up",
      "Date: Mon, 22 Jan 2024 10:00:00 +0000",
      "Content-Type: text/plain",
      "",
      "As agreed below.",
      "",
      "From: Sarah <sarah@acme.test>",
      "Sent: Friday, January 19, 2024 3:10 PM",
      "To: Mark <mark@victim.test>",
      "Subject: Invoice",
      "",
      "From: Mark <mark@victim.test>",
      "Sent: Thursday, January 18, 2024 9:00 AM",
      "To: Sarah <sarah@acme.test>",
      "Subject: Invoice",
    ]),
  );
  assert.ok(found.includes("thread-outsider"), found.join());
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
