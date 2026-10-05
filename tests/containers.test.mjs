// Looking inside archives, Office documents, PDFs and RTF.
// Run: node tests/containers.test.mjs

import assert from "node:assert/strict";
import { deflateRawSync, deflateSync } from "node:zlib";
import { inspectContainers, findPasswords, readZipDirectory } from "../scripts/inspect-files.js";
import { extractIOCs, refreshIOCs } from "../scripts/extract-iocs.js";
import { calculateScore } from "../scripts/score.js";
import { parseBody } from "../scripts/parse-body.js";
import { zipEncrypted, crc32 } from "../scripts/file-export.js";

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

const enc = (s) => new TextEncoder().encode(s);
const PROGRAM = new Uint8Array([0x4d, 0x5a, 0x90, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0xff, 0xff]);

/** A plain multi-file ZIP; `deflate` compresses the entries. */
function zip(files, { deflate = false } = {}) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const bytes = typeof content === "string" ? enc(content) : content;
    const data = deflate ? new Uint8Array(deflateRawSync(bytes)) : bytes;
    const n = enc(name);
    const head = (size, sig) => {
      const v = new DataView(new ArrayBuffer(size));
      v.setUint32(0, sig, true);
      return v;
    };
    const l = head(30, 0x04034b50);
    l.setUint16(8, deflate ? 8 : 0, true);
    l.setUint32(14, crc32(bytes), true);
    l.setUint32(18, data.length, true);
    l.setUint32(22, bytes.length, true);
    l.setUint16(26, n.length, true);
    const c = head(46, 0x02014b50);
    c.setUint16(10, deflate ? 8 : 0, true);
    c.setUint32(16, crc32(bytes), true);
    c.setUint32(20, data.length, true);
    c.setUint32(24, bytes.length, true);
    c.setUint16(28, n.length, true);
    c.setUint32(42, offset, true);
    locals.push(new Uint8Array(l.buffer), n, data);
    centrals.push(new Uint8Array(c.buffer), n);
    offset += 30 + n.length + data.length;
  }
  const cdSize = centrals.reduce((s, p) => s + p.length, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(8, centrals.length / 2, true);
  end.setUint16(10, centrals.length / 2, true);
  end.setUint32(12, cdSize, true);
  end.setUint32(16, offset, true);
  const parts = [...locals, ...centrals, new Uint8Array(end.buffer)];
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

const cleanAuth = {
  mechanisms: { spf: { status: "pass" }, dkim: { status: "pass" }, dmarc: { status: "pass" } },
  domainAlignment: { dmarcAligned: true, mismatches: [] },
  trust: { warnings: [] },
  anomalies: [],
};

/** The same steps the app runs: extract, look inside, refresh. */
async function analyse(files, text = "") {
  const body = {
    text,
    links: [],
    attachments: Object.entries(files).map(([filename, bytes]) => ({ filename, contentType: "application/octet-stream", size: bytes.length, bytes })),
  };
  const iocs = extractIOCs({ from: { email: "a@b.test" } }, body);
  await inspectContainers(iocs, body);
  refreshIOCs(iocs);
  return iocs;
}
const risks = (att) => (att.risks || []).map((r) => r.type);
const find = (iocs, name) => iocs.attachments.find((a) => a.value === name);

// ===== passwords =====

await test("passwords written in the email are found; ordinary password talk is not", () => {
  assert.deepEqual(findPasswords("The password is: 7731"), ["7731"]);
  assert.deepEqual(findPasswords("Archive pwd - Inv2024!"), ["Inv2024"]);
  assert.deepEqual(findPasswords('Use password "Qx9#2" to open'), ["Qx9#2"]);
  assert.deepEqual(findPasswords("Kennwort: abc123"), ["abc123"]);
  assert.deepEqual(findPasswords("Your password expires soon. Password reset required."), []);
});

// ===== archives =====

await test("a ZIP's contents are listed, extracted, and a program inside is decisive", async () => {
  for (const deflate of [false, true]) {
    const iocs = await analyse({ "docs.zip": zip({ "readme.txt": "hello", "invoice.pdf.exe": PROGRAM }, { deflate }) });
    const archive = find(iocs, "docs.zip");
    assert.deepEqual(archive.containerInfo.entries, ["readme.txt", "invoice.pdf.exe"]);
    assert.ok(risks(archive).includes("archive-executable"), `deflate=${deflate}`);
    const inner = find(iocs, "invoice.pdf.exe");
    assert.ok(inner, "the program was extracted");
    assert.equal(inner.embeddedIn, "docs.zip");
    assert.ok(risks(inner).includes("executable-content"), "the extracted bytes are checked like any attachment");
    assert.equal(calculateScore(cleanAuth, iocs, null, {}).tier, "High Risk");
  }
});

await test("a password-protected ZIP is opened with the password from the email", async () => {
  const iocs = await analyse({ "scan.zip": zipEncrypted("scan.exe", PROGRAM, "7731") }, "Please open the attached scan. The password is 7731.");
  const archive = find(iocs, "scan.zip");
  assert.ok(risks(archive).includes("archive-password"));
  assert.match(archive.containerInfo.notes.join(), /Opened with the password "7731"/);
  assert.ok(risks(find(iocs, "scan.exe")).includes("executable-content"));
  const score = calculateScore(cleanAuth, iocs, null, {});
  assert.equal(score.tier, "High Risk");
});

await test("a ZIP with an unknown password is flagged, not opened", async () => {
  const iocs = await analyse({ "x.zip": zipEncrypted("x.exe", PROGRAM, "unguessable-9") });
  const archive = find(iocs, "x.zip");
  assert.ok(risks(archive).includes("archive-encrypted"));
  assert.ok(risks(archive).includes("archive-executable"), "the name inside is still visible");
  assert.equal(find(iocs, "x.exe"), undefined);
});

await test("archives inside archives are opened too, and flagged", async () => {
  const inner = zip({ "run.js": "WScript.Shell" });
  const iocs = await analyse({ "outer.zip": zip({ "inner.zip": inner }) });
  assert.ok(risks(find(iocs, "outer.zip")).includes("nested-archive"));
  assert.ok(risks(find(iocs, "inner.zip")).includes("archive-executable"));
  assert.ok(find(iocs, "run.js"), "second level extracted");
});

await test("a corrupt archive does not stop the analysis", async () => {
  const broken = zip({ "a.txt": "hello" }).slice(0, 40);
  const iocs = await analyse({ "broken.zip": broken, "ok.zip": zip({ "b.txt": "fine" }) });
  assert.equal(readZipDirectory(broken), null);
  assert.deepEqual(find(iocs, "ok.zip").containerInfo.entries, ["b.txt"]);
});

// ===== Office =====

const CT = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>';

await test("Office macros, remote templates and external links are found", async () => {
  const docx = zip(
    {
      "[Content_Types].xml": CT,
      "word/document.xml": "<w:document><w:t>Enable content</w:t></w:document>",
      "word/vbaProject.bin": PROGRAM,
      "word/_rels/settings.xml.rels":
        '<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil.test/t.dotm" TargetMode="External"/></Relationships>',
    },
    { deflate: true },
  );
  const iocs = await analyse({ "invoice.docx": docx });
  const doc = find(iocs, "invoice.docx");
  assert.ok(risks(doc).includes("macros"));
  assert.ok(risks(doc).includes("remote-template"));
  assert.ok(iocs.urls.some((u) => u.value === "http://evil.test/t.dotm" && /Inside invoice\.docx/.test(u.source)));
  assert.ok(iocs.domains.some((d) => d.value === "evil.test"), "the template host becomes a domain IOC");
  const s = calculateScore(cleanAuth, iocs, null, {});
  assert.equal(s.tier, "High Risk");
  assert.ok(s.attackTypes.includes("Malware delivery"));
});

await test("a DDE field is decisive", async () => {
  const docx = zip({ "[Content_Types].xml": CT, "word/document.xml": '<w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc"</w:instrText>' });
  const iocs = await analyse({ "q.docx": docx });
  assert.ok(risks(find(iocs, "q.docx")).includes("dde"));
});

await test("an ordinary document raises nothing", async () => {
  const docx = zip({
    "[Content_Types].xml": CT,
    "word/document.xml": "<w:document><w:t>Minutes</w:t></w:document>",
    "word/_rels/document.xml.rels": '<Relationships><Relationship Id="r1" Type="http://x/styles" Target="styles.xml"/></Relationships>',
  });
  const iocs = await analyse({ "minutes.docx": docx });
  const doc = find(iocs, "minutes.docx");
  assert.deepEqual(doc.containerFindings, []);
  assert.equal(doc.risky, false);
  assert.equal(doc.containerInfo.kind, "Office document");
});

await test("legacy Office macros are found; Outlook .msg files are left alone", async () => {
  const utf16 = (s) => enc(s.split("").join("\0"));
  const ole = new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, ...utf16("_VBA_PROJECT"), ...enc("Sub AutoOpen()")]);
  const iocs = await analyse({ "old.doc": ole, "mail.msg": ole });
  assert.ok(risks(find(iocs, "old.doc")).includes("macros"));
  assert.ok(risks(find(iocs, "old.doc")).includes("macro-autorun"));
  assert.equal(find(iocs, "mail.msg").containerInfo, undefined);
});

// ===== PDF and RTF =====

function pdf(objects) {
  const parts = ["%PDF-1.7\n"];
  objects.forEach((o, i) => parts.push(`${i + 1} 0 obj\n`, o, "\nendobj\n"));
  parts.push("%%EOF\n");
  const chunks = parts.map((p) => (typeof p === "string" ? enc(p) : p));
  const out = new Uint8Array(chunks.reduce((s, c) => s + c.length, 0));
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

await test("PDF scripts, actions and links — including compressed and escaped ones — are found", async () => {
  const hidden = new Uint8Array(deflateSync(enc("<< /A << /S /URI /URI (https://hidden.test/login) >> >>")));
  const file = pdf([
    "<< /Type /Catalog /OpenAction 2 0 R >>",
    "<< /S /J#61vaScript /JS (app.alert(1)) >>",
    "<< /A << /S /URI /URI (http://plain.test/a) >> >>",
    "<< /A << /S /URI /URI <68747470733a2f2f6865782e746573742f> >> >>",
    new Uint8Array([...enc(`<< /Length ${hidden.length} /Filter /FlateDecode >>\nstream\n`), ...hidden, ...enc("\nendstream")]),
  ]);
  const iocs = await analyse({ "statement.pdf": file });
  const doc = find(iocs, "statement.pdf");
  assert.ok(risks(doc).includes("pdf-javascript"), "an escaped /JavaScript name is still found");
  assert.ok(risks(doc).includes("pdf-autoaction"));
  const urls = iocs.urls.map((u) => u.value);
  for (const u of ["http://plain.test/a", "https://hex.test/", "https://hidden.test/login"]) assert.ok(urls.includes(u), `${u} in ${urls}`);
  assert.equal(calculateScore(cleanAuth, iocs, null, {}).tier !== "Low Risk", true);
});

await test("a PDF launch action is decisive, even with junk before the header", async () => {
  const file = new Uint8Array([...enc("junkjunk\n"), ...pdf(["<< /OpenAction << /S /Launch /F (cmd.exe) >> >>"])]);
  const iocs = await analyse({ "a.pdf": file });
  assert.ok(risks(find(iocs, "a.pdf")).includes("pdf-launch"));
  assert.equal(calculateScore(cleanAuth, iocs, null, {}).tier, "High Risk");
});

await test("an RTF Equation Editor object is decisive; links in RTF are collected", async () => {
  const rtf = enc('{\\rtf1{\\object\\objemb\\objupdate{\\*\\objclass Equation.3}{\\*\\objdata 0105}}{\\field{\\*\\fldinst HYPERLINK "http://rtf.test/x"}}}');
  const iocs = await analyse({ "order.rtf": rtf });
  const doc = find(iocs, "order.rtf");
  assert.ok(risks(doc).includes("rtf-equation"));
  assert.ok(risks(doc).includes("rtf-objupdate"));
  assert.ok(iocs.urls.some((u) => u.value === "http://rtf.test/x"));
  assert.equal(calculateScore(cleanAuth, iocs, null, {}).tier, "High Risk");
});

// ===== calendar invites =====

await test("a calendar invite's folded, escaped links are found and its description is read", async () => {
  const ics = [
    "BEGIN:VCALENDAR",
    "METHOD:REQUEST",
    "BEGIN:VEVENT",
    "ORGANIZER;CN=IT Support:mailto:it@helpdesk.test",
    "SUMMARY:Mandatory password reset",
    "DTSTART:20261006T090000Z",
    "DESCRIPTION:Your account will be suspended. Verify now at https://login.micro",
    " soft-verify.test/reset?u=1\\, before noon.\\nThanks",
    "LOCATION:https://meet.evil.test/join",
    "END:VEVENT",
    "END:VCALENDAR",
  ].join("\r\n");
  const raw = `From: a@b.test\r\nSubject: Invite\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary="X"\r\n\r\n--X\r\nContent-Type: text/plain\r\n\r\nYou have been invited.\r\n--X\r\nContent-Type: text/calendar; method=REQUEST\r\n\r\n${ics}\r\n--X--\r\n`;
  const body = parseBody(raw);
  const iocs = extractIOCs({ from: { email: "a@b.test" } }, body);
  await inspectContainers(iocs, body);
  refreshIOCs(iocs);
  const invite = find(iocs, "invite.ics");
  assert.ok(invite, "the invite is listed as a file");
  assert.ok(risks(invite).includes("calendar-links"));
  const urls = iocs.urls.map((u) => u.value);
  assert.ok(urls.includes("https://login.microsoft-verify.test/reset?u=1"), urls.join(" "));
  assert.ok(urls.includes("https://meet.evil.test/join"));
  assert.ok(invite.containerInfo.entries.includes("Organizer: it@helpdesk.test"));
  assert.match(body.text, /Your account will be suspended/, "the description reaches the language checks");
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
