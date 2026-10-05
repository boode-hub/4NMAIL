// Looking inside attachments: archives, Office documents, PDFs and RTF.
//
// Most malware and credential phishing now arrives as a "document": a Word file
// whose macro or remote template fetches the payload, a PDF whose link or
// script is the real attack, a password-protected ZIP that mail gateways cannot
// open — with the password helpfully written in the email. Hashing such a file
// says nothing about any of that. Everything here is read, never run:
//
//  - ZIP: list the contents, flag programs and nested archives, notice
//    encryption, and — when the password is in the email — open it with that
//    password and inspect what is inside;
//  - Office (docx/xlsx/pptx and macro-enabled variants): macros, remote
//    templates (template injection), external links, DDE commands, ActiveX,
//    embedded objects; legacy .doc/.xls: macro streams, OLE packages;
//  - PDF: JavaScript, automatic actions, launch actions, embedded files, form
//    submission, and every link, including those inside compressed streams;
//  - RTF: embedded objects, the Equation Editor exploit, remote templates.
//
// Decompression uses the browser's own DecompressionStream; everything is
// size-limited, so a ZIP bomb cannot exhaust memory.

import { sniffFileType } from "./file-type.js";
import { crc32 } from "./file-export.js";

const LIMITS = {
  entriesListed: 500,
  entriesExtracted: 40,
  entrySize: 25 * 1024 * 1024,
  totalExtracted: 60 * 1024 * 1024,
  pdfStreams: 80,
  pdfStreamSize: 8 * 1024 * 1024,
  depth: 2,
};

const PROGRAM_EXT = new Set(
  "exe com scr pif bat cmd ps1 psm1 vbs vbe js jse wsf wsh hta msi msp dll cpl ocx lnk reg jar apk sh bash command iso img vhd vhdx one url chm".split(" "),
);
const ARCHIVE_EXT = new Set("zip rar 7z gz tgz tar cab ace arj lzh xz bz2 zst".split(" "));
const MACRO_EXT = new Set("docm dotm xlsm xltm xlam xlsb pptm potm ppsm sldm".split(" "));

const extOf = (name) => (String(name).match(/\.([A-Za-z0-9]+)$/) || [])[1]?.toLowerCase() || "";
const latin1 = (bytes) => {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return s;
};
const u16 = (bytes, at) => bytes[at] | (bytes[at + 1] << 8);
const u32 = (bytes, at) => (bytes[at] | (bytes[at + 1] << 8) | (bytes[at + 2] << 16) | (bytes[at + 3] << 24)) >>> 0;

function concat(chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

/**
 * Decompress with the platform's own implementation, never past `limit`.
 * Corrupt or truncated data returns what decoded before the error — partial
 * output is still evidence.
 */
export async function inflate(bytes, format, limit) {
  if (typeof DecompressionStream === "undefined") return null;
  const reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format)).getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > limit) {
        await reader.cancel().catch(() => {});
        return chunks.length ? concat(chunks) : null;
      }
      chunks.push(value);
    }
  } catch {
    /* corrupt or truncated: keep what decoded */
  }
  return chunks.length ? concat(chunks) : null;
}

// ===== ZIP =====

/** The archive's directory: names, sizes, methods, encryption. */
export function readZipDirectory(bytes) {
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (u32(bytes, i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return null;
  const count = u16(bytes, eocd + 10);
  let at = u32(bytes, eocd + 16);
  const entries = [];
  for (let n = 0; n < count && n < LIMITS.entriesListed; n++) {
    if (at + 46 > bytes.length || u32(bytes, at) !== 0x02014b50) break;
    const flags = u16(bytes, at + 8);
    const nameLen = u16(bytes, at + 28);
    const extraLen = u16(bytes, at + 30);
    const commentLen = u16(bytes, at + 32);
    const rawName = bytes.subarray(at + 46, at + 46 + nameLen);
    entries.push({
      name: flags & 0x0800 ? new TextDecoder().decode(rawName) : latin1(rawName),
      flags,
      method: u16(bytes, at + 10),
      time: u16(bytes, at + 12),
      crc: u32(bytes, at + 16),
      compressedSize: u32(bytes, at + 20),
      size: u32(bytes, at + 24),
      localOffset: u32(bytes, at + 42),
      encrypted: !!(flags & 1),
    });
    at += 46 + nameLen + extraLen + commentLen;
  }
  return { entries, total: count };
}

function zipCryptoDecrypt(data, password, checkByte) {
  const keys = [0x12345678, 0x23456789, 0x34567890];
  const crcByte = (crc, b) => {
    let c = (crc ^ b) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return (c ^ (crc >>> 8)) >>> 0;
  };
  const update = (b) => {
    keys[0] = crcByte(keys[0], b);
    keys[1] = (Math.imul((keys[1] + (keys[0] & 0xff)) >>> 0, 134775813) + 1) >>> 0;
    keys[2] = crcByte(keys[2], keys[1] >>> 24);
  };
  for (const c of new TextEncoder().encode(password)) update(c);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    const t = (keys[2] | 2) & 0xffff;
    out[i] = data[i] ^ ((Math.imul(t, t ^ 1) >>> 8) & 0xff);
    update(out[i]);
  }
  // The last header byte must match the CRC (or the time, with a data descriptor).
  if (out.length < 12 || out[11] !== checkByte) return null;
  return out.subarray(12);
}

/** One entry's content, decrypted with `password` if it needs one. */
export async function readZipEntry(bytes, entry, password = null) {
  const at = entry.localOffset;
  if (at + 30 > bytes.length || u32(bytes, at) !== 0x04034b50) return null;
  if (entry.size > LIMITS.entrySize) return null;
  const start = at + 30 + u16(bytes, at + 26) + u16(bytes, at + 28);
  let data = bytes.subarray(start, start + entry.compressedSize);

  if (entry.encrypted) {
    if (!password || entry.method === 99) return null; // AES-encrypted: not supported
    const check = entry.flags & 0x0008 ? (entry.time >>> 8) & 0xff : entry.crc >>> 24;
    data = zipCryptoDecrypt(data, password, check);
    if (!data) return null;
  }
  let out = null;
  if (entry.method === 0) out = data.slice();
  else if (entry.method === 8) out = await inflate(data, "deflate-raw", LIMITS.entrySize);
  if (!out) return null;
  // A wrong password can pass the one-byte check; the CRC cannot be fooled.
  if (entry.encrypted && crc32(out) !== entry.crc) return null;
  return out;
}

// ===== passwords written in the email =====

const NOT_A_PASSWORD = new Set(
  "is the your a an to for of protected required below above attached reset reminder expired expires expiry policy change changed update manager field here this that will be has have was".split(" "),
);

/** Candidate passwords from text like "the password is: 7731" or "Pwd - Inv2024". */
export function findPasswords(text) {
  const found = [];
  const re = /\b(?:password|passcode|passphrase|pass\s*code|pwd|pw|kennwort|passwort|mot\s+de\s+passe|contrase[ñn]a|senha|parola|wachtwoord|пароль)\b\s*(?:for\s+the\s+(?:file|archive|attachment|zip|document)\s*)?(?:is|:|=|-|–|—)?\s*(?:is\s*)?[:\s]*["'“‘«]?([^\s"'”’»<>]{3,40})/giu;
  for (const m of String(text || "").matchAll(re)) {
    const candidate = m[1].replace(/[.,;:!?)\]]+$/, "");
    if (candidate.length < 3 || NOT_A_PASSWORD.has(candidate.toLowerCase())) continue;
    if (!found.includes(candidate)) found.push(candidate);
    if (found.length >= 10) break;
  }
  return found;
}

// ===== inspectors =====

function finding(level, type, label, message) {
  return { level, type, label, message };
}

async function inspectZip(att, bytes, ctx) {
  const dir = readZipDirectory(bytes);
  if (!dir) return;
  const names = dir.entries.map((e) => e.name);

  if (names.includes("[Content_Types].xml")) {
    await inspectOoxml(att, bytes, dir, ctx);
    return;
  }

  const info = { kind: "Archive", entries: names.slice(0, 50), total: dir.total, notes: [] };
  att.containerInfo = info;
  const files = dir.entries.filter((e) => !e.name.endsWith("/"));
  const encrypted = files.filter((e) => e.encrypted);

  const programs = files.filter((e) => PROGRAM_EXT.has(extOf(e.name)) || /\.[a-z0-9]{2,4}\.(exe|scr|js|vbs|bat|cmd|lnk|hta)$/i.test(e.name));
  if (programs.length) {
    att.containerFindings.push(
      finding("high", "archive-executable", "Program inside archive", `Contains ${programs.slice(0, 3).map((e) => e.name).join(", ")}${programs.length > 3 ? ` and ${programs.length - 3} more` : ""}`),
    );
  }
  const nested = files.filter((e) => ARCHIVE_EXT.has(extOf(e.name)));
  if (nested.length) att.containerFindings.push(finding("medium", "nested-archive", "Archive inside archive", `Contains ${nested.slice(0, 3).map((e) => e.name).join(", ")} — layered archives defeat scanners`));

  let password = null;
  if (encrypted.length) {
    const candidates = [...ctx.passwords, "infected"];
    for (const candidate of candidates) {
      if (await readZipEntry(bytes, encrypted[0], candidate)) {
        password = candidate;
        break;
      }
    }
    const aes = encrypted.some((e) => e.method === 99);
    if (ctx.passwords.length) {
      att.containerFindings.push(
        finding(
          "high",
          "archive-password",
          "Password in the email",
          password && ctx.passwords.includes(password)
            ? `The archive is password-protected and the email gives the password ("${password}") — scanners cannot open it, the victim can. Opened and inspected with that password.`
            : `The archive is password-protected and the email offers a password (${ctx.passwords.map((p) => `"${p}"`).join(", ")}) — a way to get the contents past scanners.${aes ? " It uses AES encryption, which this tool cannot open." : ""}`,
        ),
      );
    } else {
      att.containerFindings.push(finding("medium", "archive-encrypted", "Password-protected", `${encrypted.length} of ${files.length} file${files.length === 1 ? "" : "s"} encrypted — the contents cannot be checked${aes ? " (AES encryption)" : ""}.`));
    }
    info.notes.push(password ? `Opened with the password "${password}".` : "Encrypted — contents not inspected.");
  }

  // Extract what can be read, so each file is hashed, typed and checked too.
  let extracted = 0;
  let total = 0;
  for (const entry of files) {
    if (extracted >= LIMITS.entriesExtracted || total + entry.size > LIMITS.totalExtracted) {
      info.notes.push(`Only the first ${extracted} files were extracted.`);
      break;
    }
    if (entry.encrypted && !password) continue;
    const content = await readZipEntry(bytes, entry, entry.encrypted ? password : null);
    if (!content) continue;
    extracted++;
    total += content.length;
    ctx.children.push({
      value: entry.name.split("/").pop() || entry.name,
      contentType: sniffFileType(content)?.label || "unknown",
      size: content.length,
      source: `Inside archive ${att.value}`,
      inline: false,
      embeddedIn: att.value,
      bytes: content,
      depth: (att.depth || 0) + 1,
    });
  }
}

async function inspectOoxml(att, bytes, dir, ctx) {
  const names = dir.entries.map((e) => e.name);
  const info = { kind: "Office document", entries: [], notes: [] };
  att.containerInfo = info;
  const read = async (entry) => new TextDecoder("utf-8", { fatal: false }).decode((await readZipEntry(bytes, entry)) || new Uint8Array());

  if (names.some((n) => /vbaProject\.bin$/i.test(n)) || MACRO_EXT.has(extOf(att.value))) {
    att.containerFindings.push(finding("high", "macros", "Contains macros", "The document carries VBA macros, which run code when enabled."));
    info.entries.push("VBA macros");
  }
  if (names.some((n) => /\/activeX\//i.test(n))) {
    att.containerFindings.push(finding("medium", "activex", "ActiveX controls", "ActiveX controls can run code when the document is opened."));
    info.entries.push("ActiveX controls");
  }
  const embedded = names.filter((n) => /\/embeddings\//i.test(n));
  if (embedded.length) {
    att.containerFindings.push(finding("medium", "embedded-object", "Embedded objects", `${embedded.length} embedded object${embedded.length === 1 ? "" : "s"} (${embedded.slice(0, 3).map((n) => n.split("/").pop()).join(", ")})`));
    info.entries.push(...embedded.map((n) => n.split("/").pop()));
  }

  for (const entry of dir.entries) {
    if (/\.rels$/i.test(entry.name)) {
      const xml = await read(entry);
      for (const m of xml.matchAll(/<Relationship\b[^>]*>/gi)) {
        const tag = m[0];
        const target = (tag.match(/\bTarget\s*=\s*"([^"]+)"/i) || [])[1]?.replace(/&amp;/g, "&");
        const type = (tag.match(/\bType\s*=\s*"([^"]+)"/i) || [])[1] || "";
        if (!target || !/TargetMode\s*=\s*"External"/i.test(tag)) continue;
        const kind = type.split("/").pop();
        if (/attachedTemplate|subDocument|frame/i.test(kind)) {
          att.containerFindings.push(finding("high", "remote-template", "Remote template", `Loads ${kind === "attachedTemplate" ? "its template" : "content"} from ${target} when opened — template injection, a common way to fetch the payload.`));
        } else if (/oleObject/i.test(kind)) {
          att.containerFindings.push(finding("high", "remote-object", "Remote linked object", `Links an object from ${target}, fetched when the document opens.`));
        }
        if (/^(https?|ftp):\/\//i.test(target) || /^\\\\/.test(target)) {
          ctx.urls.push({ value: target, source: `Inside ${att.value} (${kind || "external link"})`, isMismatch: false });
          info.entries.push(`${kind}: ${target}`);
        }
      }
    }
    if (/^(word\/document|xl\/sharedStrings|word\/header\d*|word\/footer\d*)\.xml$/i.test(entry.name)) {
      const xml = await read(entry);
      if (/\bDDEAUTO\b|\bDDE\s+["']?[a-z]:?\\?|instrText[^>]*>\s*DDE\b/i.test(xml)) {
        att.containerFindings.push(finding("high", "dde", "DDE command", "The document contains a DDE field, which can start a program when the document opens."));
      }
    }
  }
}

function inspectOle(att, bytes) {
  const text = latin1(bytes.subarray(0, Math.min(bytes.length, 20 * 1024 * 1024)));
  const utf16 = (s) => s.split("").join("\u0000");
  const has = (s) => text.includes(utf16(s)) || text.includes(s);
  att.containerInfo = { kind: "Legacy Office document", entries: [], notes: [] };
  if (has("_VBA_PROJECT") || (has("VBA") && has("PROJECT") && (has("ThisDocument") || has("ThisWorkbook") || has("Module1")))) {
    att.containerFindings.push(finding("high", "macros", "Contains macros", "The document carries VBA macros, which run code when enabled."));
    att.containerInfo.entries.push("VBA macros");
  }
  if (/Auto_?Open|Document_Open|Workbook_Open|AutoExec|Shell\(|WScript\.Shell|CreateObject/i.test(text)) {
    att.containerFindings.push(finding("high", "macro-autorun", "Auto-running macro", "Macro code that starts by itself or launches programs (AutoOpen / Document_Open / Shell)."));
  }
  if (has("Ole10Native")) {
    att.containerFindings.push(finding("medium", "embedded-object", "Embedded OLE package", "An embedded package can carry any file, including programs."));
  }
  if (has("EncryptedPackage")) {
    att.containerFindings.push(finding("medium", "archive-encrypted", "Password-protected document", "The document is encrypted, so its contents cannot be checked."));
  }
}

async function inspectPdf(att, bytes, ctx) {
  const raw = latin1(bytes.subarray(0, Math.min(bytes.length, 30 * 1024 * 1024)));
  const info = { kind: "PDF", entries: [], notes: [] };
  att.containerInfo = info;

  // Compressed streams hide links and scripts: decode them, within limits.
  const decoded = [];
  const embeddedFiles = [];
  let streams = 0;
  for (const m of raw.matchAll(/(?<!end)stream\r?\n/g)) {
    if (streams >= LIMITS.pdfStreams) break;
    const dictStart = raw.lastIndexOf("<<", m.index);
    const dict = dictStart >= 0 && m.index - dictStart < 2000 ? raw.slice(dictStart, m.index) : "";
    if (!/\/FlateDecode/.test(dict)) continue;
    const end = raw.indexOf("endstream", m.index + m[0].length);
    if (end < 0) continue;
    streams++;
    const data = bytes.subarray(m.index + m[0].length, end);
    const out = await inflate(data, "deflate", LIMITS.pdfStreamSize);
    if (!out) continue;
    if (/\/EmbeddedFile/.test(dict)) embeddedFiles.push(out);
    else decoded.push(latin1(out.subarray(0, 2 * 1024 * 1024)));
  }

  // Names can be written with #xx escapes ("/J#61vaScript") to dodge scanners.
  const unescapeNames = (s) => s.replace(/\/[A-Za-z0-9#]+/g, (n) => (n.includes("#") ? n.replace(/#([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))) : n));
  const all = unescapeNames(`${raw}\n${decoded.join("\n")}`);

  const count = (re) => (all.match(re) || []).length;
  if (count(/\/(?:JavaScript|JS)\b/g)) att.containerFindings.push(finding("high", "pdf-javascript", "JavaScript in PDF", "The PDF contains JavaScript, which runs in the reader."));
  if (count(/\/Launch\b/g)) att.containerFindings.push(finding("high", "pdf-launch", "Launch action", "The PDF can start a program or open a file on the computer."));
  if (count(/\/OpenAction\b|\/AA\b/g)) att.containerFindings.push(finding("medium", "pdf-autoaction", "Runs on open", "The PDF performs an action automatically when opened."));
  if (count(/\/EmbeddedFile\b/g)) att.containerFindings.push(finding("medium", "pdf-embedded", "Embedded file", "The PDF carries a file inside it."));
  if (count(/\/SubmitForm\b/g)) att.containerFindings.push(finding("medium", "pdf-submit", "Submits form data", "Form contents can be sent to an outside address."));
  if (count(/\/RichMedia\b|\/XFA\b/g)) att.containerFindings.push(finding("medium", "pdf-richmedia", "Rich media / XFA", "Active content beyond plain pages."));

  const urls = new Set();
  for (const m of all.matchAll(/\/URI\s*\(((?:\\.|[^\\)])*)\)/g)) urls.add(m[1].replace(/\\([()\\])/g, "$1"));
  for (const m of all.matchAll(/\/URI\s*<([0-9A-Fa-f\s]+)>/g)) {
    const hex = m[1].replace(/\s+/g, "");
    let s = "";
    for (let i = 0; i + 1 < hex.length; i += 2) s += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    urls.add(s);
  }
  for (const text of decoded) for (const m of text.matchAll(/https?:\/\/[^\s<>()"'\\\]]{4,}/g)) urls.add(m[0]);
  for (const url of urls) {
    if (!/^(https?|ftp|mailto|file):/i.test(url.trim())) continue;
    ctx.urls.push({ value: url.trim(), source: `Inside ${att.value} (link)`, isMismatch: false });
  }
  info.entries.push(`${urls.size} link${urls.size === 1 ? "" : "s"}`);
  if (streams) info.notes.push(`${streams} compressed stream${streams === 1 ? "" : "s"} decoded and searched.`);

  embeddedFiles.slice(0, 10).forEach((content, i) => {
    const ext = sniffFileType(content)?.extensions?.[0] || "bin";
    ctx.children.push({
      value: `${att.value}-embedded-${i + 1}.${ext}`,
      contentType: sniffFileType(content)?.label || "unknown",
      size: content.length,
      source: `Embedded in ${att.value}`,
      inline: false,
      embeddedIn: att.value,
      bytes: content,
      depth: (att.depth || 0) + 1,
    });
  });
}

function inspectRtf(att, bytes, ctx) {
  const text = latin1(bytes.subarray(0, Math.min(bytes.length, 20 * 1024 * 1024)));
  att.containerInfo = { kind: "RTF document", entries: [], notes: [] };
  if (/equation\.3|equation\s*native|\\objclass\s+equation/i.test(text)) {
    att.containerFindings.push(finding("high", "rtf-equation", "Equation Editor object", "An Equation Editor object — the vehicle of a widely exploited Office vulnerability (CVE-2017-11882)."));
  }
  if (/\\objdata/i.test(text)) att.containerFindings.push(finding("medium", "embedded-object", "Embedded object", "The RTF carries an embedded object."));
  if (/\\objupdate/i.test(text)) att.containerFindings.push(finding("high", "rtf-objupdate", "Object updates on open", "The embedded object refreshes itself when the document opens, without a click."));
  const template = text.match(/\\\*\\template\s+([^}\s]+)/i);
  if (template && /^(https?:|\\\\)/i.test(template[1])) {
    att.containerFindings.push(finding("high", "remote-template", "Remote template", `Loads its template from ${template[1]} — template injection.`));
  }
  for (const m of text.matchAll(/HYPERLINK\s+"([^"]+)"/gi)) {
    ctx.urls.push({ value: m[1], source: `Inside ${att.value} (hyperlink)`, isMismatch: false });
  }
}

/**
 * Look inside every attachment that is a container, add what was found to the
 * IOC lists, and recurse into what was extracted (to a fixed depth).
 *
 * @param {Object} iocs - extracted IOCs (mutated)
 * @param {Object|null} body - parsed body, searched for archive passwords
 * @returns {Promise<{urls: Array, children: Array}>} what was added
 */
export async function inspectContainers(iocs, body) {
  const ctx = {
    passwords: findPasswords(`${body?.text || ""}\n${(body?.html || "").replace(/<[^>]+>/g, " ")}`),
    urls: [],
    children: [],
  };
  const added = { urls: [], children: [] };

  let queue = (iocs.attachments || []).filter((a) => !a.containerChecked);
  for (let round = 0; queue.length && round <= LIMITS.depth; round++) {
    for (const att of queue) {
      att.containerChecked = true;
      att.containerFindings = att.containerFindings || [];
      const bytes = att.bytes;
      if (!bytes?.length) continue;
      const kind = sniffFileType(bytes)?.label || "";
      const ext = extOf(att.value);
      try {
        if (/^ZIP/.test(kind)) await inspectZip(att, bytes, ctx);
        // Readers accept a PDF header anywhere in the first 1 KB; so do attackers.
        else if (/^PDF/.test(kind) || latin1(bytes.subarray(0, 1024)).includes("%PDF-")) await inspectPdf(att, bytes, ctx);
        else if (/^RTF/.test(kind)) inspectRtf(att, bytes, ctx);
        else if (/OLE2/.test(kind) && ext !== "msg") inspectOle(att, bytes);
      } catch (err) {
        // One malformed file must not stop the rest of the analysis.
        att.containerInfo = { kind: kind || "file", entries: [], notes: [`Could not be fully read: ${err.message}`] };
      }
    }
    const children = ctx.children.splice(0);
    iocs.attachments.push(...children);
    added.children.push(...children);
    queue = children.filter((c) => (c.depth || 0) <= LIMITS.depth);
  }

  const known = new Set(iocs.urls.map((u) => u.value));
  for (const u of ctx.urls) {
    if (known.has(u.value)) continue;
    known.add(u.value);
    iocs.urls.push(u);
    added.urls.push(u);
  }
  return added;
}
