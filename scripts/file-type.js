// Attachment content inspection
//
// The app hashes attachments but never looked inside them. A file called
// "Invoice.pdf" whose bytes begin with "MZ" is a Windows program with a
// harmless name — the single strongest attachment signal there is, and it costs
// only the first few bytes. Nothing here executes or unpacks anything.

/** Magic-number table: [label, extensions this content legitimately has, bytes]. */
const SIGNATURES = [
  ["Windows executable (PE)", ["exe", "dll", "scr", "sys", "cpl", "ocx", "msi"], [0x4d, 0x5a]],
  ["ELF executable", ["elf", "so", "bin"], [0x7f, 0x45, 0x4c, 0x46]],
  ["Mach-O executable", ["dylib", "bin", "app"], [0xcf, 0xfa, 0xed, 0xfe]],
  ["PDF document", ["pdf"], [0x25, 0x50, 0x44, 0x46]],
  ["ZIP archive or Office/OpenDocument file", ["zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "jar", "apk", "epub", "vsdx", "xlsm", "docm", "pptm"], [0x50, 0x4b]],
  ["RAR archive", ["rar"], [0x52, 0x61, 0x72, 0x21]],
  ["7-Zip archive", ["7z"], [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]],
  ["gzip archive", ["gz", "tgz"], [0x1f, 0x8b]],
  ["Legacy Office document (OLE2)", ["doc", "xls", "ppt", "msg", "vsd"], [0xd0, 0xcf, 0x11, 0xe0]],
  ["RTF document", ["rtf", "doc"], [0x7b, 0x5c, 0x72, 0x74, 0x66]],
  ["PNG image", ["png"], [0x89, 0x50, 0x4e, 0x47]],
  ["JPEG image", ["jpg", "jpeg"], [0xff, 0xd8, 0xff]],
  ["GIF image", ["gif"], [0x47, 0x49, 0x46, 0x38]],
  ["BMP image", ["bmp"], [0x42, 0x4d]],
  ["ICO icon", ["ico"], [0x00, 0x00, 0x01, 0x00]],
  ["Windows shortcut (.lnk)", ["lnk"], [0x4c, 0x00, 0x00, 0x00]],
  ["ISO disk image", ["iso"], null], // checked separately: "CD001" at 0x8001
  ["Class file", ["class"], [0xca, 0xfe, 0xba, 0xbe]],
];

// Content that can run, whatever the file is called.
const EXECUTABLE_LABELS = new Set([
  "Windows executable (PE)",
  "ELF executable",
  "Mach-O executable",
  "Windows shortcut (.lnk)",
  "Class file",
]);

const startsWith = (bytes, sig) =>
  sig.every((b, i) => bytes[i] === b);

export function extensionOf(filename) {
  const m = String(filename || "").match(/\.([A-Za-z0-9]+)$/);
  return m ? m[1].toLowerCase() : "";
}

/**
 * Identify content from its first bytes.
 * @param {Uint8Array} bytes
 * @returns {{label: string, extensions: string[]} | null}
 */
export function sniffFileType(bytes) {
  if (!bytes || bytes.length < 2) return null;
  for (const [label, extensions, sig] of SIGNATURES) {
    if (sig && startsWith(bytes, sig)) return { label, extensions };
  }
  if (bytes.length > 0x8006 && String.fromCharCode(...bytes.slice(0x8001, 0x8006)) === "CD001") {
    return { label: "ISO disk image", extensions: ["iso"] };
  }
  return null;
}

/** Decode the first part of a file as text, for the HTML checks below. */
function asText(bytes, limit = 200000) {
  try {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(0, limit));
  } catch {
    return "";
  }
}

/**
 * HTML smuggling: an attached page that carries the payload inside itself as
 * base64 and writes it to disk with a Blob and a download link, so nothing
 * malicious ever crosses the mail gateway as a file.
 */
function smugglingFindings(text) {
  const hits = [];
  if (/new\s+Blob\s*\(|msSaveOrOpenBlob|createObjectURL/i.test(text)) hits.push("builds a file in the browser");
  if (/download\s*=|\.click\s*\(\)/i.test(text)) hits.push("triggers a download automatically");
  if (/base64,[A-Za-z0-9+/=]{500,}|atob\s*\(/i.test(text)) hits.push("carries a large embedded payload");
  return hits;
}

/**
 * Risk flags for one attachment, from its content rather than its name.
 * @param {{value?: string, contentType?: string, bytes?: Uint8Array}} att
 * @returns {Array<{type: "high"|"medium", label: string, message: string}>}
 */
export function inspectAttachment(att) {
  const out = [];
  const bytes = att?.bytes;
  if (!bytes || !bytes.length) return out;

  const ext = extensionOf(att.value);
  const sniffed = sniffFileType(bytes);

  if (sniffed) {
    const matches = !ext || sniffed.extensions.includes(ext);
    if (!matches) {
      const executable = EXECUTABLE_LABELS.has(sniffed.label);
      out.push({
        type: executable ? "high" : "medium",
        label: executable ? "Executable content" : "Type mismatch",
        message: `Named ".${ext}" but the content is ${sniffed.label}.`,
      });
    } else if (EXECUTABLE_LABELS.has(sniffed.label)) {
      out.push({
        type: "high",
        label: "Executable content",
        message: `The content is ${sniffed.label}.`,
      });
    }
  }

  const isHtml =
    /html/i.test(att.contentType || "") || ["htm", "html", "shtml", "svg"].includes(ext);
  if (isHtml) {
    const hits = smugglingFindings(asText(bytes));
    if (hits.length >= 2) {
      out.push({
        type: "high",
        label: "HTML smuggling",
        message: `This attached page ${hits.join(", ")} — the payload travels inside the HTML, past mail filters.`,
      });
    }
    if (/<script/i.test(asText(bytes, 20000))) {
      out.push({
        type: "medium",
        label: "Scripted attachment",
        message: "The attached page contains script.",
      });
    }
  }

  // An archive is not malicious by itself, but it is how executables arrive.
  if (sniffed && /archive/i.test(sniffed.label) && !/Office/i.test(sniffed.label)) {
    out.push({
      type: "medium",
      label: "Archive",
      message: `${sniffed.label} — the contents cannot be checked from here; open it only in an isolated environment.`,
    });
  }

  return out;
}

/**
 * Shannon entropy in bits per byte (0–8). Text sits around 4–5; compressed,
 * encrypted or packed content is close to 8.
 */
export function entropy(bytes) {
  const n = Math.min(bytes.length, 8 * 1024 * 1024);
  if (!n) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < n; i++) counts[bytes[i]]++;
  let h = 0;
  for (const c of counts) {
    if (c) {
      const p = c / n;
      h -= p * Math.log2(p);
    }
  }
  return h;
}

/** Architecture and build time of a Windows program, from its PE header. */
function peInfo(bytes) {
  if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) return null;
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const pe = v.getUint32(0x3c, true);
  if (pe + 24 > bytes.length || v.getUint32(pe, true) !== 0x00004550) return null;
  const machine = v.getUint16(pe + 4, true);
  const stamp = v.getUint32(pe + 8, true);
  const characteristics = v.getUint16(pe + 22, true);
  const arch = { 0x14c: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0xaa64: "ARM64", 0x1c4: "ARM" }[machine] || `machine 0x${machine.toString(16)}`;
  return {
    arch,
    kind: characteristics & 0x2000 ? "DLL (library)" : "Executable",
    // Linkers can write anything here; a date in the future or before 1995 is
    // itself a sign the header was tampered with.
    built: stamp ? new Date(stamp * 1000) : null,
  };
}

/** Printable ASCII runs of six or more characters, as the strings tool finds them. */
function strings(bytes, limit = 4 * 1024 * 1024) {
  const out = [];
  let run = "";
  const n = Math.min(bytes.length, limit);
  for (let i = 0; i < n; i++) {
    const b = bytes[i];
    if (b >= 0x20 && b < 0x7f) run += String.fromCharCode(b);
    else {
      if (run.length >= 6) out.push(run);
      run = "";
    }
  }
  if (run.length >= 6) out.push(run);
  return out;
}

/**
 * Everything worth knowing about a file before deciding what to do with it,
 * read from its bytes: what it really is, whether its name agrees, how
 * random it is, and what addresses are written inside it. Nothing is run.
 */
export function describeFile(bytes, name, declaredType) {
  bytes = bytes || new Uint8Array();
  const detected = sniffFileType(bytes);
  const ext = extensionOf(name);
  const h = entropy(bytes);
  const text = strings(bytes);
  const joined = text.join("\n");
  const unique = (re) => [...new Set(joined.match(re) || [])];

  let nameCheck;
  if (!detected) nameCheck = { ok: null, text: "No known file signature — plain text, or a format this tool does not recognise" };
  else if (!ext) nameCheck = { ok: false, text: `The name has no extension; the content is a ${detected.label}` };
  else if (detected.extensions.includes(ext)) nameCheck = { ok: true, text: `".${ext}" matches the content (${detected.label})` };
  else nameCheck = { ok: false, text: `".${ext}" does not match the content, which is a ${detected.label}` };

  return {
    size: bytes.length,
    declaredType: declaredType || null,
    detected: detected?.label || null,
    nameCheck,
    entropy: h,
    entropyNote:
      h >= 7.5 ? "very high — compressed, encrypted or packed" : h >= 6 ? "high — binary or compressed data" : h >= 3.5 ? "typical of text or documents" : "low — repetitive or mostly empty",
    pe: peInfo(bytes),
    head: bytes.subarray(0, 64),
    urls: unique(/\bhttps?:\/\/[^\s"'<>()\\]{4,}/gi).slice(0, 15),
    emails: unique(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g).slice(0, 10),
    ips: unique(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g).slice(0, 10),
    stringCount: text.length,
  };
}
