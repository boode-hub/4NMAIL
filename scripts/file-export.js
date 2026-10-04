// Getting files out of the analyzer, safely.
//
// Attachments in a phishing email are very often malware. Handing them over
// as plain files invites an accidental double-click, and endpoint protection
// may delete or quarantine them before the analyst gets a look. The convention
// across malware-analysis tooling is a password-protected ZIP with the password
// "infected": nothing runs, nothing is scanned away, and every analysis tool
// knows the password.
//
// The ZIP is written here by hand (stored, traditional PKWARE encryption) so
// the app keeps its no-dependency rule. Traditional ZIP encryption is weak and
// that is fine — it exists to stop accidents and scanners, not attackers.
// Every unzip tool, including Windows Explorer and 7-Zip, opens it.

export const ZIP_PASSWORD = "infected";

// ===== CRC-32 =====

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

const crcByte = (crc, byte) => (CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8)) >>> 0;

export function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) crc = crcByte(crc, bytes[i]);
  return (crc ^ 0xffffffff) >>> 0;
}

// ===== traditional PKWARE encryption =====

function zipCryptoKeys(password) {
  const keys = [0x12345678, 0x23456789, 0x34567890];
  const update = (byte) => {
    keys[0] = crcByte(keys[0], byte);
    keys[1] = (Math.imul((keys[1] + (keys[0] & 0xff)) >>> 0, 134775813) + 1) >>> 0;
    keys[2] = crcByte(keys[2], keys[1] >>> 24);
  };
  for (const ch of new TextEncoder().encode(password)) update(ch);
  const streamByte = () => {
    const t = (keys[2] | 2) & 0xffff;
    return (Math.imul(t, t ^ 1) >>> 8) & 0xff;
  };
  return { update, streamByte };
}

function encrypt(plain, password, crc) {
  const { update, streamByte } = zipCryptoKeys(password);
  const out = new Uint8Array(plain.length + 12);
  // 12-byte header: random, except the last byte, which lets unzip tools check
  // the password against the CRC.
  const header = crypto.getRandomValues(new Uint8Array(12));
  header[11] = crc >>> 24;
  for (let i = 0; i < 12; i++) {
    out[i] = header[i] ^ streamByte();
    update(header[i]);
  }
  for (let i = 0; i < plain.length; i++) {
    out[12 + i] = plain[i] ^ streamByte();
    update(plain[i]);
  }
  return out;
}

// ===== ZIP container =====

function dosDateTime(date) {
  const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
  const day = ((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { time, day };
}

/**
 * A single-file ZIP, encrypted with `password`, contents stored as they are.
 * @param {string} name - file name inside the archive
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function zipEncrypted(name, bytes, password = ZIP_PASSWORD, date = new Date()) {
  const nameBytes = new TextEncoder().encode(name);
  const crc = crc32(bytes);
  const data = encrypt(bytes, password, crc);
  const { time, day } = dosDateTime(date);
  const FLAGS = 0x0001 | 0x0800; // encrypted, UTF-8 name

  const local = new DataView(new ArrayBuffer(30));
  local.setUint32(0, 0x04034b50, true);
  local.setUint16(4, 20, true);
  local.setUint16(6, FLAGS, true);
  local.setUint16(8, 0, true); // stored
  local.setUint16(10, time, true);
  local.setUint16(12, day, true);
  local.setUint32(14, crc, true);
  local.setUint32(18, data.length, true);
  local.setUint32(22, bytes.length, true);
  local.setUint16(26, nameBytes.length, true);
  local.setUint16(28, 0, true);

  const central = new DataView(new ArrayBuffer(46));
  central.setUint32(0, 0x02014b50, true);
  central.setUint16(4, 20, true);
  central.setUint16(6, 20, true);
  central.setUint16(8, FLAGS, true);
  central.setUint16(10, 0, true);
  central.setUint16(12, time, true);
  central.setUint16(14, day, true);
  central.setUint32(16, crc, true);
  central.setUint32(20, data.length, true);
  central.setUint32(24, bytes.length, true);
  central.setUint16(28, nameBytes.length, true);
  // extra, comment, disk, internal and external attributes, offset: all zero.

  const localSize = 30 + nameBytes.length + data.length;
  const centralSize = 46 + nameBytes.length;
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(8, 1, true);
  end.setUint16(10, 1, true);
  end.setUint32(12, centralSize, true);
  end.setUint32(16, localSize, true);

  const out = new Uint8Array(localSize + centralSize + 22);
  let at = 0;
  for (const part of [new Uint8Array(local.buffer), nameBytes, data, new Uint8Array(central.buffer), nameBytes, new Uint8Array(end.buffer)]) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

// ===== names =====

// Extensions that run when double-clicked, or that Office/browsers execute.
const EXECUTABLE = new Set(
  "exe com scr pif bat cmd ps1 psm1 vbs vbe js jse wsf wsh hta msi msp dll cpl ocx sys lnk reg jar apk app sh bash command docm xlsm pptm iso img vhd vhdx one url".split(" "),
);

/**
 * A file name safe to hand to the browser: no paths, no control characters,
 * no reserved characters, and — for a raw download — no extension that runs
 * when double-clicked.
 */
export function safeFilename(name, { raw = false, program = false } = {}) {
  let clean = String(name || "file")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .replace(/[\\/:*?"<>|]/g, "_")
    .replace(/^[.\s]+|[.\s]+$/g, "")
    .slice(0, 180);
  if (!clean) clean = "file";
  if (raw) {
    // The name is what an attacker controls; `program` says what the bytes
    // really are. Either one being executable is enough.
    const ext = (clean.match(/\.([A-Za-z0-9]+)$/) || [])[1]?.toLowerCase();
    if (!ext || EXECUTABLE.has(ext) || program) clean += ".bin";
  }
  return clean;
}

export function isExecutableName(name) {
  const ext = (String(name || "").match(/\.([A-Za-z0-9]+)$/) || [])[1]?.toLowerCase();
  return !!ext && EXECUTABLE.has(ext);
}

// ===== hex / Base64 to bytes =====

/**
 * Turn pasted text into bytes, the way CyberChef's "From Hex" / "From Base64"
 * do — accepting the forms analysts actually paste:
 *   hex:    "4d 5a 90 00", "4D5A9000", "0x4d,0x5a", "\x4d\x5a", "4d:5a", hexdump lines
 *   base64: with or without line breaks or padding, base64url, data: URIs
 *
 * @param {string} text
 * @param {"auto"|"hex"|"base64"} mode
 * @returns {{bytes: Uint8Array, mode: string} | {error: string}}
 */
export function decodeToBytes(text, mode = "auto") {
  const input = String(text || "").trim();
  if (!input) return { error: "Paste some hex or Base64 first." };

  const dataUri = input.match(/^data:[^,]*;base64,([\s\S]*)$/i);
  if (dataUri) return fromBase64(dataUri[1], "base64 (data: URI)");

  const asHex = cleanHex(input);
  if (mode === "hex" || (mode === "auto" && asHex)) {
    if (!asHex) return { error: "That is not hex: only 0-9 and a-f are allowed, in pairs." };
    if (asHex.length % 2) return { error: `Hex needs pairs of digits; this has ${asHex.length} digits.` };
    const bytes = new Uint8Array(asHex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(asHex.substr(i * 2, 2), 16);
    return { bytes, mode: "hex" };
  }
  return fromBase64(input, "base64");
}

/** Hex digits only, or null when the text is not hex. */
function cleanHex(text) {
  // A hexdump line ("00000000  4d 5a 90 00 ...  |MZ..|"): drop offsets and the
  // ASCII column.
  const lines = text.split(/\r?\n/).map((line) => {
    const dump = line.match(/^\s*[0-9a-f]{4,16}[:\s]\s*((?:[0-9a-f]{2}\s{1,2}){1,32})/i);
    return dump ? dump[1] : line;
  });
  const stripped = lines
    .join(" ")
    .replace(/0x|\\x|%/gi, " ")
    .replace(/[\s,:;-]+/g, "");
  return /^[0-9a-f]+$/i.test(stripped) ? stripped : null;
}

function fromBase64(text, label) {
  const clean = text.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/]*$/.test(clean) || clean.length % 4 === 1) {
    return { error: "That is neither hex nor valid Base64." };
  }
  try {
    const bin = atob(clean.padEnd(Math.ceil(clean.length / 4) * 4, "="));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return { bytes, mode: label };
  } catch {
    return { error: "That is neither hex nor valid Base64." };
  }
}
