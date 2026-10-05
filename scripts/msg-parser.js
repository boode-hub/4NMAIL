// Outlook .msg files.
//
// A .msg is a Compound File (the OLE2 "file system in a file" Office used
// before ZIP) holding the message as MAPI properties: the original Internet
// headers, the subject, plain and HTML bodies, and each attachment in its own
// storage. This reads that structure and rebuilds an ordinary RFC 822 message,
// so a .msg goes through exactly the same analysis as an .eml. Read only —
// nothing in the file is run.
//
// References: [MS-CFB] Compound File Binary Format, [MS-OXMSG] .msg File Format.

const SIGNATURE = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const END_OF_CHAIN = 0xfffffffe;
const MAX_SECTORS = 1 << 22; // a chain longer than this is corrupt or hostile

export function isMsgFile(bytes) {
  return bytes?.length >= 512 && SIGNATURE.every((b, i) => bytes[i] === b);
}

// ===== Compound File =====

/** The directory tree of a Compound File, with a reader for each stream. */
export function readCompoundFile(bytes) {
  if (!isMsgFile(bytes)) throw new Error("Not an Outlook .msg file (no Compound File signature)");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (at) => view.getUint16(at, true);
  const u32 = (at) => view.getUint32(at, true);

  const sectorSize = 1 << u16(0x1e);
  const miniSectorSize = 1 << u16(0x20);
  const miniCutoff = u32(0x38);
  if (sectorSize !== 512 && sectorSize !== 4096) throw new Error("Unsupported Compound File sector size");
  const sectorOffset = (n) => (n + 1) * sectorSize;

  // The FAT's own sectors are listed in the DIFAT: 109 in the header, the rest chained.
  const fatSectors = [];
  for (let i = 0; i < 109; i++) {
    const s = u32(0x4c + i * 4);
    if (s < END_OF_CHAIN) fatSectors.push(s);
  }
  let difat = u32(0x44);
  for (let guard = 0; difat < END_OF_CHAIN && guard < 10000; guard++) {
    const at = sectorOffset(difat);
    if (at + sectorSize > bytes.length) break;
    for (let i = 0; i < sectorSize / 4 - 1; i++) {
      const s = u32(at + i * 4);
      if (s < END_OF_CHAIN) fatSectors.push(s);
    }
    difat = u32(at + sectorSize - 4);
  }
  const fat = [];
  for (const s of fatSectors) {
    const at = sectorOffset(s);
    if (at + sectorSize > bytes.length) continue;
    for (let i = 0; i < sectorSize / 4; i++) fat.push(u32(at + i * 4));
  }

  const chain = (start, table) => {
    const out = [];
    const seen = new Set();
    for (let s = start; s < END_OF_CHAIN && s < table.length && !seen.has(s) && out.length < MAX_SECTORS; s = table[s]) {
      seen.add(s);
      out.push(s);
    }
    return out;
  };
  const readChain = (start, size) => {
    const out = new Uint8Array(size);
    let at = 0;
    for (const s of chain(start, fat)) {
      if (at >= size) break;
      const from = sectorOffset(s);
      const part = bytes.subarray(from, Math.min(from + sectorSize, from + size - at, bytes.length));
      out.set(part, at);
      at += part.length;
    }
    return out;
  };

  // Directory entries, 128 bytes each.
  const dirBytes = (() => {
    const sectors = chain(u32(0x30), fat);
    return readChain(u32(0x30), sectors.length * sectorSize);
  })();
  const dv = new DataView(dirBytes.buffer);
  const entries = [];
  for (let at = 0; at + 128 <= dirBytes.length; at += 128) {
    const nameLen = Math.min(dv.getUint16(at + 0x40, true), 64);
    let name = "";
    for (let i = 0; i < nameLen - 2 && i < 62; i += 2) {
      const c = dv.getUint16(at + i, true);
      if (!c) break;
      name += String.fromCharCode(c);
    }
    entries.push({
      name,
      type: dirBytes[at + 0x42], // 1 storage, 2 stream, 5 root
      left: dv.getUint32(at + 0x44, true),
      right: dv.getUint32(at + 0x48, true),
      child: dv.getUint32(at + 0x4c, true),
      start: dv.getUint32(at + 0x74, true),
      size: dv.getUint32(at + 0x78, true),
    });
  }
  const root = entries[0];
  if (!root || root.type !== 5) throw new Error("Damaged .msg file (no root entry)");

  // Small streams live in the mini stream, addressed through the mini FAT.
  const miniFat = [];
  {
    const count = u32(0x40);
    const first = u32(0x3c);
    if (count && first < END_OF_CHAIN) {
      const raw = readChain(first, chain(first, fat).length * sectorSize);
      const mv = new DataView(raw.buffer);
      for (let i = 0; i + 4 <= raw.length; i += 4) miniFat.push(mv.getUint32(i, true));
    }
  }
  const miniStream = readChain(root.start, root.size);

  const readStream = (entry) => {
    const size = Math.min(entry.size, bytes.length);
    if (size < miniCutoff) {
      const out = new Uint8Array(size);
      let at = 0;
      for (const s of chain(entry.start, miniFat)) {
        if (at >= size) break;
        const from = s * miniSectorSize;
        const part = miniStream.subarray(from, Math.min(from + miniSectorSize, from + size - at));
        out.set(part, at);
        at += part.length;
      }
      return out;
    }
    return readChain(entry.start, size);
  };

  // Each storage's children form a red-black tree; walk it to a flat list.
  const childrenOf = (entry) => {
    const out = [];
    const stack = [entry.child];
    const seen = new Set();
    while (stack.length) {
      const id = stack.pop();
      if (id >= entries.length || seen.has(id)) continue;
      seen.add(id);
      const e = entries[id];
      out.push(e);
      stack.push(e.left, e.right);
    }
    return out;
  };

  return { root, childrenOf, readStream };
}

// ===== MAPI properties =====

const CODEPAGES = {
  65001: "utf-8", 1252: "windows-1252", 1250: "windows-1250", 1251: "windows-1251", 1253: "windows-1253",
  1254: "windows-1254", 1255: "windows-1255", 1256: "windows-1256", 1257: "windows-1257", 1258: "windows-1258",
  932: "shift_jis", 936: "gbk", 949: "euc-kr", 950: "big5", 874: "windows-874", 28591: "iso-8859-1",
  28592: "iso-8859-2", 20127: "us-ascii", 50220: "iso-2022-jp", 51932: "euc-jp", 20866: "koi8-r",
};

function decoderFor(codepage) {
  try {
    return new TextDecoder(CODEPAGES[codepage] || "windows-1252");
  } catch {
    return new TextDecoder("windows-1252");
  }
}

/** One storage's properties: { "0037": value, ... } plus its sub-storages. */
function readProperties(cfb, storage, isTopLevel) {
  const props = {};
  const storages = [];
  let fixed = null;
  for (const e of cfb.childrenOf(storage)) {
    if (e.type === 1) {
      storages.push(e);
      continue;
    }
    if (e.type !== 2) continue;
    if (e.name === "__properties_version1.0") fixed = cfb.readStream(e);
    const m = e.name.match(/^__substg1\.0_([0-9A-F]{4})([0-9A-F]{4})$/i);
    if (m) props[m[1].toUpperCase()] = { type: m[2].toUpperCase(), bytes: cfb.readStream(e) };
  }

  // Fixed-size values (dates, numbers) sit together in one stream. The header
  // is 32 bytes for the message itself, 24 for an embedded one, 8 elsewhere.
  if (fixed) {
    const headerSize = isTopLevel === true ? 32 : isTopLevel === "embedded" ? 24 : 8;
    const v = new DataView(fixed.buffer, fixed.byteOffset, fixed.byteLength);
    for (let at = headerSize; at + 16 <= fixed.length; at += 16) {
      const tag = v.getUint32(at, true);
      const id = (tag >>> 16).toString(16).toUpperCase().padStart(4, "0");
      const type = tag & 0xffff;
      if (type === 0x0003) props[id] ||= { type: "0003", value: v.getInt32(at + 8, true) };
      if (type === 0x0040) {
        const ticks = v.getUint32(at + 8, true) + v.getUint32(at + 12, true) * 2 ** 32;
        props[id] ||= { type: "0040", value: new Date(ticks / 10000 - 11644473600000) };
      }
    }
  }
  return { props, storages };
}

function propText(props, id, codepage) {
  const p = props[id];
  if (!p?.bytes) return "";
  let s;
  if (p.type === "001F") s = new TextDecoder("utf-16le").decode(p.bytes);
  else if (p.type === "001E" || p.type === "0102") s = decoderFor(codepage).decode(p.bytes);
  else return "";
  return s.replace(/\0+$/, "");
}

// ===== rebuilding the message =====

function base64Lines(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin).replace(/.{1,76}/g, "$&\r\n");
}
const utf8 = (s) => new TextEncoder().encode(s);
const quote = (s) => String(s).replace(/[\r\n"\\]/g, "_");
const encodedWord = (s) => (/^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${btoa(String.fromCharCode(...utf8(s)))}?=`);

/** A filename parameter that survives any characters (RFC 2231). */
function filenameParams(name) {
  if (/^[\x20-\x7e]*$/.test(name)) return `filename="${quote(name)}"`;
  return `filename*=UTF-8''${encodeURIComponent(name)}`;
}

const DROP_HEADERS = /^(content-type|content-transfer-encoding|mime-version|content-disposition)$/i;

function messageToEml(cfb, storage, level, depth) {
  const { props, storages } = readProperties(cfb, storage, level);
  const codepage = props["3FDE"]?.value || props["3FFD"]?.value || 1252;
  const text = (id) => propText(props, id, codepage);

  // Headers: the original Internet headers when the message came from outside;
  // otherwise rebuilt from the properties (internal or draft messages).
  let headerBlock = text("007D").replace(/\r?\n/g, "\r\n").replace(/(\r\n)+$/, "");
  if (headerBlock) {
    const kept = [];
    let skipping = false;
    for (const line of headerBlock.split("\r\n")) {
      if (/^[ \t]/.test(line)) {
        if (!skipping) kept.push(line);
        continue;
      }
      skipping = DROP_HEADERS.test(line.split(":")[0].trim());
      if (!skipping) kept.push(line);
    }
    headerBlock = kept.join("\r\n");
  } else {
    const senderName = text("0C1A") || text("0042");
    const senderEmail = text("5D01") || text("0C1F") || text("0065");
    const recipients = [];
    for (const s of storages.filter((s) => /^__recip_version1\.0_/i.test(s.name))) {
      const r = readProperties(cfb, s, false).props;
      const name = propText(r, "3001", codepage);
      const email = propText(r, "39FE", codepage) || propText(r, "3003", codepage);
      if (email) recipients.push(name && name !== email ? `"${quote(name)}" <${email}>` : `<${email}>`);
    }
    const date = props["0039"]?.value || props["0E06"]?.value;
    const lines = [];
    if (senderEmail) lines.push(`From: ${senderName ? `"${quote(encodedWord(senderName))}" ` : ""}<${senderEmail}>`);
    if (recipients.length) lines.push(`To: ${recipients.join(", ")}`);
    lines.push(`Subject: ${encodedWord(text("0037"))}`);
    if (date instanceof Date && !isNaN(date)) lines.push(`Date: ${date.toUTCString().replace("GMT", "+0000")}`);
    const id = text("1035");
    if (id) lines.push(`Message-ID: ${id}`);
    lines.push("X-Converted-From: Outlook .msg without Internet headers (sent internally or never sent)");
    headerBlock = lines.join("\r\n");
  }

  const boundary = (tag) => `=_msg_${tag}_${depth}_${Math.random().toString(36).slice(2, 10)}`;
  const mixed = boundary("mixed");
  const parts = [];

  const plain = text("1000");
  const htmlProp = props["1013"];
  const html = htmlProp ? propText(props, "1013", codepage) : "";
  // ponytail: bodies kept only as RTF (compressed RTF, 0x1009) are not decoded; plain/HTML are almost always present too.
  if (plain && html) {
    const alt = boundary("alt");
    parts.push(
      `Content-Type: multipart/alternative; boundary="${alt}"\r\n\r\n` +
        `--${alt}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${base64Lines(utf8(plain))}` +
        `--${alt}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${base64Lines(utf8(html))}` +
        `--${alt}--\r\n`,
    );
  } else if (html || plain) {
    parts.push(`Content-Type: text/${html ? "html" : "plain"}; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${base64Lines(utf8(html || plain))}`);
  }

  for (const s of storages.filter((s) => /^__attach_version1\.0_/i.test(s.name))) {
    const a = readProperties(cfb, s, false);
    const at = (id) => propText(a.props, id, codepage);
    let name = at("3707") || at("3704") || at("3001") || "attachment";
    let mime = at("370E") || "application/octet-stream";
    const cid = at("3712");
    let data = a.props["3701"]?.bytes;
    // An attached Outlook item is a whole message in a sub-storage.
    const embedded = a.storages.find((x) => x.name === "__substg1.0_3701000D");
    if (embedded && depth < 3) {
      data = utf8(messageToEml(cfb, embedded, "embedded", depth + 1));
      mime = "message/rfc822";
      if (!/\.eml$/i.test(name)) name = `${name.replace(/\.msg$/i, "")}.eml`;
    }
    if (!data) continue;
    const disposition = cid ? "inline" : "attachment";
    parts.push(
      `Content-Type: ${mime.replace(/[\r\n;"]/g, "")}; name="${quote(name)}"\r\n` +
        `Content-Disposition: ${disposition}; ${filenameParams(name)}\r\n` +
        (cid ? `Content-ID: <${cid.replace(/^<|>$/g, "").replace(/[\r\n<>]/g, "")}>\r\n` : "") +
        `Content-Transfer-Encoding: base64\r\n\r\n${base64Lines(data)}`,
    );
  }

  const bodyBlock = parts.map((p) => `--${mixed}\r\n${p}`).join("") + `--${mixed}--\r\n`;
  return `${headerBlock}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="${mixed}"\r\n\r\n${bodyBlock}`;
}

/**
 * Convert an Outlook .msg file to an RFC 822 message.
 * @param {Uint8Array} bytes
 * @returns {string} the message source
 */
export function msgToEml(bytes) {
  const cfb = readCompoundFile(bytes);
  return messageToEml(cfb, cfb.root, true, 0);
}

/** The source of an uploaded email file, whichever format it is in. */
export async function readEmailFile(file) {
  if (/\.msg$/i.test(file.name || "")) return msgToEml(new Uint8Array(await file.arrayBuffer()));
  return file.text();
}
