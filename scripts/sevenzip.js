// 7-Zip (.7z) archives, read in the browser.
//
// Suspicious emails are often handed over as a password-protected .7z — the
// format 7-Zip itself defaults to. Its pieces: a small container format, LZMA
// and LZMA2 compression, and 7-Zip's AES-256 (SHA-256-stretched password,
// AES in CBC mode), optionally applied to the file list as well ("encrypt
// file names"). All of it is implemented here; nothing is uploaded.
//
// References: 7-Zip's 7zFormat.txt and the LZMA specification (lzma-specification.txt).

import { crc32 } from "./file-export.js";

const SIGNATURE = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const MAX_OUTPUT = 200 * 1024 * 1024; // ponytail: whole folders are decoded in memory; stream if bigger archives matter

export class PasswordRequired extends Error {}
export class WrongPassword extends Error {}

export function is7z(bytes) {
  return bytes?.length >= 32 && SIGNATURE.every((b, i) => bytes[i] === b);
}

// ===== LZMA =====

class RangeDecoder {
  constructor(buf, pos, end) {
    this.buf = buf;
    this.pos = pos + 1; // the first byte is always 0
    this.end = end;
    this.range = 0xffffffff;
    this.code = 0;
    for (let i = 0; i < 4; i++) this.code = this.code * 256 + this.next();
  }
  next() {
    if (this.pos >= this.end) throw new Error("LZMA data ends early");
    return this.buf[this.pos++];
  }
  normalize() {
    if (this.range < 0x1000000) {
      this.range *= 256;
      this.code = this.code * 256 + this.next();
    }
  }
  bit(probs, i) {
    const p = probs[i];
    const bound = (this.range >>> 11) * p;
    let b;
    if (this.code < bound) {
      this.range = bound;
      probs[i] = p + ((2048 - p) >>> 5);
      b = 0;
    } else {
      this.range -= bound;
      this.code -= bound;
      probs[i] = p - (p >>> 5);
      b = 1;
    }
    this.normalize();
    return b;
  }
  direct(count) {
    let result = 0;
    for (; count > 0; count--) {
      this.range = this.range >>> 1;
      let b = 0;
      if (this.code >= this.range) {
        this.code -= this.range;
        b = 1;
      }
      result = result * 2 + b;
      this.normalize();
    }
    return result;
  }
  tree(probs, offset, bits) {
    let m = 1;
    for (let i = 0; i < bits; i++) m = m * 2 + this.bit(probs, offset + m);
    return m - (1 << bits);
  }
  reverseTree(probs, offset, bits) {
    let m = 1;
    let symbol = 0;
    for (let i = 0; i < bits; i++) {
      const b = this.bit(probs, offset + m);
      m = m * 2 + b;
      symbol |= b << i;
    }
    return symbol;
  }
}

class LenDecoder {
  constructor() {
    this.choice = new Uint16Array(2).fill(1024);
    this.low = new Uint16Array(16 << 3).fill(1024);
    this.mid = new Uint16Array(16 << 3).fill(1024);
    this.high = new Uint16Array(256).fill(1024);
  }
  decode(rc, posState) {
    if (!rc.bit(this.choice, 0)) return rc.tree(this.low, posState << 3, 3);
    if (!rc.bit(this.choice, 1)) return 8 + rc.tree(this.mid, posState << 3, 3);
    return 16 + rc.tree(this.high, 0, 8);
  }
}

/**
 * An LZMA decoder writing into one output buffer, which doubles as the
 * dictionary — fine when the whole stream is decoded in memory. LZMA2 drives
 * it chunk by chunk, keeping the output (and, if told to, the state).
 */
class LzmaDecoder {
  constructor(out) {
    this.out = out;
    this.outPos = 0;
  }
  setProps(lc, lp, pb) {
    if (lc > 8 || lp > 4 || pb > 4) throw new Error("bad LZMA properties");
    this.lc = lc;
    this.lp = lp;
    this.pb = pb;
  }
  resetState() {
    const p = (n) => new Uint16Array(n).fill(1024);
    this.literal = p(0x300 << (this.lc + this.lp));
    this.isMatch = p(12 << 4);
    this.isRep = p(12);
    this.isRepG0 = p(12);
    this.isRepG1 = p(12);
    this.isRepG2 = p(12);
    this.isRep0Long = p(12 << 4);
    this.posSlot = p(4 << 6);
    this.posDecoders = p(115);
    this.align = p(16);
    this.len = new LenDecoder();
    this.repLen = new LenDecoder();
    this.state = 0;
    this.reps = [0, 0, 0, 0];
  }
  distance(rc, len) {
    const lenState = Math.min(len, 3);
    const slot = rc.tree(this.posSlot, lenState << 6, 6);
    if (slot < 4) return slot;
    const directBits = (slot >>> 1) - 1;
    let dist = (2 | (slot & 1)) * 2 ** directBits;
    if (slot < 14) return dist + rc.reverseTree(this.posDecoders, dist - slot, directBits);
    dist += rc.direct(directBits - 4) * 16;
    return dist + rc.reverseTree(this.align, 0, 4);
  }
  /** Decode until `end` bytes of output exist (or an end marker). */
  decode(rc, end) {
    const out = this.out;
    const pbMask = (1 << this.pb) - 1;
    const lpMask = (1 << this.lp) - 1;
    let { state, outPos } = this;
    let [rep0, rep1, rep2, rep3] = this.reps;
    while (outPos < end) {
      const posState = outPos & pbMask;
      if (!rc.bit(this.isMatch, (state << 4) + posState)) {
        const prev = outPos > 0 ? out[outPos - 1] : 0;
        const base = 0x300 * (((outPos & lpMask) << this.lc) + (prev >>> (8 - this.lc)));
        let symbol = 1;
        if (state >= 7) {
          if (rep0 >= outPos) throw new Error("LZMA distance before start");
          let match = out[outPos - rep0 - 1];
          do {
            const matchBit = (match >>> 7) & 1;
            match <<= 1;
            const b = rc.bit(this.literal, base + ((1 + matchBit) << 8) + symbol);
            symbol = (symbol << 1) | b;
            if (matchBit !== b) break;
          } while (symbol < 0x100);
        }
        while (symbol < 0x100) symbol = (symbol << 1) | rc.bit(this.literal, base + symbol);
        out[outPos++] = symbol - 0x100;
        state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
        continue;
      }
      let len;
      if (rc.bit(this.isRep, state)) {
        if (outPos === 0) throw new Error("LZMA repeat at start");
        if (!rc.bit(this.isRepG0, state)) {
          if (!rc.bit(this.isRep0Long, (state << 4) + posState)) {
            state = state < 7 ? 9 : 11;
            out[outPos] = out[outPos - rep0 - 1];
            outPos++;
            continue;
          }
        } else {
          let dist;
          if (!rc.bit(this.isRepG1, state)) dist = rep1;
          else {
            if (!rc.bit(this.isRepG2, state)) dist = rep2;
            else {
              dist = rep3;
              rep3 = rep2;
            }
            rep2 = rep1;
          }
          rep1 = rep0;
          rep0 = dist;
        }
        len = this.repLen.decode(rc, posState);
        state = state < 7 ? 8 : 11;
      } else {
        rep3 = rep2;
        rep2 = rep1;
        rep1 = rep0;
        len = this.len.decode(rc, posState);
        state = state < 7 ? 7 : 10;
        rep0 = this.distance(rc, len);
        if (rep0 === 0xffffffff) break; // end marker
      }
      len += 2;
      if (rep0 >= outPos) throw new Error("LZMA distance before start");
      const stop = Math.min(outPos + len, end);
      for (; outPos < stop; outPos++) out[outPos] = out[outPos - rep0 - 1];
    }
    Object.assign(this, { state, outPos, reps: [rep0, rep1, rep2, rep3] });
  }
}

function lzma(input, props, size) {
  const d = props[0];
  if (d >= 9 * 5 * 5) throw new Error("bad LZMA properties");
  const decoder = new LzmaDecoder(new Uint8Array(size));
  decoder.setProps(d % 9, Math.floor(d / 9) % 5, Math.floor(d / 45));
  decoder.resetState();
  decoder.decode(new RangeDecoder(input, 0, input.length), size);
  return decoder.out;
}

function lzma2(input, size) {
  const decoder = new LzmaDecoder(new Uint8Array(size));
  let pos = 0;
  let needProps = true;
  while (pos < input.length) {
    const control = input[pos++];
    if (control === 0) break;
    if (control === 1 || control === 2) {
      // Stored chunk.
      const length = (input[pos] << 8 | input[pos + 1]) + 1;
      pos += 2;
      if (decoder.outPos + length > size || pos + length > input.length) throw new Error("LZMA2 chunk out of bounds");
      decoder.out.set(input.subarray(pos, pos + length), decoder.outPos);
      decoder.outPos += length;
      pos += length;
      continue;
    }
    if (control < 0x80) throw new Error("bad LZMA2 chunk");
    const unpacked = ((control & 0x1f) << 16) + (input[pos] << 8) + input[pos + 1] + 1;
    const packed = (input[pos + 2] << 8) + input[pos + 3] + 1;
    pos += 4;
    const reset = (control >>> 5) & 3;
    if (reset >= 2) {
      const d = input[pos++];
      decoder.setProps(d % 9, Math.floor(d / 9) % 5, Math.floor(d / 45));
      needProps = false;
    } else if (needProps) throw new Error("LZMA2 chunk without properties");
    if (reset >= 1) decoder.resetState();
    if (decoder.outPos + unpacked > size) throw new Error("LZMA2 chunk out of bounds");
    decoder.decode(new RangeDecoder(input, pos, pos + packed), decoder.outPos + unpacked);
    pos += packed;
  }
  return decoder.out.subarray(0, decoder.outPos);
}

// ===== 7-Zip AES =====

async function sevenZipAes(input, props, password, size) {
  if (password == null) throw new PasswordRequired("This archive is password-protected");
  const b0 = props[0];
  const cycles = b0 & 0x3f;
  let salt = new Uint8Array();
  const iv = new Uint8Array(16);
  if (b0 & 0xc0) {
    const b1 = props[1];
    const saltSize = ((b0 >>> 7) & 1) + (b1 >>> 4);
    const ivSize = ((b0 >>> 6) & 1) + (b1 & 0x0f);
    salt = props.subarray(2, 2 + saltSize);
    iv.set(props.subarray(2 + saltSize, 2 + saltSize + ivSize));
  }
  const pw = new Uint8Array(password.length * 2);
  for (let i = 0; i < password.length; i++) {
    pw[i * 2] = password.charCodeAt(i) & 0xff;
    pw[i * 2 + 1] = password.charCodeAt(i) >>> 8;
  }
  let key;
  if (cycles === 0x3f) {
    key = new Uint8Array(32);
    key.set([...salt, ...pw].slice(0, 32));
  } else {
    // SHA-256 over 2^cycles repetitions of salt ‖ password ‖ 64-bit counter,
    // hashed as one stream — the same digest as feeding it piece by piece.
    const unit = salt.length + pw.length + 8;
    const rounds = 2 ** cycles;
    if (unit * rounds > 256 * 1024 * 1024) throw new Error("7z key stretching too large to compute here");
    const stream = new Uint8Array(unit * rounds);
    for (let r = 0, at = 0; r < rounds; r++, at += unit) {
      stream.set(salt, at);
      stream.set(pw, at + salt.length);
      let n = r;
      for (let i = 0; i < 8 && n; i++) {
        stream[at + salt.length + pw.length + i] = n & 0xff;
        n = Math.floor(n / 256);
      }
    }
    key = new Uint8Array(await crypto.subtle.digest("SHA-256", stream));
  }
  if (input.length % 16) throw new WrongPassword("Encrypted data is not whole blocks");
  // 7-Zip pads with zeros, Web Crypto expects PKCS#7. One extra block that
  // decrypts to sixteen 0x10 bytes makes the padding valid.
  const aesKey = await crypto.subtle.importKey("raw", key, "AES-CBC", false, ["encrypt", "decrypt"]);
  const last = input.length ? input.subarray(input.length - 16) : iv;
  const pad = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv: last }, aesKey, new Uint8Array(16).fill(16))).subarray(0, 16);
  const padded = new Uint8Array(input.length + 16);
  padded.set(input);
  padded.set(pad, input.length);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aesKey, padded));
  return plain.subarray(0, size);
}

// ===== container =====

class Reader {
  constructor(bytes) {
    this.b = bytes;
    this.p = 0;
  }
  byte() {
    if (this.p >= this.b.length) throw new Error("7z header ends early");
    return this.b[this.p++];
  }
  number() {
    const first = this.byte();
    let mask = 0x80;
    let value = 0;
    for (let i = 0; i < 8; i++) {
      if (!(first & mask)) return value + (first & (mask - 1)) * 2 ** (8 * i);
      value += this.byte() * 2 ** (8 * i);
      mask >>>= 1;
    }
    return value;
  }
  bytes(n) {
    if (this.p + n > this.b.length) throw new Error("7z header ends early");
    const out = this.b.subarray(this.p, this.p + n);
    this.p += n;
    return out;
  }
  u32() {
    const v = this.b[this.p] | (this.b[this.p + 1] << 8) | (this.b[this.p + 2] << 16) | (this.b[this.p + 3] << 24);
    this.p += 4;
    return v >>> 0;
  }
  bits(n) {
    const out = [];
    let mask = 0;
    let byte = 0;
    for (let i = 0; i < n; i++) {
      if (!mask) {
        byte = this.byte();
        mask = 0x80;
      }
      out.push(!!(byte & mask));
      mask >>>= 1;
    }
    return out;
  }
  digests(n) {
    const defined = this.byte() ? new Array(n).fill(true) : this.bits(n);
    return defined.map((d) => (d ? this.u32() : null));
  }
}

function readFolder(r) {
  const coders = [];
  for (let n = r.number(); n > 0; n--) {
    const flags = r.byte();
    const id = [...r.bytes(flags & 0x0f)].map((b) => b.toString(16).padStart(2, "0")).join("");
    const ins = flags & 0x10 ? r.number() : 1;
    const outs = flags & 0x10 ? r.number() : 1;
    const props = flags & 0x20 ? r.bytes(r.number()) : new Uint8Array();
    coders.push({ id, ins, outs, props });
  }
  const totalOut = coders.reduce((s, c) => s + c.outs, 0);
  const totalIn = coders.reduce((s, c) => s + c.ins, 0);
  const bindPairs = [];
  for (let i = 0; i < totalOut - 1; i++) bindPairs.push({ in: r.number(), out: r.number() });
  const packedCount = totalIn - bindPairs.length;
  const packed = [];
  if (packedCount === 1) {
    for (let i = 0; i < totalIn; i++) if (!bindPairs.some((b) => b.in === i)) packed.push(i);
  } else {
    for (let i = 0; i < packedCount; i++) packed.push(r.number());
  }
  return { coders, bindPairs, packed, unpackSizes: [] };
}

function readStreamsInfo(r) {
  const info = { packPos: 0, packSizes: [], folders: [], substreams: null };
  for (let id = r.byte(); id !== 0x00; id = r.byte()) {
    if (id === 0x06) {
      info.packPos = r.number();
      const n = r.number();
      for (let t = r.byte(); t !== 0x00; t = r.byte()) {
        if (t === 0x09) for (let i = 0; i < n; i++) info.packSizes.push(r.number());
        else if (t === 0x0a) r.digests(n);
        else throw new Error(`unknown 7z pack property ${t}`);
      }
    } else if (id === 0x07) {
      if (r.byte() !== 0x0b) throw new Error("7z folder list missing");
      const n = r.number();
      if (r.byte() !== 0) throw new Error("external 7z folders are not supported");
      for (let i = 0; i < n; i++) info.folders.push(readFolder(r));
      if (r.byte() !== 0x0c) throw new Error("7z unpack sizes missing");
      for (const f of info.folders) for (const c of f.coders) for (let o = 0; o < c.outs; o++) f.unpackSizes.push(r.number());
      for (let t = r.byte(); t !== 0x00; t = r.byte()) {
        if (t === 0x0a) r.digests(info.folders.length).forEach((crc, i) => (info.folders[i].crc = crc));
        else throw new Error(`unknown 7z folder property ${t}`);
      }
    } else if (id === 0x08) {
      const counts = info.folders.map(() => 1);
      const sizes = [];
      const crcs = [];
      let t = r.byte();
      if (t === 0x0d) {
        for (let i = 0; i < counts.length; i++) counts[i] = r.number();
        t = r.byte();
      }
      const folderSize = (f) => f.unpackSizes[mainOutput(f)];
      if (t === 0x09) {
        info.folders.forEach((f, i) => {
          let used = 0;
          for (let k = 1; k < counts[i]; k++) {
            const s = r.number();
            sizes.push(s);
            used += s;
          }
          if (counts[i]) sizes.push(folderSize(f) - used);
        });
        t = r.byte();
      } else {
        info.folders.forEach((f, i) => counts[i] === 1 && sizes.push(folderSize(f)));
      }
      // CRCs are listed for streams whose CRC is not already the folder's.
      const unknown = info.folders.reduce((n, f, i) => n + (counts[i] === 1 && f.crc != null ? 0 : counts[i]), 0);
      while (t !== 0x00) {
        if (t === 0x0a) {
          const listed = r.digests(unknown);
          let k = 0;
          info.folders.forEach((f, i) => {
            for (let s = 0; s < counts[i]; s++) crcs.push(counts[i] === 1 && f.crc != null ? f.crc : listed[k++]);
          });
        } else throw new Error(`unknown 7z substream property ${t}`);
        t = r.byte();
      }
      info.substreams = { counts, sizes, crcs };
    } else {
      throw new Error(`unknown 7z streams property ${id}`);
    }
  }
  return info;
}

/** The out stream no bind pair consumes: the folder's result. */
function mainOutput(folder) {
  const total = folder.coders.reduce((s, c) => s + c.outs, 0);
  for (let o = 0; o < total; o++) if (!folder.bindPairs.some((b) => b.out === o)) return o;
  throw new Error("7z folder has no output");
}

const METHODS = { "00": "Copy", "030101": "LZMA", 21: "LZMA2", "06f10701": "AES", "03030103": "BCJ", "0303011b": "BCJ2", "040108": "Deflate", "030401": "PPMd" };

/** Decode one folder: follow the coder chain from its output back to the packed data. */
async function decodeFolder(bytes, info, folderIndex, password, limit = MAX_OUTPUT) {
  const folder = info.folders[folderIndex];
  let packIndex = info.folders.slice(0, folderIndex).reduce((n, f) => n + f.packed.length, 0);
  let offset = 32 + info.packPos;
  for (let i = 0; i < packIndex; i++) offset += info.packSizes[i];
  const packedData = folder.packed.map((_, k) => {
    const start = offset;
    offset += info.packSizes[packIndex + k];
    if (offset > bytes.length) throw new Error("7z archive is truncated");
    return bytes.subarray(start, offset);
  });
  // Coder index ↔ stream index: each coder takes its share of in/out streams in order.
  const firstIn = [];
  const firstOut = [];
  folder.coders.reduce(([i, o], c, k) => ((firstIn[k] = i), (firstOut[k] = o), [i + c.ins, o + c.outs]), [0, 0]);

  const produce = async (outIndex) => {
    const k = firstOut.findIndex((start, idx) => outIndex >= start && outIndex < start + folder.coders[idx].outs);
    const coder = folder.coders[k];
    if (coder.ins !== 1 || coder.outs !== 1) throw new Error(`7z method ${METHODS[coder.id] || coder.id} is not supported`);
    const inIndex = firstIn[k];
    const bound = folder.bindPairs.find((b) => b.in === inIndex);
    const input = bound ? await produce(bound.out) : packedData[folder.packed.indexOf(inIndex)];
    const size = folder.unpackSizes[outIndex];
    if (size > limit) throw new Error("7z content too large to open here");
    switch (coder.id) {
      case "00":
        return input.subarray(0, size);
      case "030101":
        return lzma(input, coder.props, size);
      case "21":
        return lzma2(input, size);
      case "06f10701":
        return sevenZipAes(input, coder.props, password, size);
      default:
        throw new Error(`7z method ${METHODS[coder.id] || coder.id} is not supported`);
    }
  };

  const encrypted = folder.coders.some((c) => c.id === "06f10701");
  let out;
  try {
    out = await produce(mainOutput(folder));
  } catch (err) {
    // Garbage from a wrong key usually breaks decompression before the CRC.
    if (encrypted && !(err instanceof PasswordRequired)) throw new WrongPassword("Wrong password");
    throw err;
  }
  if (folder.crc != null && crc32(out) !== folder.crc) {
    throw encrypted ? new WrongPassword("Wrong password") : new Error("7z data is corrupt (CRC mismatch)");
  }
  return out;
}

function readFilesInfo(r) {
  const count = r.number();
  const files = Array.from({ length: count }, () => ({ name: "", emptyStream: false, emptyFile: false }));
  let emptyStreams = 0;
  for (let type = r.byte(); type !== 0x00; type = r.byte()) {
    const size = r.number();
    const end = r.p + size;
    if (type === 0x0e) {
      r.bits(count).forEach((v, i) => (files[i].emptyStream = v));
      emptyStreams = files.filter((f) => f.emptyStream).length;
    } else if (type === 0x0f) {
      const flags = r.bits(emptyStreams);
      files.filter((f) => f.emptyStream).forEach((f, i) => (f.emptyFile = flags[i]));
    } else if (type === 0x11) {
      if (r.byte() !== 0) throw new Error("external 7z names are not supported");
      for (const f of files) {
        let name = "";
        for (let c = r.byte() | (r.byte() << 8); c; c = r.byte() | (r.byte() << 8)) name += String.fromCharCode(c);
        f.name = name;
      }
    }
    r.p = end;
  }
  return files;
}

/**
 * The files in a .7z archive.
 * @param {Uint8Array} bytes
 * @param {string|null} password
 * @param {(name: string) => boolean} [wanted] - extract only these (others are listed)
 * @param {number} [limit] - largest decompressed folder accepted, in bytes
 * @returns {Promise<Array<{name: string, size: number, bytes: Uint8Array|null}>>}
 * @throws {PasswordRequired} when a password is needed and none was given
 * @throws {WrongPassword} when the given password does not open it
 */
export async function read7z(bytes, password = null, wanted = () => true, limit = MAX_OUTPUT) {
  if (!is7z(bytes)) throw new Error("Not a 7z archive");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const nextOffset = Number(view.getBigUint64(12, true));
  const nextSize = Number(view.getBigUint64(20, true));
  if (32 + nextOffset + nextSize > bytes.length) throw new Error("7z archive is truncated");
  let header = bytes.subarray(32 + nextOffset, 32 + nextOffset + nextSize);

  // An encoded header (compressed, and encrypted when file names are) is
  // itself a folder to decode first.
  for (let guard = 0; header[0] === 0x17 && guard < 4; guard++) {
    const r = new Reader(header);
    r.byte();
    header = await decodeFolder(bytes, readStreamsInfo(r), 0, password);
  }
  const r = new Reader(header);
  if (r.byte() !== 0x01) throw new Error("7z header not recognised");
  let streams = { folders: [], packSizes: [], packPos: 0, substreams: null };
  let files = [];
  for (let id = r.byte(); id !== 0x00; id = r.byte()) {
    if (id === 0x02) for (let t = r.byte(); t !== 0; t = r.byte()) r.bytes(r.number());
    else if (id === 0x03) readStreamsInfo(r);
    else if (id === 0x04) streams = readStreamsInfo(r);
    else if (id === 0x05) files = readFilesInfo(r);
    else throw new Error(`unknown 7z header property ${id}`);
  }

  // Files with content take the folders' substreams in order.
  const sub = streams.substreams || { counts: streams.folders.map(() => 1), sizes: streams.folders.map((f) => f.unpackSizes[mainOutput(f)]), crcs: [] };
  const result = [];
  let fileIndex = 0;
  let streamIndex = 0;
  const nextContentFile = () => {
    while (fileIndex < files.length && files[fileIndex].emptyStream) {
      const f = files[fileIndex++];
      if (!f.emptyFile && f.name) continue; // a directory
      if (f.name) result.push({ name: f.name, size: 0, bytes: new Uint8Array() });
    }
    return files[fileIndex++];
  };
  for (let fi = 0; fi < streams.folders.length; fi++) {
    const count = sub.counts[fi];
    const names = [];
    for (let k = 0; k < count; k++) names.push(nextContentFile()?.name || `file${streamIndex + k}`);
    const needed = names.some((n) => wanted(n));
    const data = needed ? await decodeFolder(bytes, streams, fi, password, limit) : null;
    let at = 0;
    for (let k = 0; k < count; k++, streamIndex++) {
      const size = sub.sizes[streamIndex];
      let content = null;
      if (data && wanted(names[k])) {
        content = data.subarray(at, at + size);
        const crc = sub.crcs[streamIndex];
        if (crc != null && crc32(content) !== crc) throw new Error(`7z data for ${names[k]} is corrupt (CRC mismatch)`);
      }
      result.push({ name: names[k], size, bytes: content });
      at += size;
    }
  }
  while (fileIndex < files.length) nextContentFile();
  return result;
}
