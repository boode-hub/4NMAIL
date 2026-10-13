// AES block encryption (FIPS-197) and WinZip AES decryption.
//
// Password-protected ZIPs come in two kinds: the old ZipCrypto cipher
// (inspect-files.js) and WinZip AES, which 7-Zip, WinZip and most security
// tools use. WinZip AES is AES in counter mode with a little-endian counter;
// the browser's AES-CTR counts big-endian, so the keystream is generated here
// from the block cipher. Key derivation (PBKDF2) and the integrity check
// (HMAC-SHA1) use the browser's own Web Crypto.

const SBOX = new Uint8Array(256);
{
  // The S-box from its definition: the multiplicative inverse in GF(2^8)
  // followed by the affine transform — generated, not pasted, so no table typo.
  const rotl = (x, s) => ((x << s) | (x >> (8 - s))) & 0xff;
  let p = 1;
  let q = 1;
  do {
    p = (p ^ (p << 1) ^ (p & 0x80 ? 0x1b : 0)) & 0xff; // p × 3
    q ^= q << 1; // q ÷ 3
    q ^= q << 2;
    q ^= q << 4;
    q &= 0xff;
    if (q & 0x80) q ^= 0x09;
    SBOX[p] = q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4) ^ 0x63;
  } while (p !== 1);
  SBOX[0] = 0x63;
}

const xtime = (b) => ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff;

/** Round keys for a 16-, 24- or 32-byte key. */
export function expandKey(key) {
  const nk = key.length / 4;
  const rounds = nk + 6;
  const w = new Uint8Array(16 * (rounds + 1));
  w.set(key);
  let rcon = 1;
  for (let i = nk; i < 4 * (rounds + 1); i++) {
    let t = [w[i * 4 - 4], w[i * 4 - 3], w[i * 4 - 2], w[i * 4 - 1]];
    if (i % nk === 0) {
      t = [SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]];
      rcon = xtime(rcon);
    } else if (nk > 6 && i % nk === 4) {
      t = t.map((b) => SBOX[b]);
    }
    for (let j = 0; j < 4; j++) w[i * 4 + j] = w[(i - nk) * 4 + j] ^ t[j];
  }
  return { w, rounds };
}

/** Encrypt one 16-byte block. */
export function encryptBlock({ w, rounds }, input, out = new Uint8Array(16)) {
  const s = new Uint8Array(16);
  const t = new Uint8Array(16);
  for (let i = 0; i < 16; i++) s[i] = input[i] ^ w[i];
  for (let round = 1; round <= rounds; round++) {
    // SubBytes and ShiftRows together; the state is column-major.
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) t[c * 4 + r] = SBOX[s[((c + r) % 4) * 4 + r]];
    }
    if (round < rounds) {
      for (let c = 0; c < 4; c++) {
        const a0 = t[c * 4];
        const a1 = t[c * 4 + 1];
        const a2 = t[c * 4 + 2];
        const a3 = t[c * 4 + 3];
        const x = a0 ^ a1 ^ a2 ^ a3;
        t[c * 4] = a0 ^ x ^ xtime(a0 ^ a1);
        t[c * 4 + 1] = a1 ^ x ^ xtime(a1 ^ a2);
        t[c * 4 + 2] = a2 ^ x ^ xtime(a2 ^ a3);
        t[c * 4 + 3] = a3 ^ x ^ xtime(a3 ^ a0);
      }
    }
    for (let i = 0; i < 16; i++) s[i] = t[i] ^ w[round * 16 + i];
  }
  out.set(s);
  return out;
}

const KEY_LENGTH = { 1: 16, 2: 24, 3: 32 }; // WinZip AES strength → key bytes

/**
 * Decrypt a WinZip AES entry (salt ‖ 2-byte check ‖ data ‖ 10-byte HMAC).
 * Returns the still-compressed data, or null when the password is wrong or
 * the content was altered.
 */
export async function winZipAesDecrypt(raw, password, strength) {
  const keyLength = KEY_LENGTH[strength];
  const saltLength = keyLength / 2;
  if (!keyLength || raw.length < saltLength + 2 + 10) return null;
  const salt = raw.subarray(0, saltLength);
  const check = raw.subarray(saltLength, saltLength + 2);
  const data = raw.subarray(saltLength + 2, raw.length - 10);
  const mac = raw.subarray(raw.length - 10);

  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const derived = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-1", salt, iterations: 1000 }, material, (keyLength * 2 + 2) * 8),
  );
  // The two-byte check rejects most wrong passwords before any decryption.
  if (derived[keyLength * 2] !== check[0] || derived[keyLength * 2 + 1] !== check[1]) return null;

  // The HMAC over the encrypted data proves the password and the content.
  const hmacKey = await crypto.subtle.importKey("raw", derived.subarray(keyLength, keyLength * 2), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, data)).subarray(0, 10);
  if (!expected.every((b, i) => b === mac[i])) return null;

  const key = expandKey(derived.subarray(0, keyLength));
  const out = new Uint8Array(data.length);
  const counter = new Uint8Array(16);
  const stream = new Uint8Array(16);
  for (let block = 0, at = 0; at < data.length; block++, at += 16) {
    // Little-endian block counter, starting at 1.
    let n = block + 1;
    for (let i = 0; i < 8; i++) {
      counter[i] = n & 0xff;
      n = Math.floor(n / 256);
    }
    encryptBlock(key, counter, stream);
    const end = Math.min(16, data.length - at);
    for (let i = 0; i < end; i++) out[at + i] = data[at + i] ^ stream[i];
  }
  return out;
}
