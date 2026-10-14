// Reading uploaded files: an .eml, .msg or .txt as it is, or the emails inside
// an archive — ZIP, 7z or gzip, password-protected or not.
//
// Security tools and mail admins hand suspicious emails over in an encrypted
// archive, so nothing on the way deletes or opens them. The archive is
// decrypted here, in the browser, with "infected" tried first — the
// convention for malware samples — and the analyst asked for the password
// only when that fails. Anything that is not an email is named and refused,
// never pasted into the input box as binary.

import { readZipDirectory, readZipEntry, inflate } from "./inspect-files.js";
import { read7z, is7z, PasswordRequired, WrongPassword } from "./sevenzip.js";
import { msgToEml, isMsgFile } from "./msg-parser.js";
import { sniffFileType } from "./file-type.js";

const EMAIL_FILE = /\.(eml|msg|txt)$/i;
const ARCHIVE_FILE = /\.(zip|7z|gz)$/i;
const DEFAULT_PASSWORDS = ["infected"];
const MAX_DEPTH = 2; // an archive inside an archive inside the upload

const isZip = (b) => b[0] === 0x50 && b[1] === 0x4b && b[2] === 3 && b[3] === 4;
const isGzip = (b) => b[0] === 0x1f && b[1] === 0x8b;

/**
 * Binary that is not an email: NUL bytes, or a known file signature, in the
 * first few kilobytes. UTF-8 text (bytes ≥ 0x80) is not binary.
 */
function notAnEmail(name, bytes) {
  const head = bytes.subarray(0, 4096);
  if (!head.includes(0)) return null;
  const kind = sniffFileType(bytes)?.label;
  if (/RAR/.test(kind || "")) return `${name} is a RAR archive, which the browser cannot open — extract it with 7-Zip or WinRAR and upload the email inside`;
  return `${name} is ${kind ? `a ${kind}` : "binary data"}, not an email`;
}

function emailText(name, bytes) {
  if (/\.msg$/i.test(name) || isMsgFile(bytes)) return msgToEml(bytes);
  const problem = notAnEmail(name, bytes);
  if (problem) throw new Error(problem);
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

/**
 * Open a password-protected archive: no password, then "infected", then ask
 * until it opens or the analyst cancels (null).
 */
async function withPassword(name, attempt, askPassword) {
  for (const password of [null, ...DEFAULT_PASSWORDS]) {
    const result = await attempt(password);
    if (result) return result;
  }
  for (let wrong = false; ; wrong = true) {
    const answer = await askPassword(name, wrong);
    if (answer == null) return null;
    const result = await attempt(answer);
    if (result) return result;
  }
}

/** Files out of a ZIP: those that are emails or further archives. */
async function fromZip(name, bytes, askPassword) {
  const dir = readZipDirectory(bytes);
  if (!dir) throw new Error(`${name} is not a readable ZIP archive`);
  const entries = dir.entries.filter((e) => !e.name.endsWith("/") && (EMAIL_FILE.test(e.name) || ARCHIVE_FILE.test(e.name))).slice(0, 200);
  if (!entries.length) throw new Error(`${name} holds no .eml, .msg or .txt file`);
  const locked = entries.find((e) => e.encrypted);
  return withPassword(
    name,
    async (password) => {
      if (locked && (password == null || !(await readZipEntry(bytes, locked, password)))) return null;
      const files = [];
      for (const e of entries) {
        const content = await readZipEntry(bytes, e, e.encrypted ? password : null);
        if (content) files.push({ name: e.name.split("/").pop(), bytes: content });
      }
      return files;
    },
    askPassword,
  );
}

/** Files out of a 7z, header-encrypted or not. */
async function from7z(name, bytes, askPassword) {
  const wanted = (n) => EMAIL_FILE.test(n) || ARCHIVE_FILE.test(n);
  const files = await withPassword(
    name,
    async (password) => {
      try {
        return await read7z(bytes, password, wanted);
      } catch (err) {
        if (err instanceof PasswordRequired || err instanceof WrongPassword) return null;
        throw err;
      }
    },
    askPassword,
  );
  if (!files) return null;
  const found = files.filter((f) => f.bytes && wanted(f.name));
  if (!found.length) throw new Error(`${name} holds no .eml, .msg or .txt file`);
  return found.map((f) => ({ name: f.name.split(/[\\/]/).pop(), bytes: f.bytes }));
}

/** The emails in one file's bytes, opening archives (and archives inside them). */
async function emailsFromBytes(name, bytes, askPassword, depth, archive) {
  let files = null;
  if (depth < MAX_DEPTH && isGzip(bytes)) {
    const inner = await inflate(bytes, "gzip", 100 * 1024 * 1024);
    if (!inner) throw new Error(`${name} is a damaged gzip file`);
    files = [{ name: name.replace(/\.gz$/i, "") || "content", bytes: inner }];
  } else if (depth < MAX_DEPTH && isZip(bytes)) {
    files = await fromZip(name, bytes, askPassword);
  } else if (depth < MAX_DEPTH && is7z(bytes)) {
    files = await from7z(name, bytes, askPassword);
  } else {
    return [{ name, text: emailText(name, bytes), ...(archive ? { archive } : {}) }];
  }
  if (!files) return []; // cancelled
  const label = archive ? `${archive} › ${name}` : name;
  const emails = [];
  for (const f of files) emails.push(...(await emailsFromBytes(f.name, f.bytes, askPassword, depth + 1, label)));
  return emails;
}

/**
 * The email(s) in one uploaded file.
 * @param {File} file
 * @param {(archive: string, wrongBefore: boolean) => Promise<string|null>} askPassword
 *   resolves to the password typed, or null when the analyst cancels
 * @returns {Promise<Array<{name: string, text: string, archive?: string}>>}
 */
export async function emailsFromUpload(file, askPassword) {
  return emailsFromBytes(file.name, new Uint8Array(await file.arrayBuffer()), askPassword, 0, null);
}

/**
 * Ask for an archive's password in a small dialog (built on first use, so
 * every page that reads uploads gets it). Resolves to null on Cancel.
 */
export function askZipPassword(archive, wrongBefore) {
  let dialog = document.getElementById("zip-password-dialog");
  if (!dialog) {
    dialog = document.createElement("dialog");
    dialog.id = "zip-password-dialog";
    dialog.className = "zip-dialog";
    dialog.innerHTML = `<form>
      <h3>Password-protected archive</h3>
      <p class="zip-dialog-text"></p>
      <input type="password" name="password" autocomplete="off" spellcheck="false" aria-label="Archive password" />
      <p class="zip-dialog-error" hidden>Wrong password — try again.</p>
      <p class="zip-dialog-note">Decrypted in this browser; the password and the file go nowhere.</p>
      <div class="zip-dialog-actions">
        <button type="button" class="btn btn-secondary zip-dialog-cancel">Cancel</button>
        <button type="submit" class="btn btn-primary">Open</button>
      </div>
    </form>`;
    // The page's CSP forbids form submission (form-action 'none'), and a
    // blocked <form method="dialog"> closes without a "close" event — the
    // caller would wait for ever. So nothing is submitted: Open and Enter are
    // handled here, and the answer is handed over directly.
    dialog.querySelector("form").addEventListener("submit", (e) => {
      e.preventDefault();
      dialog.dispatchEvent(new CustomEvent("answer", { detail: dialog.querySelector("input").value }));
    });
    dialog.querySelector(".zip-dialog-cancel").addEventListener("click", () => dialog.dispatchEvent(new CustomEvent("answer", { detail: null })));
    // Escape closes the dialog by itself; that counts as Cancel.
    dialog.addEventListener("cancel", (e) => {
      e.preventDefault();
      dialog.dispatchEvent(new CustomEvent("answer", { detail: null }));
    });
    document.body.append(dialog);
  }
  const input = dialog.querySelector("input");
  dialog.querySelector(".zip-dialog-text").textContent = `"${archive}" is encrypted, and "infected" did not open it. Enter its password.`;
  dialog.querySelector(".zip-dialog-error").hidden = !wrongBefore;
  input.value = "";
  return new Promise((resolve) => {
    dialog.addEventListener(
      "answer",
      (e) => {
        dialog.close();
        resolve(e.detail);
      },
      { once: true },
    );
    dialog.showModal();
    input.focus();
  });
}
