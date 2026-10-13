// Reading uploaded files: an .eml, .msg or .txt as it is, or the emails inside
// a ZIP — password-protected or not.
//
// Security tools and mail admins hand suspicious emails over in an encrypted
// ZIP, so nothing on the way deletes or opens them. The archive is decrypted
// here, in the browser (ZipCrypto or WinZip AES), with "infected" tried
// first — the convention for malware samples — and the analyst asked for the
// password only when that fails.

import { readZipDirectory, readZipEntry } from "./inspect-files.js";
import { msgToEml, isMsgFile } from "./msg-parser.js";

const EMAIL_FILE = /\.(eml|msg|txt)$/i;
const DEFAULT_PASSWORDS = ["infected"];

function emailText(name, bytes) {
  return /\.msg$/i.test(name) || isMsgFile(bytes) ? msgToEml(bytes) : new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

/**
 * The email(s) in one uploaded file.
 * @param {File} file
 * @param {(archive: string, wrongBefore: boolean) => Promise<string|null>} askPassword
 *   resolves to the password typed, or null when the analyst cancels
 * @returns {Promise<Array<{name: string, text: string, archive?: string}>>}
 */
export async function emailsFromUpload(file, askPassword) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const dir = bytes[0] === 0x50 && bytes[1] === 0x4b ? readZipDirectory(bytes) : null;
  if (!dir) return [{ name: file.name, text: emailText(file.name, bytes) }];

  const entries = dir.entries.filter((e) => !e.name.endsWith("/") && EMAIL_FILE.test(e.name));
  if (!entries.length) throw new Error(`${file.name} holds no .eml, .msg or .txt file`);

  let password = null;
  const locked = entries.find((e) => e.encrypted);
  if (locked) {
    for (const guess of DEFAULT_PASSWORDS) {
      if (await readZipEntry(bytes, locked, guess)) {
        password = guess;
        break;
      }
    }
    for (let wrong = false; !password; wrong = true) {
      const answer = await askPassword(file.name, wrong);
      if (answer == null) return [];
      if (await readZipEntry(bytes, locked, answer)) password = answer;
    }
  }

  const emails = [];
  for (const entry of entries.slice(0, 200)) {
    const content = await readZipEntry(bytes, entry, entry.encrypted ? password : null);
    if (content) emails.push({ name: entry.name.split("/").pop(), text: emailText(entry.name, content), archive: file.name });
  }
  if (!emails.length) throw new Error(`Nothing in ${file.name} could be read`);
  return emails;
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
