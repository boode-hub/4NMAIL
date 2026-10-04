// Unicode tricks
//
// Three ways text is made to read differently from what it is:
//
//  - Right-to-left override (U+202E and its relatives) reverses what follows,
//    so "invoice‮fdp.exe" is displayed as "invoiceexe.pdf". In a file name it
//    is never legitimate.
//  - Zero-width characters inside a word ("Pa​ypal") are invisible to the
//    reader but break the word for a spam filter's keyword match. (Marketing
//    mail pads its preview text with zero-width characters between words; that
//    is ignored — only characters inside a word count.)
//  - Letters from two alphabets in one word ("Pаypal" with a Cyrillic а) read
//    as the familiar word while being a different string.
//
// Pure text work.

const BIDI = /[‪-‮⁦-⁩‎‏؜]/;
const BIDI_ALL = /[‪-‮⁦-⁩‎‏؜]/g;
// Zero-width and invisible formatting characters.
const INVISIBLE_IN_WORD = /[\p{L}\p{N}][​-‍⁠﻿­᠎]+[\p{L}\p{N}]/gu;
const WORD = /[\p{L}\p{M}]{3,}/gu;

const NAMES = {
  "‪": "LRE", "‫": "RLE", "‬": "PDF", "‭": "LRO", "‮": "RLO",
  "⁦": "LRI", "⁧": "RLI", "⁨": "FSI", "⁩": "PDI",
  "‎": "LRM", "‏": "RLM", "؜": "ALM",
};

/** "invoice[U+202E RLO]fdp.exe" — the hidden controls made visible. */
export function revealControls(text) {
  return String(text || "").replace(BIDI_ALL, (c) => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")} ${NAMES[c] || ""}]`);
}

/** What a name really is once the direction controls are removed. */
export function stripControls(text) {
  return String(text || "").replace(BIDI_ALL, "");
}

export function hasBidiControl(text) {
  return BIDI.test(String(text || ""));
}

function scripts(word) {
  const found = new Set();
  for (const ch of word) {
    if (/\p{Script=Latin}/u.test(ch)) found.add("Latin");
    else if (/\p{Script=Cyrillic}/u.test(ch)) found.add("Cyrillic");
    else if (/\p{Script=Greek}/u.test(ch)) found.add("Greek");
    else if (/\p{Script=Armenian}/u.test(ch)) found.add("Armenian");
    else if (/\p{Script=Cherokee}/u.test(ch)) found.add("Cherokee");
  }
  return found;
}

/** Words that mix Latin with a lookalike alphabet. */
export function mixedScriptWords(text) {
  const out = [];
  for (const m of String(text || "").matchAll(WORD)) {
    const s = scripts(m[0]);
    if (s.has("Latin") && s.size > 1) out.push({ word: m[0], scripts: [...s] });
  }
  return out;
}

/** Zero-width characters hidden inside words. */
export function invisibleInWords(text) {
  return [...String(text || "").matchAll(INVISIBLE_IN_WORD)].map((m) => m[0]);
}

/**
 * Findings about Unicode tricks in the subject, the sender's name, the body
 * and attachment names.
 */
export function analyzeUnicode(headers, body, attachments = []) {
  const findings = [];
  const add = (id, severity, title, detail) => findings.push({ id, severity, title, detail });

  // 1. File names that hide their real extension.
  const reversed = attachments.filter((a) => hasBidiControl(a.value || a.filename));
  for (const att of reversed.slice(0, 3)) {
    const name = att.value || att.filename;
    add(
      "unicode-rtlo-filename",
      "high",
      "An attachment name hides its real extension",
      `"${name}" contains a text-direction control, so it displays differently from what it is. The real name is ${revealControls(name)} — the file ends in "${(stripControls(name).match(/\.[^.]+$/) || [""])[0]}".`,
    );
  }

  // 2. Direction controls in what the reader sees first.
  for (const [where, value] of [
    ["subject", headers?.subject],
    ["sender's name", headers?.from?.name],
  ]) {
    if (hasBidiControl(value)) {
      add(
        "unicode-bidi",
        "high",
        `The ${where} contains a hidden text-direction control`,
        `It reads "${stripControls(value)}" but is really ${revealControls(value)}. These controls are used to make text display in a misleading order.`,
      );
    }
  }

  // 3. Invisible characters breaking up words.
  for (const [where, value] of [
    ["subject", headers?.subject],
    ["sender's name", headers?.from?.name],
  ]) {
    const hidden = invisibleInWords(value);
    if (hidden.length) {
      add(
        "unicode-invisible",
        "medium",
        `The ${where} hides invisible characters inside words`,
        `${hidden.length} word${hidden.length === 1 ? " is" : "s are"} split by zero-width characters, which the reader cannot see but which stop filters from recognising the word.`,
      );
    }
  }
  const bodyText = `${body?.text || ""}\n${body?.html ? body.html.replace(/<[^>]+>/g, " ") : ""}`;
  const hiddenInBody = invisibleInWords(bodyText);
  if (hiddenInBody.length >= 3) {
    add(
      "unicode-invisible",
      "medium",
      "The body hides invisible characters inside words",
      `${hiddenInBody.length} words are split by zero-width characters — a way to slip known phrases past keyword filters while reading normally.`,
    );
  }

  // 4. Lookalike letters from another alphabet.
  for (const [where, value, severity] of [
    ["subject", headers?.subject, "high"],
    ["sender's name", headers?.from?.name, "high"],
  ]) {
    const mixed = mixedScriptWords(value);
    if (mixed.length) {
      add(
        "unicode-mixed-script",
        severity,
        `The ${where} mixes alphabets inside a word`,
        `"${mixed[0].word}" combines ${mixed[0].scripts.join(" and ")} letters that look alike — it reads as a familiar word but is a different string.`,
      );
    }
  }
  const mixedInBody = mixedScriptWords(bodyText);
  if (mixedInBody.length) {
    const sample = [...new Set(mixedInBody.map((m) => m.word))].slice(0, 3);
    add(
      "unicode-mixed-script",
      mixedInBody.length >= 3 ? "high" : "medium",
      "The body contains words that mix alphabets",
      `${mixedInBody.length} word${mixedInBody.length === 1 ? " combines" : "s combine"} Latin with lookalike letters from another alphabet (${sample.map((w) => `"${w}"`).join(", ")}).`,
    );
  }

  return findings;
}
