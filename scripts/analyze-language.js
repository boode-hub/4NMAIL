// Language / Urgency / Fraud Analysis
// Local keyword and pattern detection — no external API calls.
//
// The word lists live in keywords.js. Each category has strong phrases (red
// flags in themselves) and broad words (what the message is about). Both are
// found and shown; only strong phrases count toward the score, so broad words
// inform the analyst without ever moving the verdict.
//
// Matching walks the text word by word and looks candidates up by their first
// word, instead of running one regular expression per term: with two thousand
// terms that is the difference between milliseconds and seconds on a large
// email. Whole words only — "irs" never matches inside "first".

import { CATEGORIES, BROAD_WEIGHT } from "./keywords.js";

// A category's broad words can add at most this much to its 0-100 score.
const BROAD_CAP = 30;

// Words, numbers and contractions ("don't", "i'm"). Everything else — spaces,
// line breaks, hyphens, slashes, punctuation — separates words, so a phrase
// still matches when it is split across a line or written with a hyphen.
const WORD_RE = /[\p{L}\p{N}]+(?:'[\p{L}]+)*/gu;

/** Lower-case, straight apostrophes, possessive dropped. */
function normalizeToken(token) {
  return token.toLowerCase().replace(/[’‘`]/g, "'").replace(/'s$/, "");
}

/** Keyword -> its normalised words. */
function tokenize(text) {
  return (String(text).replace(/[’‘`]/g, "'").match(WORD_RE) || []).map(normalizeToken);
}

/** The singular forms a word might be the plural of. */
function singulars(token) {
  const out = [token];
  if (token.length > 3 && token.endsWith("ies")) out.push(token.slice(0, -3) + "y");
  if (token.length > 3 && token.endsWith("es")) out.push(token.slice(0, -2));
  if (token.length > 2 && token.endsWith("s")) out.push(token.slice(0, -1));
  return out;
}

/** True when a text word is the keyword word, or a plural of it. */
function sameWord(textToken, keywordToken, isLast) {
  if (textToken === keywordToken) return true;
  if (!isLast) return false;
  return singulars(textToken).includes(keywordToken);
}

// ===== index, built once =====

const INDEX = new Map(); // first keyword word -> [{ category, tier, tokens, term }]

for (const [category, config] of Object.entries(CATEGORIES)) {
  for (const tier of ["strong", "broad"]) {
    for (const term of config[tier] || []) {
      const tokens = tokenize(term);
      if (!tokens.length) continue;
      const entry = { category, tier, tokens, term };
      if (!INDEX.has(tokens[0])) INDEX.set(tokens[0], []);
      INDEX.get(tokens[0]).push(entry);
    }
  }
}

/** Every indexed term, for tests and for the curious. */
export function keywordStats() {
  const stats = {};
  for (const [category, config] of Object.entries(CATEGORIES)) {
    stats[category] = {
      strong: (config.strong || []).length,
      broad: (config.broad || []).length,
      patterns: (config.patterns || []).length,
    };
  }
  return stats;
}

// ===== matching =====

function wordsWithPositions(text) {
  const words = [];
  for (const m of text.matchAll(WORD_RE)) {
    words.push({ token: normalizeToken(m[0]), start: m.index, end: m.index + m[0].length });
  }
  return words;
}

/** Strong beats broad, then the longer match wins. */
function better(a, b) {
  if (!b) return true;
  if (a.tier !== b.tier) return a.tier === "strong";
  return a.length > b.length;
}

/** Remove overlaps inside one category, keeping the better of each pair. */
function resolveOverlaps(matches) {
  const sorted = [...matches].sort((a, b) => a.index - b.index || b.length - a.length);
  const kept = [];
  for (const m of sorted) {
    const last = kept[kept.length - 1];
    if (last && m.index < last.index + last.length) {
      if (better(m, last)) kept[kept.length - 1] = m;
      continue;
    }
    kept.push(m);
  }
  return kept;
}

function findMatches(text) {
  const byCategory = Object.fromEntries(Object.keys(CATEGORIES).map((c) => [c, []]));
  const words = wordsWithPositions(text);
  const nextFree = {};

  for (let i = 0; i < words.length; i++) {
    const candidates = new Set();
    for (const form of singulars(words[i].token)) {
      for (const entry of INDEX.get(form) || []) candidates.add(entry);
    }
    if (!candidates.size) continue;

    const best = {};
    for (const entry of candidates) {
      if ((nextFree[entry.category] || 0) > i) continue;
      const n = entry.tokens.length;
      if (i + n > words.length) continue;
      let ok = true;
      for (let k = 0; k < n; k++) {
        if (!sameWord(words[i + k].token, entry.tokens[k], k === n - 1)) {
          ok = false;
          break;
        }
      }
      if (!ok) continue;
      const start = words[i].start;
      const end = words[i + n - 1].end;
      const match = { index: start, length: end - start, tier: entry.tier, words: n };
      if (better(match, best[entry.category])) best[entry.category] = match;
    }

    for (const [category, match] of Object.entries(best)) {
      byCategory[category].push({
        phrase: text.slice(match.index, match.index + match.length),
        index: match.index,
        length: match.length,
        tier: match.tier,
        category,
      });
      nextFree[category] = i + match.words;
    }
  }

  // Patterns: money amounts, account numbers, wallet addresses, and the BEC
  // wording no fixed phrase would catch.
  for (const [category, config] of Object.entries(CATEGORIES)) {
    for (const { re, tier } of config.patterns || []) {
      const regex = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
      let hit;
      while ((hit = regex.exec(text)) !== null) {
        const phrase = hit[0].trim();
        if (phrase) {
          byCategory[category].push({
            phrase,
            index: hit.index + hit[0].indexOf(phrase),
            length: phrase.length,
            tier,
            category,
          });
        }
        if (regex.lastIndex === hit.index) regex.lastIndex++;
      }
    }
    byCategory[category] = resolveOverlaps(byCategory[category]);
  }
  return byCategory;
}

/**
 * Analyze text for manipulation and fraud language.
 * @param {string} text - The email body text to analyze
 * @returns {Object} categories, scores, matches and highlighted text
 */
export function analyzeLanguage(text) {
  if (!text || typeof text !== "string") {
    return {
      categories: {},
      totalScore: 0,
      detectedLanguage: "unknown",
      languageMismatch: false,
      highlightedText: "",
      summary: "No text provided for analysis",
      matches: [],
    };
  }

  // Same length as the original, so match positions map straight back.
  const normalized = text.replace(/[’‘`]/g, "'").replace(/ /g, " ");
  const found = findMatches(normalized);
  const categories = {};
  const allMatches = [];

  for (const [key, config] of Object.entries(CATEGORIES)) {
    const matches = found[key].map((m) => ({ ...m, phrase: text.slice(m.index, m.index + m.length) }));
    const strongCount = matches.filter((m) => m.tier === "strong").length;
    const broadCount = matches.length - strongCount;
    const strongPart = strongCount * config.weight * 10;
    const broadPart = Math.min(broadCount * config.weight * 10 * BROAD_WEIGHT, BROAD_CAP);
    categories[key] = {
      label: config.label,
      score: Math.round(Math.min(strongPart + broadPart, 100)),
      matches,
      matchCount: matches.length,
      strongCount,
      broadCount,
      weight: config.weight,
    };
    for (const m of matches) allMatches.push(m); // spread overflows the stack on huge bodies
  }

  const totalScore = Math.min(
    Object.values(categories).reduce((sum, cat) => sum + cat.score, 0),
    100,
  );

  return {
    categories,
    totalScore: Math.round(totalScore),
    detectedLanguage: detectLanguage(text),
    languageMismatch: false,
    highlightedText: generateHighlightedText(text, allMatches),
    summary: generateSummary(categories),
    matches: allMatches,
  };
}

// ===== language detection =====

const LANGUAGE_MARKERS = {
  en: {
    words: ["the", "and", "is", "to", "of", "a", "in", "that", "have", "it", "for", "not", "on", "with", "he", "as", "you", "do", "at", "this", "be", "are", "was", "were", "been", "will", "would", "could", "should", "can", "may", "might", "must", "shall", "has", "had", "did", "does", "doing", "done"],
    threshold: 0.2,
  },
  es: {
    words: ["el", "la", "de", "que", "y", "a", "en", "un", "ser", "se", "no", "haber", "por", "con", "su", "para", "como", "estar", "tener"],
    threshold: 0.25,
  },
  fr: {
    words: ["le", "de", "et", "à", "un", "il", "être", "avoir", "ne", "je", "son", "que", "se", "qui", "ce", "dans", "en", "du", "elle", "au"],
    threshold: 0.25,
  },
  de: {
    words: ["der", "die", "und", "in", "den", "von", "zu", "das", "mit", "sich", "des", "auf", "für", "ist", "im", "dem", "nicht", "ein", "eine"],
    threshold: 0.25,
  },
};

function detectLanguage(text) {
  const words = text.toLowerCase().match(/\b\w+\b/g) || [];
  if (words.length < 10) return "unknown";

  let bestLang = "unknown";
  let bestScore = 0;
  for (const [lang, config] of Object.entries(LANGUAGE_MARKERS)) {
    const score = words.filter((word) => config.words.includes(word)).length / words.length;
    if (score > config.threshold && score > bestScore) {
      bestScore = score;
      bestLang = lang;
    }
  }
  return bestLang;
}

// ===== presentation =====

/**
 * The text with every match wrapped in <mark>. Overlapping matches (the same
 * words in two categories) merge into one mark carrying every category; a mark
 * made only of broad words is styled more quietly.
 */
export const MAX_HIGHLIGHTS = 1500;

function generateHighlightedText(text, matches) {
  if (!matches.length) return escapeHtml(text);

  const sorted = [...matches].sort((a, b) => a.index - b.index);
  const merged = [];
  for (const m of sorted) {
    const last = merged[merged.length - 1];
    if (last && m.index < last.index + last.length) {
      last.length = Math.max(last.length, m.index + m.length - last.index);
      if (!last.categories.includes(m.category)) last.categories.push(m.category);
      if (m.tier === "strong") last.strong = true;
    } else {
      merged.push({ index: m.index, length: m.length, categories: [m.category], strong: m.tier === "strong" });
    }
  }

  // Every highlight is an element; a huge body with tens of thousands of them
  // freezes the page. Past the cap the text is shown plain — every phrase is
  // still counted and listed.
  let result = "";
  let lastIndex = 0;
  for (const m of merged.slice(0, MAX_HIGHLIGHTS)) {
    result += escapeHtml(text.substring(lastIndex, m.index));
    const primary = m.categories[0];
    const labels = m.categories.map(getCategoryLabel).join(", ");
    result += `<mark class="highlight-${primary}${m.strong ? "" : " broad"}" title="${escapeHtml(labels)}${m.strong ? "" : " (broad term)"}">${escapeHtml(text.substring(m.index, m.index + m.length))}</mark>`;
    lastIndex = m.index + m.length;
  }
  return result + escapeHtml(text.substring(lastIndex));
}

function getCategoryLabel(category) {
  return CATEGORIES[category]?.label || category;
}

function generateSummary(categories) {
  const strong = [];
  let broad = 0;
  for (const cat of Object.values(categories)) {
    if (cat.strongCount) {
      strong.push(`${cat.strongCount} ${cat.label.toLowerCase()} phrase${cat.strongCount > 1 ? "s" : ""}`);
    }
    broad += cat.broadCount;
  }
  const also = broad ? ` Also noted: ${broad} broader money, pressure or persuasion term${broad === 1 ? "" : "s"}.` : "";
  if (!strong.length) return `No suspicious phrases detected.${also}`;
  return `Detected: ${strong.join(", ")}.${also}`;
}

function escapeHtml(text) {
  if (!text) return "";
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
