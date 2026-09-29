// Static inspection of HTML — attachments and message bodies alike.
//
// Phishing HTML attachments do their work in the victim's browser: a fake
// login page posts the password to a Telegram bot, or a "document viewer"
// decodes a hidden archive and saves it to disk. Running that code to watch it
// is not safe (a browser sandbox cannot stop WebRTC from reaching the
// attacker), so everything here is read, never executed: the page's text is
// searched for where it would send data and what it carries inside itself.
//
// Pure string work: no DOM, no eval, no network.

import { sniffFileType } from "./file-type.js";

// Places phishing kits post stolen data to. Chosen because they need no server
// of the kit author's own — which is exactly why kits use them.
//
// The third field says whether the address alone is conclusive. A Telegram bot
// API URL has no business in an email; a workers.dev or Apps Script address
// can be an ordinary website, and only counts when the page sends data to it.
const EXFIL_SERVICES = [
  [/api\.telegram\.org\/bot/i, "Telegram bot", true],
  [/discord(?:app)?\.com\/api\/webhooks/i, "Discord webhook", true],
  [/hooks\.slack\.com\/services/i, "Slack webhook", true],
  [/formspree\.io/i, "Formspree", true],
  [/formsubmit\.co/i, "FormSubmit", true],
  [/getform\.io/i, "Getform", true],
  [/submit-form\.com/i, "Submit-Form", true],
  [/api\.emailjs\.com/i, "EmailJS", true],
  [/webhook\.site/i, "webhook.site", true],
  [/\.m\.pipedream\.net|pipedream\.net/i, "Pipedream", true],
  [/requestbin|\.requestcatcher\.com/i, "request bin", true],
  [/script\.google\.com\/macros/i, "Google Apps Script", false],
  [/\.ngrok(?:-free)?\.(?:io|app|dev)/i, "ngrok tunnel", false],
  [/\.workers\.dev/i, "Cloudflare Worker", false],
];

// Uses that actually send data somewhere, as opposed to displaying something.
const SENDING_KINDS = new Set([
  "form target", "fetch", "XMLHttpRequest", "jQuery request", "beacon", "WebSocket", "request URL",
]);

const MAX_DEPTH = 2;
const MAX_TEXT = 3_000_000;

// Most specific use first: a URL that is both a form target and a link is
// reported as the form target.
const KIND_RANK = [
  "form target", "fetch", "XMLHttpRequest", "jQuery request", "beacon",
  "WebSocket", "request URL", "redirect", "meta refresh", "external script",
  "embedded frame", "URL in script", "stylesheet or resource", "image", "link",
];

/** Every URL a page would load or send data to, with how it would be used. */
function destinations(text) {
  const out = [];
  const add = (url, kind) => {
    const clean = String(url || "").trim().replace(/&amp;/g, "&");
    if (/^(https?:)?\/\//i.test(clean) || /^wss?:\/\//i.test(clean)) {
      out.push({ url: clean.startsWith("//") ? `https:${clean}` : clean, kind });
    }
  };
  const each = (re, kind) => {
    for (const m of text.matchAll(re)) add(m[1], kind);
  };

  each(/<form\b[^>]*\baction\s*=\s*["']([^"']+)["']/gi, "form target");
  each(/\bfetch\s*\(\s*["'`]([^"'`]+)["'`]/gi, "fetch");
  each(/\.open\s*\(\s*["'`](?:GET|POST|PUT)["'`]\s*,\s*["'`]([^"'`]+)["'`]/gi, "XMLHttpRequest");
  each(/\$\.(?:ajax|post|get)\s*\(\s*(?:\{[^}]*?url\s*:\s*)?["'`]([^"'`]+)["'`]/gi, "jQuery request");
  each(/\burl\s*:\s*["'`](https?:\/\/[^"'`]+)["'`]/gi, "request URL");
  each(/sendBeacon\s*\(\s*["'`]([^"'`]+)["'`]/gi, "beacon");
  each(/new\s+WebSocket\s*\(\s*["'`]([^"'`]+)["'`]/gi, "WebSocket");
  each(/location(?:\.href)?\s*=\s*["'`]([^"'`]+)["'`]/gi, "redirect");
  each(/location\.(?:replace|assign)\s*\(\s*["'`]([^"'`]+)["'`]/gi, "redirect");
  each(/<meta\b[^>]*http-equiv\s*=\s*["']?refresh[^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"'>\s]+)/gi, "meta refresh");
  each(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi, "external script");
  each(/<iframe\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi, "embedded frame");
  each(/<link\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi, "stylesheet or resource");
  each(/<img\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi, "image");
  each(/<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi, "link");
  // Complete URLs left in scripts. Endpoints assembled from string pieces are
  // out of reach of static reading; whole ones are not.
  each(/["'`](https?:\/\/[^\s"'`<>]{4,})["'`]/gi, "URL in script");

  const best = new Map();
  for (const d of out) {
    const prev = best.get(d.url);
    if (!prev || KIND_RANK.indexOf(d.kind) < KIND_RANK.indexOf(prev.kind)) best.set(d.url, d);
  }
  return [...best.values()].map((d) => {
    const service = EXFIL_SERVICES.find(([re]) => re.test(d.url));
    return service && (service[2] || SENDING_KINDS.has(d.kind)) ? { ...d, exfil: service[1] } : d;
  });
}

// ===== embedded payloads =====

function base64ToBytes(b64) {
  const clean = String(b64).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (clean.length < 16 || /[^A-Za-z0-9+/]/.test(clean) || clean.length % 4 === 1) return null;
  try {
    const bin = atob(clean.padEnd(Math.ceil(clean.length / 4) * 4, "="));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;
    return bytes;
  } catch {
    return null;
  }
}

function looksLikeText(bytes) {
  const n = Math.min(bytes.length, 2048);
  let printable = 0;
  for (let i = 0; i < n; i++) {
    const c = bytes[i];
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 0xc2) printable++;
  }
  return n > 0 && printable / n > 0.9;
}

const bytesToText = (bytes) => new TextDecoder("utf-8", { fatal: false }).decode(bytes);

/** The name a smuggling page gives the file it writes, when it says. */
function savedFilenames(text) {
  const names = new Set();
  const grab = (re) => {
    for (const m of text.matchAll(re)) if (m[1] && m[1].length < 200) names.add(m[1]);
  };
  grab(/\bdownload\s*=\s*["']([^"']+\.[a-z0-9]{2,5})["']/gi);
  grab(/\.download\s*=\s*["'`]([^"'`]+)["'`]/gi);
  grab(/msSaveOrOpenBlob\s*\([^,]+,\s*["'`]([^"'`]+)["'`]/gi);
  grab(/saveAs\s*\([^,]+,\s*["'`]([^"'`]+)["'`]/gi);
  return [...names];
}

/**
 * Large encoded blobs carried inside the page: base64 data URIs, atob()
 * arguments, long base64 string literals, and long percent-encoded strings.
 */
function embeddedBlobs(text) {
  const found = [];
  const seen = new Set();
  const push = (bytes, how, declaredType) => {
    if (!bytes || bytes.length < 64) return;
    const key = `${bytes.length}:${bytes.slice(0, 32).join(",")}`;
    if (seen.has(key)) return;
    seen.add(key);
    found.push({ bytes, how, declaredType: declaredType || null });
  };

  for (const m of text.matchAll(/data:([a-z0-9.+\/-]+)?(?:;[a-z0-9=._-]+)*;base64,([A-Za-z0-9+/=\s]{120,})/gi)) {
    // Raster images are content, not payload: a logo in a data URI is ordinary.
    if (/^image\//i.test(m[1] || "") && !/svg/i.test(m[1] || "")) continue;
    push(base64ToBytes(m[2]), "data: URI", m[1]);
  }
  for (const m of text.matchAll(/atob\s*\(\s*["'`]([A-Za-z0-9+/=_-]{100,})["'`]\s*\)/g)) {
    push(base64ToBytes(m[1]), "atob() call");
  }
  for (const m of text.matchAll(/["'`]([A-Za-z0-9+/]{800,}={0,2})["'`]/g)) {
    push(base64ToBytes(m[1]), "base64 string");
  }
  for (const m of text.matchAll(/(?:unescape|decodeURIComponent|decodeURI)\s*\(\s*["'`]([^"'`]{100,})["'`]\s*\)/gi)) {
    // Only strings that are mostly escapes are an encoded layer; a long
    // ordinary string with the odd %20 is not.
    const escapes = (m[1].match(/%[0-9a-f]{2}/gi) || []).length;
    if (escapes < 10 || (escapes * 3) / m[1].length < 0.15) continue;
    let decoded;
    try {
      decoded = decodeURIComponent(m[1]);
    } catch {
      decoded = m[1].replace(/%([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
    }
    push(new TextEncoder().encode(decoded), "percent-encoded string");
  }
  return found;
}

/**
 * What a piece of HTML would do if it were opened — worked out by reading it.
 *
 * @param {string} html
 * @param {{name?: string, depth?: number}} [options]
 */
export function inspectHtml(html, { name = "page", depth = 0 } = {}) {
  const text = String(html || "").slice(0, MAX_TEXT);
  const result = {
    passwordForm: /<input\b[^>]*\btype\s*=\s*["']?password/i.test(text),
    destinations: destinations(text),
    exfil: [],
    payloads: [],
    savedAs: savedFilenames(text),
    hiddenLayers: 0,
  };

  let index = 0;
  for (const blob of embeddedBlobs(text)) {
    const sniffed = sniffFileType(blob.bytes);
    const textual = !sniffed && looksLikeText(blob.bytes);
    const decoded = textual ? bytesToText(blob.bytes) : "";

    // A hidden layer of HTML or script is read too: it is usually where the
    // real login form and the real collection endpoint live.
    if (textual) {
      if (depth < MAX_DEPTH && /<(?:html|form|input|script|body|div)\b|fetch\s*\(|XMLHttpRequest|location\b/i.test(decoded)) {
        result.hiddenLayers++;
        const inner = inspectHtml(decoded, { name, depth: depth + 1 });
        result.passwordForm ||= inner.passwordForm;
        result.hiddenLayers += inner.hiddenLayers;
        for (const d of inner.destinations) result.destinations.push({ ...d, via: `hidden ${blob.how}` });
        result.payloads.push(...inner.payloads);
        result.savedAs.push(...inner.savedAs);
      }
      continue;
    }

    // Anything that is not readable text is a file the page carries.
    index++;
    const ext = sniffed?.extensions?.[0] || "bin";
    result.payloads.push({
      name: result.savedAs[index - 1] || result.savedAs[0] || `${name}-embedded-${index}.${ext}`,
      bytes: blob.bytes,
      type: sniffed?.label || blob.declaredType || "unknown binary",
      how: blob.how,
    });
  }

  const byUrl = new Map();
  for (const d of result.destinations) if (!byUrl.has(d.url)) byUrl.set(d.url, d);
  result.destinations = [...byUrl.values()];
  result.exfil = [...new Set(result.destinations.filter((d) => d.exfil).map((d) => d.exfil))];
  result.savedAs = [...new Set(result.savedAs)];
  return result;
}

/** True for content that is HTML whatever its label says. */
export function looksLikeHtml(text) {
  const head = String(text || "").slice(0, 4000);
  return (
    /<(?:!doctype\s+html|html|body)\b/i.test(head) ||
    (head.match(/<\/?(?:div|table|p|a|span|td|tr|img|br)\b/gi) || []).length >= 4
  );
}
