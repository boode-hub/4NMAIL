// Safe, readable HTML preview
//
// The preview used to hand the message's HTML to the frame as-is. That was
// safe, but it often showed a white page: every picture in a phishing mail is
// remote (and must stay blocked, or opening the preview tells the sender you
// looked), embedded logos referenced by "cid:" never resolved, and text
// written for a dark mail client disappeared on a white canvas.
//
// Everything is prepared here, before the frame sees it:
//  - "cid:" images are replaced by the embedded image itself (a data: URI);
//  - every remote image becomes a visible box of the same size naming the
//    host it would have come from;
//  - links keep their text but lose their target (hovering shows where they
//    go), so a click in the preview can never navigate anywhere;
//  - scripts, frames, objects, <base>, meta refresh and resource hints go;
//  - a readable default look is set, which the message's own CSS still wins
//    over.
// The frame stays sandboxed with no permissions and a no-network policy, so
// none of this is the safety boundary — it is what makes the preview legible.
//
// DOMParser builds an inert document: it runs no script and fetches nothing.

const PREVIEW_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; form-action 'none'; base-uri 'none'";

const BASE_STYLE = `
html{background:#ffffff;color:#1f2328;font:14px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
body{margin:12px;overflow-wrap:anywhere;}
img{max-width:100%;height:auto;}
table{max-width:100%;}
a.pv-link{color:#0969da;text-decoration:underline dotted;cursor:help;}
.pv-blocked{display:inline-block;box-sizing:border-box;max-width:100%;border:1px dashed #afb8c1;background:#f6f8fa;color:#57606a;font:11px/1.35 -apple-system,"Segoe UI",sans-serif;padding:6px;overflow:hidden;vertical-align:middle;text-align:center;}
`;

const IMAGE_TYPES = /^image\/(png|jpe?g|gif|webp|bmp|x-icon|vnd\.microsoft\.icon|svg\+xml)$/i;
const MAX_EMBEDDED = 5 * 1024 * 1024;

function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

/** Content-ID → data: URI, for embedded images only. */
export function cidMap(attachments = []) {
  const map = new Map();
  for (const att of attachments) {
    const cid = String(att.contentId || "").replace(/[<>]/g, "").trim().toLowerCase();
    if (!cid || !att.bytes?.length || !IMAGE_TYPES.test(att.contentType || "")) continue;
    if (att.bytes.length > MAX_EMBEDDED) continue;
    map.set(cid, `data:${att.contentType.toLowerCase()};base64,${bytesToBase64(att.bytes)}`);
  }
  return map;
}

export function defangForTooltip(url) {
  return String(url || "")
    .trim()
    .replace(/^http/i, "hxxp")
    .replace(/:\/\//, "[://]")
    .replace(/\./g, "[.]");
}

function hostOf(url) {
  try {
    return new URL(url).hostname.replace(/\./g, "[.]") || "unknown host";
  } catch {
    return "unknown host";
  }
}

/**
 * Turn a message's HTML into a document that is safe and readable in the
 * sandboxed preview frame.
 *
 * @param {string} html
 * @param {Array} attachments - parsed attachments, for cid: images
 * @returns {{ html: string, stats: Object }}
 */
export function buildPreview(html, attachments = []) {
  const stats = { remoteImages: 0, embeddedImages: 0, missingEmbedded: 0, links: 0, removed: 0, stylesheets: 0 };
  const doc = new DOMParser().parseFromString(String(html || ""), "text/html");
  const cids = cidMap(attachments);

  // Active or navigating content goes entirely.
  for (const el of doc.querySelectorAll(
    "script, noscript, iframe, frame, frameset, object, embed, applet, base, meta[http-equiv], portal",
  )) {
    el.remove();
    stats.removed++;
  }
  for (const el of doc.querySelectorAll("link")) {
    if (/stylesheet/i.test(el.getAttribute("rel") || "")) stats.stylesheets++;
    el.remove();
  }

  // Event handlers, javascript: URLs and background fetches, everywhere.
  for (const el of doc.querySelectorAll("*")) {
    for (const attr of [...el.attributes]) {
      if (/^on/i.test(attr.name) || /^\s*(javascript|vbscript|data:text\/html)/i.test(attr.value)) {
        el.removeAttribute(attr.name);
      }
    }
    el.removeAttribute("background");
  }

  // Images: embedded ones shown, remote ones replaced by a labelled box.
  for (const img of doc.querySelectorAll("img, input[type=image i]")) {
    const src = (img.getAttribute("src") || "").trim();
    img.removeAttribute("srcset");
    const cid = src.match(/^cid:(.+)$/i)?.[1]?.trim().toLowerCase();
    if (cid && cids.has(cid)) {
      img.setAttribute("src", cids.get(cid));
      stats.embeddedImages++;
      continue;
    }
    if (/^data:image\//i.test(src)) {
      stats.embeddedImages++;
      continue;
    }
    if (!src) continue;

    const box = doc.createElement("span");
    box.className = "pv-blocked";
    const width = parseInt(img.getAttribute("width"), 10);
    const height = parseInt(img.getAttribute("height"), 10);
    box.style.width = `${Math.min(width > 0 ? width : 180, 900)}px`;
    box.style.minHeight = `${Math.min(height > 0 ? height : 44, 900)}px`;
    const alt = (img.getAttribute("alt") || "").trim().slice(0, 120);
    if (cid) {
      stats.missingEmbedded++;
      box.textContent = `Embedded image not included in the message${alt ? ` — "${alt}"` : ""}`;
      box.title = src;
    } else {
      stats.remoteImages++;
      box.textContent = `Remote image blocked${alt ? ` — "${alt}"` : ""} · ${hostOf(src)}`;
      box.title = defangForTooltip(src);
    }
    img.replaceWith(box);
  }

  // Links: text kept, destination moved into the tooltip. Nothing in the
  // preview can navigate, and hovering still shows the real target.
  for (const a of doc.querySelectorAll("a[href], area[href]")) {
    const href = a.getAttribute("href");
    a.removeAttribute("href");
    a.removeAttribute("target");
    a.classList.add("pv-link");
    a.setAttribute("title", `Link → ${defangForTooltip(href)}`);
    stats.links++;
  }

  // Forms stay visible — a fake login form is evidence — but go nowhere.
  for (const form of doc.querySelectorAll("form")) form.removeAttribute("action");

  // Policy first, then the readable defaults, then the message's own styles
  // (already in the document), so the message still overrides the defaults.
  const head = doc.head || doc.documentElement.insertBefore(doc.createElement("head"), doc.body);
  const meta = doc.createElement("meta");
  meta.setAttribute("http-equiv", "Content-Security-Policy");
  meta.setAttribute("content", PREVIEW_CSP);
  const charset = doc.createElement("meta");
  charset.setAttribute("charset", "utf-8");
  const style = doc.createElement("style");
  style.textContent = BASE_STYLE;
  head.prepend(meta, charset, style);

  return { html: "<!doctype html>" + doc.documentElement.outerHTML, stats };
}

/** A plain-text message shown in the frame the same way, for a uniform view. */
export function textAsPreview(text) {
  const esc = String(text || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  return buildPreview(
    `<html><body><pre style="white-space:pre-wrap;font:13px/1.5 ui-monospace,Consolas,monospace;margin:0">${esc}</pre></body></html>`,
  );
}

/** One line describing what the preview left out, for the note above it. */
export function describePreview(stats) {
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
  const parts = [];
  if (stats.remoteImages) parts.push(`${plural(stats.remoteImages, "remote image")} blocked`);
  if (stats.stylesheets) parts.push(`${plural(stats.stylesheets, "remote stylesheet")} blocked`);
  if (stats.embeddedImages) parts.push(`${plural(stats.embeddedImages, "embedded image")} shown`);
  if (stats.missingEmbedded) parts.push(`${plural(stats.missingEmbedded, "embedded image")} missing from the message`);
  if (stats.removed) parts.push(`${plural(stats.removed, "script or frame element")} removed`);
  if (stats.links) parts.push(`${plural(stats.links, "link")} disabled — hover to see the destination`);
  return parts.join(" · ");
}
