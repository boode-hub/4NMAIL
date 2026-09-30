// Quoted conversation analysis — fabricated email threads
//
// A favourite business-email-compromise trick: the attacker pastes a made-up
// conversation into the body — "From: … Sent: … To: … Subject: RE: Invoice"
// several times over — so the payment request looks like the next step in a
// thread the victim's colleagues already agreed to. The quoted messages are
// just text; nothing checked them. This module reads them back out and asks
// whether that conversation could actually have happened:
//
//  - is the email really a reply to anything (In-Reply-To / References)?
//  - do the quoted dates exist (weekday matches the date), and come in order,
//    and before the message itself?
//  - is the sender in the thread they claim to continue, under the same
//    address — or a lookalike of it?
//  - is the payment instruction sitting inside the part that looks fabricated?
//
// Pure text work: no DOM, no network.

import { orgDomain } from "./parse-auth.js";
import { skeleton, levenshtein } from "./analyze-identity.js";
import { analyzeLanguage } from "./analyze-language.js";

// Header labels in the languages mail clients most often write them in.
const FIELD = {
  from: /^(?:from|de|von|da|van|od|från|fra)\s*:\s*(.*)$/i,
  date: /^(?:sent|date|envoyé|gesendet|datum|enviado|data|verzonden|inviato|skickat|sendt)\s*:\s*(.*)$/i,
  to: /^(?:to|à|an|para|aan|a|till|til)\s*:\s*(.*)$/i,
  cc: /^(?:cc|kopie|copie)\s*:\s*(.*)$/i,
  subject: /^(?:subject|objet|betreff|asunto|oggetto|onderwerp|assunto|ämne|emne)\s*:\s*(.*)$/i,
};

const WROTE = /\b(?:wrote|a écrit|schrieb|escribió|ha scritto|schreef|escreveu|skrev)\s*:?\s*$/i;
const SEPARATOR =
  /^[-_=\s]*(?:original message|forwarded message|mensaje original|message d'origine|ursprüngliche nachricht|messaggio originale|oorspronkelijk bericht|begin forwarded message)[-_=:\s]*$/i;

const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
const WEEKDAYS = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];

/** HTML to text that keeps line structure, which quoted headers depend on. */
export function htmlToLines(html) {
  return String(html || "")
    .replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(?:p|div|tr|li|h[1-6]|blockquote|table|pre)>/gi, "\n")
    .replace(/<hr\b[^>]*>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&amp;/gi, "&");
}

/** "John Smith <john@acme.com>", "john@acme.com", "Smith, John [mailto:john@acme.com]". */
export function parsePerson(value) {
  const text = String(value || "").trim();
  const email = (text.match(/[\w.+'-]+@[\w-]+(?:\.[\w-]+)+/) || [])[0]?.toLowerCase() || null;
  const name = text
    .replace(/<[^>]*>|\[mailto:[^\]]*\]|\([^)]*\)/gi, "")
    .replace(/[\w.+'-]+@[\w-]+(?:\.[\w-]+)+/g, "")
    .replace(/["';]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  return { name: name || null, email };
}

/**
 * Read a written date without trusting it: the weekday it claims, and the
 * calendar date it names. Only month-name dates are used — "03/04/2024" could
 * be March or April, and a wrong guess would accuse an honest thread.
 */
export function parseClaimedDate(raw) {
  const text = String(raw || "").toLowerCase();
  const weekday = WEEKDAYS.findIndex((d) => new RegExp(`\\b${d.slice(0, 3)}(?:${d.slice(3)})?\\b`).test(text));
  const month = MONTHS.findIndex((m) => new RegExp(`\\b${m.slice(0, 3)}(?:${m.slice(3)})?\\b`).test(text));
  if (month < 0) return null;
  const monthWord = new RegExp(`\\b${MONTHS[month].slice(0, 3)}[a-z]*\\.?`);
  const [before, after] = text.split(monthWord);
  // "January 15, 2024" or "15 January 2024".
  const day = Number((after?.match(/^\s*(\d{1,2})\b/) || before?.match(/\b(\d{1,2})\s*$/) || [])[1]);
  const year = Number((text.match(/\b(19|20)\d{2}\b/) || [])[0]);
  if (!day || day > 31 || !year) return null;

  const time = text.match(/\b(\d{1,2}):(\d{2})(?::\d{2})?\s*(am|pm)?/);
  let hours = time ? Number(time[1]) : 0;
  if (time?.[3] === "pm" && hours < 12) hours += 12;
  if (time?.[3] === "am" && hours === 12) hours = 0;
  const minutes = time ? Number(time[2]) : 0;

  const actual = new Date(Date.UTC(year, month, day));
  // February 31st and friends do not exist.
  if (actual.getUTCMonth() !== month) return { valid: false, weekdayClaimed: weekday, raw };
  return {
    valid: true,
    raw,
    timestamp: Date.UTC(year, month, day, hours, minutes),
    weekdayClaimed: weekday >= 0 ? weekday : null,
    weekdayActual: actual.getUTCDay(),
    dateText: `${day} ${MONTHS[month][0].toUpperCase()}${MONTHS[month].slice(1)} ${year}`,
  };
}

/**
 * Pull every quoted message out of the body, in the order they appear
 * (newest first in a normal thread).
 */
export function extractQuotedMessages(text) {
  const lines = String(text || "")
    .split(/\r?\n/)
    .map((l) => l.replace(/^[\s>]+/, "").trim());
  const messages = [];
  let separators = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;

    if (SEPARATOR.test(line)) {
      separators++;
      continue;
    }

    // Outlook / Apple Mail header block: a run of labelled lines.
    const fieldOf = (l) => Object.entries(FIELD).find(([, re]) => re.test(l));
    if (fieldOf(line)) {
      const block = {};
      let j = i;
      while (j < lines.length && j < i + 10) {
        const current = lines[j];
        if (!current) {
          // A blank line ends a block once it has what a block needs.
          if (block.from && block.subject) break;
          j++;
          continue;
        }
        const hit = fieldOf(current);
        if (!hit) break;
        const [field, re] = hit;
        if (block[field] !== undefined) break; // the next block starts here
        block[field] = current.match(re)[1].trim();
        j++;
      }
      if (block.from !== undefined && block.subject !== undefined && (block.date !== undefined || block.to !== undefined)) {
        messages.push({
          style: "header block",
          from: parsePerson(block.from),
          to: block.to || null,
          date: block.date || null,
          subject: block.subject,
          line: i,
        });
        i = j - 1;
        continue;
      }
    }

    // Gmail / Thunderbird attribution: "On <date>, <name> <<email>> wrote:",
    // sometimes wrapped over two lines.
    const joined = WROTE.test(line) ? line : WROTE.test(`${line} ${lines[i + 1] || ""}`) ? `${line} ${lines[i + 1]}` : null;
    if (joined && /^(?:on|le|am|el|il|op|em|den|på)\b/i.test(joined)) {
      const person = parsePerson(joined);
      const time = joined.match(/\d{1,2}:\d{2}(?::\d{2})?\s*(?:am|pm)?/i);
      const datePart = time
        ? joined.slice(0, time.index + time[0].length).replace(/^\S+\s+/, "")
        : joined.replace(/^\S+\s+/, "").split(/,\s*(?=[^,]*<)/)[0];
      const namePart = time ? joined.slice(time.index + time[0].length) : "";
      messages.push({
        style: "attribution line",
        from: { name: parsePerson(namePart.replace(WROTE, "")).name || person.name, email: person.email },
        to: null,
        date: datePart.trim(),
        subject: null,
        line: i,
      });
      if (joined !== line) i++;
    }
  }
  return { messages, separators, lines };
}

/** Are two domains different but meant to look the same? */
function lookalikeDomains(a, b) {
  if (!a || !b) return false;
  const orgA = orgDomain(a);
  const orgB = orgDomain(b);
  if (!orgA || !orgB || orgA === orgB) return false;
  const nameA = orgA.split(".")[0];
  const nameB = orgB.split(".")[0];
  if (nameA.length < 4 || nameB.length < 4) return false;
  if (skeleton(nameA) === skeleton(nameB)) return true;
  // Same name, different ending: acme.com vs acme-payments.com / acme.co
  if (nameA === nameB) return true;
  return levenshtein(nameA, nameB) <= (Math.max(nameA.length, nameB.length) >= 8 ? 2 : 1);
}

const normName = (n) => String(n || "").toLowerCase().replace(/[^a-zÀ-ɏ]+/g, " ").trim();

/**
 * Findings about the quoted conversation in a message.
 *
 * @param {Object} headers - parsed headers
 * @param {Object|null} body - parsed body
 * @returns {{ messages: Array, findings: Array<{id, severity, title, detail}> }}
 */
export function analyzeThread(headers, body) {
  const text = body?.html ? htmlToLines(body.html) : body?.text || "";
  const { messages, separators, lines } = extractQuotedMessages(text);
  const findings = [];
  const add = (id, severity, title, detail) => findings.push({ id, severity, title, detail });

  const subject = String(headers?.subject || "");
  const isReplySubject = /^\s*(?:re|aw|sv|antw|res|ref)\s*:/i.test(subject);
  const isForward = /^\s*(?:fw|fwd|tr|wg|rv)\s*:/i.test(subject) || separators > 0 && messages.length <= 1;
  const hasReplyHeaders = !!(headers?.all?.["in-reply-to"] || headers?.all?.["references"]);

  for (const m of messages) m.parsedDate = parseClaimedDate(m.date);

  // 1. A reply that is not a reply.
  if (isReplySubject && !hasReplyHeaders) {
    add(
      "thread-fake-reply",
      messages.length ? "high" : "medium",
      messages.length ? "A reply to a conversation that never happened" : "The subject says RE:, but this is not a reply",
      messages.length
        ? `The subject starts with "RE:" and the body quotes ${messages.length} earlier message${messages.length === 1 ? "" : "s"}, but the email carries no In-Reply-To or References header — no mail system recorded it as a reply. The thread was pasted in.`
        : `The subject starts with "RE:" but the email carries no In-Reply-To or References header, so it answers nothing. Fake replies are used to borrow the trust of an existing conversation.`,
    );
  } else if (messages.length && !hasReplyHeaders && !isForward) {
    add(
      "thread-pasted",
      "medium",
      "A quoted conversation in a message that is not a reply",
      `The body quotes ${messages.length} earlier message${messages.length === 1 ? "" : "s"}, but the email itself is neither a reply nor a forward.`,
    );
  }

  // 2. Dates that could not have been written by a mail client.
  const wrongWeekday = messages.filter((m) => m.parsedDate?.valid && m.parsedDate.weekdayClaimed != null && m.parsedDate.weekdayClaimed !== m.parsedDate.weekdayActual);
  if (wrongWeekday.length) {
    const m = wrongWeekday[0];
    add(
      "thread-bad-date",
      "high",
      "A quoted date that does not exist",
      `A quoted message is dated "${m.date}", but ${m.parsedDate.dateText} was a ${WEEKDAYS[m.parsedDate.weekdayActual][0].toUpperCase()}${WEEKDAYS[m.parsedDate.weekdayActual].slice(1)}. Mail clients write these dates themselves and never get the weekday wrong; people typing a fake thread do.${wrongWeekday.length > 1 ? ` (${wrongWeekday.length} quoted dates are wrong.)` : ""}`,
    );
  }
  const impossible = messages.filter((m) => m.parsedDate && !m.parsedDate.valid);
  if (impossible.length) {
    add("thread-bad-date", "high", "A quoted date that does not exist", `A quoted message is dated "${impossible[0].date}", which is not a real calendar date.`);
  }

  const sentAt = Date.parse(headers?.date || "");
  if (!Number.isNaN(sentAt)) {
    const future = messages.filter((m) => m.parsedDate?.valid && m.parsedDate.timestamp > sentAt + 86400000);
    if (future.length) {
      add(
        "thread-future-date",
        "high",
        "The quoted thread is dated after the email itself",
        `A quoted message is dated "${future[0].date}", later than this email was sent (${headers.date}).`,
      );
    }
  }
  const dated = messages.filter((m) => m.parsedDate?.valid);
  for (let k = 1; k < dated.length; k++) {
    // A thread reads newest first; an older message above a newer one is odd.
    if (dated[k].parsedDate.timestamp > dated[k - 1].parsedDate.timestamp + 86400000) {
      add(
        "thread-order",
        "medium",
        "The quoted messages are out of order",
        `"${dated[k].date}" is quoted below "${dated[k - 1].date}", but is newer — a real thread lists the newest message first.`,
      );
      break;
    }
  }

  // 3. Who is in the thread, against who sent the email.
  const sender = headers?.from || {};
  const senderEmail = (sender.email || "").toLowerCase();
  const senderDomain = senderEmail.split("@")[1] || null;
  const senderName = normName(sender.name);
  const participants = messages.map((m) => m.from).filter((p) => p?.email || p?.name);

  const sameNameOtherAddress = participants.find(
    (p) => senderName && p.name && normName(p.name) === senderName && p.email && senderEmail && p.email !== senderEmail,
  );
  if (sameNameOtherAddress) {
    add(
      "thread-impersonation",
      "high",
      "The sender impersonates someone from the thread",
      `This email is signed "${sender.name}" and sent from ${senderEmail}, but in the quoted thread ${sameNameOtherAddress.name} writes from ${sameNameOtherAddress.email}.`,
    );
  }

  const lookalike = participants.find((p) => p.email && lookalikeDomains(senderDomain, p.email.split("@")[1]));
  if (lookalike) {
    add(
      "thread-lookalike",
      "high",
      "The sender's domain imitates a domain from the thread",
      `The conversation includes ${lookalike.email}; this email comes from ${senderEmail} — a lookalike domain continuing someone else's conversation.`,
    );
  }

  const participantOrgs = new Set(participants.map((p) => orgDomain(p.email?.split("@")[1])).filter(Boolean));
  if (senderDomain && participantOrgs.size && messages.length >= 2 && !participantOrgs.has(orgDomain(senderDomain)) && !lookalike) {
    add(
      "thread-outsider",
      "medium",
      "The sender is not part of the conversation they continue",
      `The quoted thread is between ${[...participantOrgs].slice(0, 3).join(", ")}; nobody from ${senderDomain} appears in it.`,
    );
  }

  // 4. The payment request inside the part that looks made up.
  const fabricated = findings.some((f) => f.severity === "high" || f.id === "thread-outsider" || f.id === "thread-pasted");
  if (fabricated && messages.length) {
    const quotedText = lines.slice(messages[0].line).join("\n");
    const bec = analyzeLanguage(quotedText).categories?.bec;
    if (bec?.strongCount) {
      add(
        "thread-payment",
        "high",
        "The payment instruction sits inside the suspect thread",
        `The quoted conversation contains ${bec.strongCount} payment or bank-detail phrase${bec.strongCount === 1 ? "" : "s"} ("${bec.matches.find((m) => m.tier === "strong")?.phrase}") — the "approval" the request relies on is part of what looks fabricated.`,
      );
    }
  }

  return {
    messages: messages.map(({ line, ...m }) => m),
    findings,
    hasReplyHeaders,
    isForward,
  };
}
