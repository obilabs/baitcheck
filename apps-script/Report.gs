/**
 * Baitcheck: report packet.
 *
 * `buildReportPacket` is pure and follows docs/REPORT-PACKET.md (schema v1,
 * draft). `sendReport` emails the packet plus the original message as .eml to
 * the admin-configured REPORT_ADDRESS, from the reporting user's own mailbox.
 *
 * Licence: Apache-2.0. Copyright 2026 Obilabs.
 */

var REPORT_SCHEMA_VERSION = 1;

/**
 * The original travels inside a zip. See the comment in sendReport: Gmail's
 * send API re-types an attached .eml by sniffing its contents, so neither
 * message/rfc822 nor application/octet-stream survives delivery.
 */
var EML_ARCHIVE_NAME = 'reported-message.zip';
var EML_INNER_NAME = 'reported-message.eml';
var EML_CONTENT_TYPE = 'application/zip';

/**
 * facts, analysis: from readMessageFacts / analyzeFacts.
 * meta: { reportId, reportedAt (ISO), messageId, comment, orgDomains,
 *         attachments: [{name, type, size, sha256}], eml: {sha256, size},
 *         ai: { provider, sent, summary, label } (optional; AI is off by
 *         default, so the default is provider 'none' and sent false) }
 */
function buildReportPacket(facts, analysis, meta) {
  var signals = analysis.signals || [];
  var headers = buildHeaderFacts(facts, analysis);
  return {
    schema_version: REPORT_SCHEMA_VERSION,
    report_id: meta.reportId,
    reported_at: meta.reportedAt,
    tenant: { domain: (meta.orgDomains && meta.orgDomains[0]) || null },
    // The reporter is the sender of the report email; milestone 0 does not
    // request the extra scope needed to read the user's address here.
    reporter: { email: null, comment: meta.comment || '' },
    message: {
      gmail_message_id: meta.messageId,
      subject: facts.subject || '',
      // `from` is the header as delivered. When a list re-sent the message
      // that header IS the list, so `relay` below carries the original sender
      // and the original message's own authentication results; a receiver must
      // read `relay.via_list` before treating `from` as the sender.
      from: { name: (analysis.from || analysis.sender).name || '', address: (analysis.from || analysis.sender).address || '' },
      relay: buildRelayField_(analysis),
      reply_to: analysis.sender.reply_to || '',
      return_path: analysis.sender.return_path || '',
      date: facts.date || '',
      authentication: {
        spf: normaliseAuth_(analysis.authentication.spf),
        dkim: normaliseAuth_(analysis.authentication.dkim),
        dmarc: normaliseAuth_(analysis.authentication.dmarc),
        dkim_domain: analysis.authentication.dkim_domain || ''
      },
      has_list_unsubscribe: !!analysis.hasListUnsubscribe,
      attachments: (meta.attachments || []).map(function (a) {
        return { name: a.name, type: a.type, size: a.size, sha256: a.sha256 || '' };
      })
    },
    indicators: {
      urls: (analysis.links || []).map(function (l) {
        return { href: l.href, text: l.text, host: l.host, shortener: l.shortener, ip_literal: l.ip_literal };
      }),
      domains: (analysis.lookalikes || []).map(function (l) {
        // Domain age (RDAP) is not looked up in milestone 0.
        return { domain: l.domain, lookalike_of: l.lookalike_of, registered: null, age_days: null };
      }),
      hashes: (meta.attachments || []).map(function (a) { return a.sha256; }).filter(function (h) { return !!h; })
    },
    // The same heuristic result as `verdict.reasons`, as data instead of prose,
    // plus the checks that ran and found nothing. Added 2026-09-21, schema
    // still v1: `verdict.reasons` keeps its meaning and its wording.
    analysis: buildAnalysisField_(analysis),
    // The headers a triager or a model actually needs, each as received. A
    // filtered set on purpose, not every header: see docs/REPORT-PACKET.md.
    headers: headers,
    verdict: {
      // Milestone 0 shows evidence and leaves the decision to the person.
      label: signals.length ? 'suspicious' : 'unknown',
      score: null,
      reasons: signals.map(function (s) { return s.text; }),
      engine: 'heuristics-' + BAITCHECK_VERSION,
      ai: buildAiField_(headers, analysis, facts, meta)
    },
    eml: meta.eml
      ? {
          // `encoding` says how the .eml travels. It is inside a zip archive so
          // no receiving client can render the reported message (see
          // sendReport). sha256 and size are of the .eml itself, not the zip.
          encoding: 'attachment',
          content_type: EML_CONTENT_TYPE,
          archive: EML_ARCHIVE_NAME,
          file: EML_INNER_NAME,
          sha256: meta.eml.sha256,
          size: meta.eml.size
        }
      : null
  };
}

/**
 * `message.relay` (schema v1 addition). Always present so a receiver can tell
 * "not via a list" from "an older add-on that did not look":
 *   { via_list, list, original_sender, original_authentication }
 * `original_sender` is null when the headers do not say who sent the original;
 * a receiver must not fall back to `message.from` in that case.
 */
function buildRelayField_(analysis) {
  var relay = (analysis && analysis.relay) || { via_list: false };
  var forwarded = relay.forwarded
    ? { evidence: relay.forwarded.evidence, to: relay.forwarded.to || '', from: relay.forwarded.from || '' }
    : null;
  if (!relay.via_list) {
    return {
      via_list: false, list: null, original_sender: null, original_authentication: null, forwarded: forwarded
    };
  }
  var list = relay.list || {};
  var original = relay.original;
  var auth = relay.original_authentication;
  return {
    via_list: true,
    list: { address: list.address || '', id: list.id || '', name: list.name || '' },
    original_sender: original
      ? { name: original.name || '', address: original.address || '', domain: original.domain || '' }
      : null,
    original_authentication: auth
      ? {
          spf: normaliseAuth_(auth.spf),
          dkim: normaliseAuth_(auth.dkim),
          dmarc: normaliseAuth_(auth.dmarc),
          dkim_domain: auth.dkim_domain || ''
        }
      : null,
    forwarded: forwarded
  };
}

/**
 * `analysis` (schema v1 addition): the heuristic result as data.
 *   { engine, findings: [{id, text, evidence}], checks_clear: [id],
 *     summary: {headline_id, headline, next_step, reasons: [string]} }
 * `findings` are the checks that fired, each with what it matched on.
 * `checks_clear` are the checks that ran with the input they need and found
 * nothing. An id in neither list was NOT run — no header to run it against —
 * which a receiver must not read as "clear".
 */
function buildAnalysisField_(analysis) {
  var signals = (analysis && analysis.signals) || [];
  var fired = {};
  signals.forEach(function (s) { fired[s.id] = true; });
  return {
    engine: 'heuristics-' + BAITCHECK_VERSION,
    findings: signals.map(function (s) {
      return { id: s.id, text: s.text, evidence: s.evidence || {} };
    }),
    checks_clear: ((analysis && analysis.checksRun) || []).filter(function (id) { return !fired[id]; }),
    // The quick view the reporter saw: headline id and text, next step and
    // the short reasons, so the security team reads the same first lines.
    summary: summaryField_(analysis)
  };
}

function summaryField_(analysis) {
  var s = (analysis && analysis.summary) || summarise(analysis || {}, []);
  return {
    headline_id: s.headline_id,
    headline: s.headline,
    next_step: s.next_step,
    reasons: (s.reasons || []).slice()
  };
}

/**
 * `headers` (schema v1 addition): the header facts a triager or a model needs,
 * each as received. Deliberately a short, fixed list rather than every header:
 * a full dump is large, and headers carry personal data about people who never
 * reported anything (every Received hop, other recipients, internal routing and
 * scanner headers). A header the message did not carry is omitted, never sent
 * as null, so "absent" is visible as absence.
 */
function buildHeaderFacts(facts, analysis) {
  facts = facts || {};
  var from = (analysis && (analysis.from || analysis.sender)) || {};
  var headers = {};
  if (from.name || from.address) {
    headers.from = { name: from.name || '', address: from.address || '' };
  }
  addHeader_(headers, 'reply_to', facts.replyTo);
  addHeader_(headers, 'return_path', facts.returnPath);
  addHeader_(headers, 'sender', facts.sender);
  addHeader_(headers, 'date', facts.date);
  addHeader_(headers, 'message_id', facts.messageIdHeader);
  addHeader_(headers, 'list_id', facts.listId);
  addHeader_(headers, 'x_been_there', facts.beenThere);
  addHeader_(headers, 'x_original_sender', facts.originalSender || facts.originalFrom);
  addHeader_(headers, 'delivered_to', facts.deliveredTo);
  addHeader_(headers, 'authentication_results', facts.authenticationResults);
  addHeader_(headers, 'x_original_authentication_results', facts.originalAuthenticationResults);
  // Presence only: the value is a mailto or an unsubscribe URL that identifies
  // the recipient, and only its presence is evidence of bulk mail.
  headers.has_list_unsubscribe = !!String(facts.listUnsubscribe || '').trim();
  return headers;
}

function addHeader_(headers, key, value) {
  var v = String(value == null ? '' : value).trim();
  if (v) headers[key] = v;
}

/**
 * Exactly what an administrator would be sending if they turned AI on, and
 * whether it was in fact sent.
 *
 * AI is off by default, so `sent` is false and the prompt travels unsent and
 * marked as such. That is the point: "nothing leaves the mailbox" is easy to
 * assert and hard to verify, and the prompt on a real message is the
 * verifiable form of it. The text comes from buildAiPrompt (AiPrompt.gs), the
 * one place a prompt is written, so a later AI call sends this same string.
 */
function buildAiField_(headers, analysis, facts, meta) {
  var ai = (meta && meta.ai) || {};
  var sent = !!ai.sent;
  return {
    provider: ai.provider || 'none',
    sent: sent,
    prompt_template_version: AI_PROMPT_TEMPLATE_VERSION,
    prompt: buildAiPrompt(headers, analysis, (facts && facts.subject) || ''),
    prompt_includes_message_body: !!AI_PROMPT_INCLUDES_BODY,
    note: sent ? AI_PROMPT_SENT_NOTE : AI_PROMPT_NOT_SENT_NOTE,
    summary: ai.summary || '',
    label: ai.label || ''
  };
}

function normaliseAuth_(v) {
  return v === 'pass' || v === 'fail' ? v : (v === 'softfail' ? 'fail' : 'none');
}

/**
 * Google Admin console destinations offered under "Suggested actions".
 *
 * Verified 2026-09-16 against Google's own help pages, which print these deep
 * links (the console itself is behind a sign-in and cannot be fetched):
 * - /ac/apps/gmail/spam        Blocked senders, under Gmail's
 *   "Spam, phishing and malware" settings.
 * - /ac/emaillogsearch         Email Log Search, available on every Workspace
 *   edition; shows who else received a message.
 * - /ac/sc/investigation       Security investigation tool. Google lists the
 *   Gmail messages data source (the one that can search mailboxes and delete
 *   copies) for Frontline Plus, Enterprise Plus and Education Plus only, so
 *   the wording never promises the reader has it.
 */
var ADMIN_BLOCKED_SENDERS_URL = 'https://admin.google.com/ac/apps/gmail/spam';
var ADMIN_EMAIL_LOG_SEARCH_URL = 'https://admin.google.com/ac/emaillogsearch';
var ADMIN_INVESTIGATION_URL = 'https://admin.google.com/ac/sc/investigation';

var SECTION_HEADINGS = [
  '1. WHAT HAPPENED',
  '2. WHAT BAITCHECK NOTICED',
  '3. THE FACTS',
  '4. SUGGESTED ACTIONS',
  '5. ATTACHED',
  '6. WHAT BAITCHECK DID NOT DO'
];

/**
 * Plain-text body of the report email, in the order a person triages: what
 * happened, what was noticed, the facts, what they could do, what is attached,
 * what Baitcheck did not do. Short enough to read on a phone; the JSON packet
 * carries the full structure.
 */
function buildReportBody(facts, analysis, packet, emlAttached) {
  var sender = analysis.sender || {};
  var auth = analysis.authentication || {};
  var lines = [];

  lines.push('A user reported this message with Baitcheck ' + BAITCHECK_VERSION + '.');
  lines.push('Baitcheck reports what it noticed. It gives no verdict; you decide.');
  lines.push('');

  lines.push(SECTION_HEADINGS[0]);
  lines.push('Reporter:    the sender of this email');
  lines.push('Reported at: ' + packet.reported_at);
  lines.push('Subject:     ' + oneLine_(facts.subject || '(no subject)'));
  lines.push('Sent:        ' + (facts.date || '(unknown)'));
  lines.push('Their note:  ' + (packet.reporter.comment ? oneLine_(packet.reporter.comment) : '(none)'));
  lines.push('');

  lines.push(SECTION_HEADINGS[1]);
  lines.push('Card headline: ' + packet.analysis.summary.headline);
  if (analysis.signals && analysis.signals.length) {
    analysis.signals.forEach(function (s) { lines.push('- ' + s.text); });
  } else {
    lines.push('- Nothing stood out in its checks. They are simple and miss things;');
    lines.push('  the reporter still thought this was worth sending.');
  }
  lines.push('');

  lines.push(SECTION_HEADINGS[2]);
  var relay = (analysis.relay && analysis.relay.via_list) ? analysis.relay : null;
  var from = analysis.from || sender;
  if (relay) {
    var list = relay.list || {};
    lines.push('Arrived via:  a mailing list or group' +
      (list.address || list.name ? ' (' + oneLine_([list.name, list.address].filter(Boolean).join(' ')) + ')' : '') +
      ', which re-sent it');
    lines.push('From header:  ' + oneLine_((from.name ? from.name + ' ' : '') + '<' + (from.address || 'none') + '>') +
      '  <- the list, not the sender');
    lines.push(relay.original
      ? 'Original sender: ' + oneLine_((relay.original.name ? relay.original.name + ' ' : '')) +
        '<' + relay.original.address + '>'
      : 'Original sender: not stated in the headers. Baitcheck does not know who sent it;');
    if (!relay.original) lines.push('                 do not read the list address as the sender.');
  } else {
    lines.push('Display name: ' + oneLine_(sender.name || '(none)'));
    lines.push('From address: ' + (sender.address || '(none)'));
  }
  var forwarded = analysis.relay && analysis.relay.forwarded;
  if (forwarded) {
    lines.push(forwarded.evidence === 'header'
      ? 'Forwarded:    ' + (forwarded.from ? 'from ' + forwarded.from + ' ' : '') +
        (forwarded.to ? 'to ' + forwarded.to : '') + ' (forwarding does not rewrite From)'
      : 'Delivered-To: ' + forwarded.to + ', which is not on the To or Cc line (alias, group,' +
        ' forwarding rule or Bcc; the headers do not say which)');
  }
  lines.push('Reply-To:     ' + (sender.reply_to || '(none)'));
  lines.push('Return-Path:  ' + (sender.return_path || '(none)'));
  var delivered = 'SPF ' + (auth.spf || 'none') + ' / DKIM ' + (auth.dkim || 'none') +
    (auth.dkim_domain ? ' (' + auth.dkim_domain + ')' : '') + ' / DMARC ' + (auth.dmarc || 'none');
  if (relay) {
    var orig = relay.original_authentication;
    lines.push('Before the list: ' + (orig
      ? 'SPF ' + orig.spf + ' / DKIM ' + orig.dkim + (orig.dkim_domain ? ' (' + orig.dkim_domain + ')' : '') +
        ' / DMARC ' + orig.dmarc
      : 'not recorded in the headers'));
    lines.push('As delivered:    ' + delivered + '  <- the list re-signed it; this is the');
    lines.push('                 list\'s result, not the original sender\'s');
  } else {
    lines.push(delivered);
  }
  var hosts = linkDomains_(analysis);
  lines.push(hosts.length
    ? 'Link domains (' + hosts.length + '): ' + hosts.slice(0, 8).join(', ') +
      (hosts.length > 8 ? ', +' + (hosts.length - 8) + ' more in the packet' : '')
    : 'Link domains: none');
  var attachments = packet.message.attachments || [];
  if (attachments.length) {
    lines.push('Attachments in the message (' + attachments.length + '):');
    attachments.slice(0, 5).forEach(function (a) {
      lines.push('- ' + a.name + '  sha256 ' + (a.sha256 || '(not hashed)'));
    });
    if (attachments.length > 5) lines.push('- +' + (attachments.length - 5) + ' more in the packet');
  } else {
    lines.push('Attachments in the message: none');
  }
  lines.push('');

  buildSuggestedActions_(analysis).forEach(function (l) { lines.push(l); });
  lines.push('');

  lines.push(SECTION_HEADINGS[4]);
  if (emlAttached) {
    lines.push('- reported-message.zip: contains reported-message.eml, the original with');
    lines.push('  full headers. It is zipped on purpose: mail clients and Google Groups');
    lines.push('  render an attached email inline, which would load its remote images and');
    lines.push('  put a live link in front of whoever reads this. Open it deliberately.');
  } else {
    lines.push('- The original could not be attached. Ask the reporter to forward it as an');
    lines.push('  attachment (Gmail: More > Forward as attachment).');
  }
  lines.push('- baitcheck-report.json: the same facts as structured data (schema v' + REPORT_SCHEMA_VERSION + ').');
  lines.push('Report ID: ' + packet.report_id);
  lines.push('');

  lines.push(SECTION_HEADINGS[5]);
  lines.push('Baitcheck did not move, delete or quarantine the message, and cannot:');
  lines.push('it does not ask for the scope that would let it. The reporter still has the');
  lines.push('message in their mailbox.');

  return lines.join('\n');
}

/** Section 4: suggestions with a reason and a place to do them. Never instructions. */
function buildSuggestedActions_(analysis) {
  var sender = analysis.sender || {};
  var address = sender.address || '';
  var domain = sender.domain || '';
  var lookalike = (analysis.lookalikes || [])[0];
  var relay = (analysis.relay && analysis.relay.via_list) ? analysis.relay : null;
  var lines = [SECTION_HEADINGS[3]];
  lines.push('Suggestions for whoever triages this, with the reason for each.');
  lines.push('Baitcheck cannot carry any of them out and will not ask to.');
  if (relay) {
    // The From header here is one of your own lists. Blocking it would cut off
    // the group for everyone, so the addresses below are the original sender's.
    lines.push('');
    lines.push('This message came through a list' +
      (relay.list && relay.list.address ? ' (' + relay.list.address + ')' : '') + ', so the addresses below are');
    lines.push(relay.original
      ? 'the original sender\'s. Blocking the list address would stop the list itself.'
      : 'empty: the headers do not say who sent the original. Blocking the list address');
    if (!relay.original) lines.push('would stop the list itself, not the sender.');
  }
  lines.push('');

  lines.push('a) Block the sender address' + (address ? ' (' + address + ')' : ''));
  lines.push('   Why: stops this exact address reaching anyone in your organisation.');
  lines.push('   Narrow and easy to undo. Whoever sent it can register another');
  lines.push('   address, so treat it as a stop-gap.');
  lines.push('   Gmail > Spam, phishing and malware > Blocked senders:');
  lines.push('   ' + ADMIN_BLOCKED_SENDERS_URL);
  lines.push('');

  lines.push('b) Block the sending domain' + (domain ? ' (' + domain + ')' : ''));
  lines.push('   Why: covers every address at that domain, not just this one.' +
    (lookalike ? ' ' + lookalike.domain + ' looks like ' + lookalike.lookalike_of + '.' : ''));
  lines.push('   Wider, so check first that no mail you want comes from it.');
  lines.push('   Same screen as above: ' + ADMIN_BLOCKED_SENDERS_URL);
  lines.push('');

  lines.push('c) Find out who else received it');
  lines.push('   Why: one report usually means several copies were delivered.');
  lines.push('   Email Log Search shows delivery for a subject or sender and is on every');
  lines.push('   Workspace edition: ' + ADMIN_EMAIL_LOG_SEARCH_URL);
  lines.push('   Searching mailboxes and removing copies needs the security investigation');
  lines.push('   tool, which Google lists for Frontline Plus, Enterprise Plus and');
  lines.push('   Education Plus only, so your edition may not have it:');
  lines.push('   ' + ADMIN_INVESTIGATION_URL);
  lines.push('');

  lines.push('d) Do nothing');
  lines.push('   Why: if the facts above explain the message (a sender the reporter deals');
  lines.push('   with, a domain that authenticated, a newsletter), close the report and');
  lines.push('   tell the reporter. Reporting when unsure is the behaviour you want.');
  return lines;
}

/** Deduplicated link hosts, in the order they appear. */
function linkDomains_(analysis) {
  return uniq((analysis.links || []).map(function (l) { return l.host; }));
}

function oneLine_(s) {
  return String(s == null ? '' : s).replace(/[\r\n]+/g, ' ').slice(0, 300);
}

/**
 * Sends the report. Returns { ok, message }.
 * Never moves or deletes the reported message.
 */
function sendReport(msg, facts, analysis, config, comment) {
  if (!config.reportAddress) {
    return { ok: false, message: 'Reporting is not set up yet. Ask your admin to set REPORT_ADDRESS.' };
  }

  var emlBlob = null;
  var emlMeta = null;
  try {
    var raw = msg.getRawContent();
    // The original goes inside a zip. Two approaches failed in real Gmail:
    //  - message/rfc822: Google Groups renders it inline, loading the reported
    //    message's remote images and tracking pixels from the security team's
    //    side and putting a live link one click away.
    //  - application/octet-stream named .eml: GmailApp.sendEmail re-typed the
    //    part as text/html by sniffing its contents and dropped the filename,
    //    so it was rendered anyway (seen in "Show original", 2026-09-20).
    // Nothing renders the contents of a zip, and zipping phishing samples is
    // the usual practice between security teams. The hash below is of the
    // untouched .eml bytes, so a receiver can verify what is inside.
    var inner = Utilities.newBlob(raw, 'message/rfc822', EML_INNER_NAME);
    emlBlob = Utilities.zip([inner], EML_ARCHIVE_NAME);
    var emlBytes = inner.getBytes();
    emlMeta = { sha256: sha256Hex(emlBytes), size: emlBytes.length };
  } catch (err) {
    console.warn('Baitcheck: could not read raw message: ' + err);
  }

  var attachments = [];
  try {
    attachments = msg.getAttachments({ includeInlineImages: false }).map(function (a) {
      var bytes = a.getBytes();
      return { name: a.getName(), type: a.getContentType(), size: a.getSize(), sha256: sha256Hex(bytes) };
    });
  } catch (err) {
    console.warn('Baitcheck: could not hash attachments: ' + err);
  }

  var packet = buildReportPacket(facts, analysis, {
    reportId: Utilities.getUuid(),
    reportedAt: new Date().toISOString(),
    messageId: facts.messageId,
    comment: String(comment || '').slice(0, 2000),
    orgDomains: config.orgDomains,
    attachments: attachments,
    eml: emlMeta
  });

  var files = [];
  if (emlBlob) files.push(emlBlob);
  files.push(Utilities.newBlob(JSON.stringify(packet, null, 2), 'application/json', 'baitcheck-report.json'));

  var subject = '[Baitcheck] User report: ' + String(facts.subject || '(no subject)').replace(/[\r\n]+/g, ' ').slice(0, 150);
  GmailApp.sendEmail(config.reportAddress, subject, buildReportBody(facts, analysis, packet, !!emlBlob), {
    attachments: files,
    name: 'Baitcheck'
  });
  return {
    ok: true,
    reportId: packet.report_id,
    message: emlBlob
      ? 'Sent to your security team. Thank you.'
      : 'Sent to your security team, but the original could not be attached.'
  };
}
