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
 * facts, analysis: from readMessageFacts / analyzeFacts.
 * meta: { reportId, reportedAt (ISO), messageId, comment, orgDomains,
 *         attachments: [{name, type, size, sha256}], eml: {sha256, size} }
 */
function buildReportPacket(facts, analysis, meta) {
  var signals = analysis.signals || [];
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
      from: { name: analysis.sender.name || '', address: analysis.sender.address || '' },
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
    verdict: {
      // Milestone 0 shows evidence and leaves the decision to the person.
      label: signals.length ? 'suspicious' : 'unknown',
      score: null,
      reasons: signals.map(function (s) { return s.text; }),
      engine: 'heuristics-' + BAITCHECK_VERSION,
      ai: { provider: 'none', summary: '', label: '' }
    },
    eml: meta.eml ? { encoding: 'attachment', sha256: meta.eml.sha256, size: meta.eml.size } : null
  };
}

function normaliseAuth_(v) {
  return v === 'pass' || v === 'fail' ? v : (v === 'softfail' ? 'fail' : 'none');
}

/** Plain-text body of the report email: short, readable by a person. */
function buildReportBody(facts, analysis, packet, emlAttached) {
  var lines = [
    'A user reported this message with Baitcheck ' + BAITCHECK_VERSION + '.',
    'The reporter is the sender of this email.',
    '',
    'Subject:  ' + (facts.subject || '(no subject)'),
    'From:     ' + (facts.from || ''),
    'Reply-To: ' + (facts.replyTo || '-'),
    'Date:     ' + (facts.date || ''),
    'Report ID: ' + packet.report_id,
    ''
  ];
  if (packet.reporter.comment) {
    lines.push('Reporter comment:', packet.reporter.comment, '');
  }
  lines.push('What Baitcheck noticed:');
  if (analysis.signals.length) {
    analysis.signals.forEach(function (s) { lines.push('- ' + s.text); });
  } else {
    lines.push('- Nothing in its checks stood out.');
  }
  lines.push('');
  lines.push(emlAttached
    ? 'Attached: reported-message.eml (original, with full headers) and baitcheck-report.json (packet schema v' + REPORT_SCHEMA_VERSION + ').'
    : 'The original message could not be attached; see baitcheck-report.json. Ask the reporter to forward it as an attachment.');
  return lines.join('\n');
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
    emlBlob = Utilities.newBlob(raw, 'message/rfc822', 'reported-message.eml');
    var emlBytes = emlBlob.getBytes();
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
