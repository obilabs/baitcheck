/**
 * Baitcheck: Gmail add-on entry points and cards.
 *
 * Opening a message runs local checks only. No network requests are made
 * until the user presses "Check links" (and the admin enabled a lookup
 * service) or "Report to security".
 *
 * Licence: Apache-2.0. Copyright 2026 Obilabs.
 */

/** Homepage trigger: shown when the add-on is opened with no message selected. */
function onHomepage() {
  return CardService.newCardBuilder()
    .setHeader(cardHeader_())
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph()
      .setText('Open an email to see what Baitcheck notices about it.')))
    .build();
}

/** Contextual trigger: a message was opened. Local checks only. */
function onGmailMessageOpen(e) {
  var ctx = loadMessage_(e);
  return buildMessageCard(ctx.analysis, ctx.config, null);
}

/** Button: look up this message's links with the admin-enabled services. */
function onCheckLinks(e) {
  var ctx = loadMessage_(e);
  var results = checkUrls(ctx.analysis.urls, ctx.config);
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(buildMessageCard(ctx.analysis, ctx.config, results)))
    .build();
}

/** Button: send the report to the configured security address. */
function onReport(e) {
  var ctx = loadMessage_(e);
  var comment = (e.formInput && e.formInput.comment) || '';
  var result;
  try {
    result = sendReport(ctx.msg, ctx.facts, ctx.analysis, ctx.config, comment);
  } catch (err) {
    console.error('Baitcheck: report failed: ' + err);
    result = { ok: false, message: 'Could not send the report. Please forward the message to your security team.' };
  }
  var response = CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(result.message));
  if (result.ok) {
    response.setNavigation(CardService.newNavigation().updateCard(buildReportedCard(result)));
  }
  return response.build();
}

/* --------------------------------- loading -------------------------------- */

function loadMessage_(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var msg = GmailApp.getMessageById(e.gmail.messageId);
  var config = getConfig();
  var facts = readMessageFacts(msg);
  facts.messageId = e.gmail.messageId;
  return { msg: msg, config: config, facts: facts, analysis: analyzeFacts(facts, config) };
}

/** Reads the fields the heuristics need. Attachment names only, not content. */
function readMessageFacts(msg) {
  var attachments = [];
  try {
    attachments = msg.getAttachments({ includeInlineImages: false }).map(function (a) {
      return { name: a.getName(), type: a.getContentType(), size: a.getSize() };
    });
  } catch (err) {
    console.warn('Baitcheck: could not list attachments: ' + err);
  }
  var date = msg.getDate();
  return {
    from: msg.getFrom() || '',
    replyTo: msg.getReplyTo() || '',
    returnPath: msg.getHeader('Return-Path') || '',
    subject: msg.getSubject() || '',
    date: date ? new Date(date).toISOString() : '',
    htmlBody: msg.getBody() || '',
    plainBody: msg.getPlainBody() || '',
    // The RFC 5322 Message-ID, which is not the Gmail message id: a receiver
    // needs it to find the same message in mail logs or in another mailbox.
    messageIdHeader: msg.getHeader('Message-ID') || msg.getHeader('Message-Id') || '',
    authenticationResults: msg.getHeader('Authentication-Results') || '',
    listUnsubscribe: msg.getHeader('List-Unsubscribe') || '',
    // Headers that show a mailing list, group or forwarder re-sent the
    // message. getHeader reads the already-loaded message, so this costs no
    // extra request and keeps the card inside the add-on's time budget.
    listId: msg.getHeader('List-Id') || '',
    listPost: msg.getHeader('List-Post') || '',
    mailingList: msg.getHeader('Mailing-list') || '',
    beenThere: msg.getHeader('X-BeenThere') || '',
    sender: msg.getHeader('Sender') || '',
    originalSender: msg.getHeader('X-Original-Sender') || '',
    originalFrom: msg.getHeader('X-Original-From') || '',
    originalAuthenticationResults: msg.getHeader('X-Original-Authentication-Results') || '',
    // Alias and forwarding evidence: which address the message was actually
    // delivered to, versus who it was addressed to.
    deliveredTo: msg.getHeader('Delivered-To') || '',
    forwardedTo: msg.getHeader('X-Forwarded-To') || '',
    forwardedFor: msg.getHeader('X-Forwarded-For') || '',
    to: msg.getHeader('To') || '',
    cc: msg.getHeader('Cc') || '',
    attachments: attachments
  };
}

/* ---------------------------------- cards --------------------------------- */

function cardHeader_() {
  // No product name here: Gmail already shows "Baitcheck" above the card, so a
  // title repeated it. The one line the reader gets is the stance.
  return CardService.newCardHeader().setTitle('Evidence first. You decide.');
}

/** lookupResults: null before "Check links" was pressed. */
function buildMessageCard(analysis, config, lookupResults) {
  var card = CardService.newCardBuilder().setHeader(cardHeader_());

  var summary = CardService.newCardSection();
  var n = analysis.signals.length;
  summary.addWidget(CardService.newDecoratedText()
    .setText(n ? '<b>' + n + ' thing' + (n === 1 ? '' : 's') + ' worth a closer look</b>' : '<b>Nothing stood out in these checks</b>')
    .setBottomLabel('Local checks only. Nothing has left your mailbox.')
    .setWrapText(true));
  analysis.signals.forEach(function (s) {
    summary.addWidget(CardService.newTextParagraph().setText('&#8226; ' + escapeHtml(s.text)));
  });
  if (!n) {
    summary.addWidget(CardService.newTextParagraph().setText(
      'These checks are simple and can miss things. If you did not expect this message, treat links and attachments with care.'));
  }
  card.addSection(summary);

  // A list re-sends someone else's message under its own address, so this goes
  // above the rest: who really sent it changes how every line below reads.
  if (analysis.relayNotes && analysis.relayNotes.length) {
    var relay = CardService.newCardSection().setHeader('How this arrived');
    analysis.relayNotes.forEach(function (note) {
      relay.addWidget(CardService.newTextParagraph().setText(escapeHtml(note)));
    });
    card.addSection(relay);
  }

  if (analysis.context.length) {
    var ctx = CardService.newCardSection().setHeader('Context');
    analysis.context.forEach(function (c) {
      ctx.addWidget(CardService.newTextParagraph().setText(escapeHtml(c)));
    });
    card.addSection(ctx);
  }

  if (config.lookupNames.length && analysis.urls.length) {
    var links = CardService.newCardSection().setHeader('Link reputation');
    if (!lookupResults) {
      links.addWidget(CardService.newTextParagraph().setText(
        'Sends only the link addresses (up to ' + MAX_LOOKUP_URLS + ') to: ' +
        escapeHtml(config.lookupNames.map(function (s) { return LOOKUP_LABELS[s]; }).join(', ')) + '.'));
      links.addWidget(CardService.newTextButton().setText('Check links')
        .setOnClickAction(CardService.newAction().setFunctionName('onCheckLinks')));
    } else {
      renderLookupResults_(links, lookupResults);
    }
    card.addSection(links);
  }

  var report = CardService.newCardSection().setHeader('Report');
  if (config.reportAddress) {
    report.addWidget(CardService.newTextInput().setFieldName('comment').setTitle('Note for your security team (optional)').setMultiline(true));
    report.addWidget(CardService.newTextButton().setText('Report to security')
      .setOnClickAction(CardService.newAction().setFunctionName('onReport')));
    report.addWidget(CardService.newTextParagraph().setText(
      'Sends a copy of this message to ' + escapeHtml(config.reportAddress) + '. The message stays in your mailbox.'));
  } else {
    report.addWidget(CardService.newTextParagraph().setText(
      'Reporting is not set up yet. Ask your admin to set REPORT_ADDRESS.'));
  }
  card.addSection(report);

  return card.build();
}

function renderLookupResults_(section, results) {
  var listed = results.filter(function (r) { return r.status === 'listed'; });
  var errors = results.filter(function (r) { return r.status === 'error'; });
  if (listed.length) {
    listed.forEach(function (r) {
      section.addWidget(CardService.newTextParagraph().setText(
        '&#8226; <b>' + escapeHtml(LOOKUP_LABELS[r.service]) + '</b> lists ' + escapeHtml(trunc(r.url, 80)) +
        (r.detail ? ' (' + escapeHtml(r.detail) + ')' : '')));
    });
  } else {
    section.addWidget(CardService.newTextParagraph().setText(
      'None of the checked links are on the enabled lists. Not being listed does not make a link safe.'));
  }
  if (errors.length) {
    section.addWidget(CardService.newTextParagraph().setText(
      errors.length + ' lookup(s) could not be completed.'));
  }
}

function buildReportedCard(result) {
  return CardService.newCardBuilder()
    .setHeader(cardHeader_())
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText('<b>Reported.</b> ' + escapeHtml(result.message)))
      .addWidget(CardService.newTextParagraph().setText(
        'Baitcheck did not move or delete the message. Report ID: ' + escapeHtml(result.reportId))))
    .build();
}
