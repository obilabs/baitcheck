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

/**
 * The quick view. The first section is the whole first impression (on a phone
 * it is all that shows): a headline, a next step, at most three reasons, and
 * the Report button. Everything else is one tap away in "Details".
 *
 * lookupResults: null before "Check links" was pressed.
 */
function buildMessageCard(analysis, config, lookupResults) {
  var card = CardService.newCardBuilder().setHeader(cardHeader_());
  var summary = analysis.summary || summarise(analysis, config.orgDomains);
  var canCheckLinks = config.lookupNames.length > 0 && analysis.urls.length > 0;

  // 1. Headline, next step, reasons, actions.
  var top = CardService.newCardSection();
  top.addWidget(CardService.newDecoratedText()
    .setText('<b>' + escapeHtml(summary.headline) + '</b>')
    .setBottomLabel(summary.next_step)
    .setWrapText(true));
  if (summary.reasons.length) {
    top.addWidget(CardService.newTextParagraph().setText(summary.reasons.map(function (r) {
      return '&#8226; ' + escapeHtml(r);
    }).join('<br>')));
  }
  var buttons = CardService.newButtonSet();
  var hasButton = false;
  if (config.reportAddress) {
    buttons.addButton(CardService.newTextButton().setText('Report to security')
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setOnClickAction(CardService.newAction().setFunctionName('onReport')));
    hasButton = true;
  }
  if (canCheckLinks && !lookupResults) {
    buttons.addButton(CardService.newTextButton().setText('Check links')
      .setTextButtonStyle(CardService.TextButtonStyle.OUTLINED)
      .setOnClickAction(CardService.newAction().setFunctionName('onCheckLinks')));
    hasButton = true;
  }
  if (hasButton) top.addWidget(buttons);
  top.addWidget(CardService.newTextParagraph().setText(privacyLine_(config, canCheckLinks && !lookupResults)));
  card.addSection(top);

  // 2. Details, collapsed: how it arrived, every finding in full, the context.
  var details = CardService.newCardSection().setHeader('Details')
    .setCollapsible(true).setNumUncollapsibleWidgets(0);
  // A list re-sends someone else's message under its own address, so this goes
  // first: who really sent it changes how every line below reads.
  if (analysis.relayNotes && analysis.relayNotes.length) {
    details.addWidget(CardService.newTextParagraph().setText('<b>How this arrived</b><br>' +
      analysis.relayNotes.map(escapeHtml).join('<br>')));
  }
  if (analysis.signals.length) {
    details.addWidget(CardService.newTextParagraph().setText('<b>What the checks found</b><br>' +
      analysis.signals.map(function (s) { return '&#8226; ' + escapeHtml(s.text); }).join('<br>')));
  }
  if (analysis.context.length) {
    details.addWidget(CardService.newTextParagraph().setText('<b>Context</b><br>' +
      analysis.context.map(escapeHtml).join('<br>')));
  }
  // The receiving server's results, only when it recorded any (the DMARC check
  // runs exactly when an Authentication-Results header is present).
  var a = analysis.authentication;
  if (a && (analysis.checksRun || []).indexOf('dmarc_fail') !== -1) {
    details.addWidget(CardService.newTextParagraph().setText(escapeHtml(
      'As delivered: SPF ' + a.spf + ', DKIM ' + a.dkim + ', DMARC ' + a.dmarc + '.')));
  }
  details.addWidget(CardService.newTextParagraph().setText('These checks are simple and can miss things.'));
  card.addSection(details);

  // 3. The optional note, collapsed so it does not push the Report button down.
  if (config.reportAddress) {
    card.addSection(CardService.newCardSection().setHeader('Add a note for security')
      .setCollapsible(true).setNumUncollapsibleWidgets(0)
      .addWidget(CardService.newTextInput().setFieldName('comment')
        .setTitle('Note for your security team (optional)').setMultiline(true)));
  }

  // 4. Link reputation, only once "Check links" was pressed.
  if (canCheckLinks && lookupResults) {
    var links = CardService.newCardSection().setHeader('Link reputation');
    renderLookupResults_(links, lookupResults);
    card.addSection(links);
  }

  return card.build();
}

/** One sentence on what the buttons send, so nothing leaves unannounced. */
function privacyLine_(config, offersLinkCheck) {
  var parts = [];
  if (config.reportAddress) {
    parts.push('Report sends a copy to ' + escapeHtml(config.reportAddress) + '.');
  } else {
    parts.push('Reporting is not set up yet. Ask your admin to set REPORT_ADDRESS.');
  }
  if (offersLinkCheck) {
    parts.push('Check links sends only the link addresses (up to ' + MAX_LOOKUP_URLS + ') to ' +
      escapeHtml(config.lookupNames.map(function (s) { return LOOKUP_LABELS[s]; }).join(', ')) + '.');
  }
  parts.push(config.reportAddress || offersLinkCheck
    ? 'Nothing else leaves your mailbox.'
    : 'Nothing leaves your mailbox.');
  return parts.join(' ');
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
