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
 * How each headline looks. Colour and icon only reinforce the words: every
 * headline reads the same with both removed, and nothing is green (there is
 * no all-clear to show).
 *
 * `icon` is a Material Symbols name. An unknown name renders nothing, so each
 * one is checked against Google's published list (test/card-style.test.js).
 * Caution headlines get a filled icon, a second cue that does not rely on
 * colour.
 *
 * Colour is fixed hex, and Gmail does not swap it for the dark theme, so each
 * tone is a mid tone that reads on both (about 4:1 on white and on Gmail's dark
 * grey). No fixed colour reaches 4.5:1 on both, so colour stays on the short
 * bold headline and every other line keeps the theme's own text colour.
 */
var CARD_TONES = {
  caution: '#d9541e', // warm amber-red
  neutral: '#7a7a7a'  // grey
};
// The Report button only. Gmail picks a contrasting label colour for it.
var CARD_BRAND_COLOR = '#0f6b63';
var HEADLINE_STYLE = {
  link: { icon: 'link_off', tone: 'caution' },
  attachment: { icon: 'attach_file', tone: 'caution' },
  sender: { icon: 'alternate_email', tone: 'caution' },
  company_claim: { icon: 'badge', tone: 'caution' },
  ask: { icon: 'payments', tone: 'caution' },
  bulk: { icon: 'campaign', tone: 'neutral' },
  unclear: { icon: 'help', tone: 'neutral' }
};
var REASON_ICON = 'arrow_right';
var REPORTED_ICON = 'send';
var NOTE_TITLE = 'Note (optional)';

function materialIcon_(name, filled) {
  return CardService.newIconImage().setMaterialIcon(
    CardService.newMaterialIcon().setName(name).setFill(!!filled));
}

/** The headline row: icon, bold headline, next step underneath. */
function headlineWidget_(summary) {
  var style = HEADLINE_STYLE[summary.headline_id] || HEADLINE_STYLE.unclear;
  return CardService.newDecoratedText()
    .setStartIcon(materialIcon_(style.icon, style.tone === 'caution'))
    .setText('<font color="' + CARD_TONES[style.tone] + '"><b>' + escapeHtml(summary.headline) + '</b></font>')
    .setBottomLabel(summary.next_step)
    .setWrapText(true);
}

/** One reason per row, its text aligned under the headline's text. */
function reasonWidget_(reason) {
  return CardService.newDecoratedText()
    .setStartIcon(materialIcon_(REASON_ICON, false))
    .setText(escapeHtml(reason))
    .setWrapText(true);
}

/**
 * The quick view. The first section is the whole first impression (on a phone
 * it is all that shows): a headline, a next step and at most three reasons.
 * The Report button sits in the card's fixed footer, so it stays in view
 * however long the card gets. Everything else is one tap away in "Details".
 *
 * lookupResults: null before "Check links" was pressed.
 */
function buildMessageCard(analysis, config, lookupResults) {
  var card = CardService.newCardBuilder().setHeader(cardHeader_());
  var summary = analysis.summary || summarise(analysis, config.orgDomains);
  var canCheckLinks = config.lookupNames.length > 0 && analysis.urls.length > 0;
  var offerCheckLinks = canCheckLinks && !lookupResults;

  // 1. Headline, next step, reasons, and what the buttons send.
  var top = CardService.newCardSection();
  top.addWidget(headlineWidget_(summary));
  summary.reasons.forEach(function (r) { top.addWidget(reasonWidget_(r)); });

  var checkLinks = offerCheckLinks
    ? CardService.newTextButton().setText('Check links')
      .setTextButtonStyle(CardService.TextButtonStyle.OUTLINED)
      .setOnClickAction(CardService.newAction().setFunctionName('onCheckLinks'))
    : null;
  if (config.reportAddress) {
    // A fixed footer takes a FILLED primary and an optional OUTLINED secondary.
    var footer = CardService.newFixedFooter().setPrimaryButton(CardService.newTextButton()
      .setText('Report to security')
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setBackgroundColor(CARD_BRAND_COLOR)
      .setOnClickAction(CardService.newAction().setFunctionName('onReport')));
    if (checkLinks) footer.setSecondaryButton(checkLinks);
    card.setFixedFooter(footer);
  } else if (checkLinks) {
    // A footer needs a primary button, so without Report the button stays inline.
    top.addWidget(CardService.newButtonSet().addButton(checkLinks));
  }
  top.addWidget(CardService.newDivider());
  top.addWidget(CardService.newTextParagraph().setText(privacyLine_(config, offerCheckLinks)));
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

  // 3. The optional note, collapsed so it does not push the reasons down. The
  // section header says who it is for. The input's title is required and Gmail
  // shows it more than once (as the field's label and in its outline), so it
  // stays short; no hint is set, which would repeat it again.
  if (config.reportAddress) {
    card.addSection(CardService.newCardSection().setHeader('Add a note for security')
      .setCollapsible(true).setNumUncollapsibleWidgets(0)
      .addWidget(CardService.newTextInput().setFieldName('comment')
        .setTitle(NOTE_TITLE).setMultiline(true)));
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
      .addWidget(CardService.newDecoratedText()
        .setStartIcon(materialIcon_(REPORTED_ICON, false))
        .setText('<b>Reported</b>')
        .setBottomLabel(result.message)
        .setWrapText(true))
      .addWidget(CardService.newTextParagraph().setText(
        'Baitcheck did not move or delete the message. Report ID: ' + escapeHtml(result.reportId))))
    .build();
}
