'use strict';
// The quick view: one headline, one next step, at most three short reasons.
//
// The five fixtures below are the mock cards from the design: a cold pitch
// relayed by a group, a brand lookalike, a newsletter, a colleague's ordinary
// email, and an expected vendor asking to change bank details. All names and
// domains are fictional.

const test = require('node:test');
const assert = require('node:assert/strict');
const { load, fakeMessage, plain, gmailEvent, VERDICT_LANGUAGE } = require('./harness');

const PROPS = { REPORT_ADDRESS: 'security@acme.com', ORG_DOMAINS: 'acme.com' };
const NOT_A_VERDICT = /\b(scam|phish|spoof|fake|impersonat)/i;
const HEADLINE_CATEGORIES = ['link', 'attachment', 'sender', 'company_claim', 'ask'];

/** A: a cold pitch through the organisation's own group, title only in the signature. */
const RELAYED_PITCH = {
  from: "'Sam Lee' via Acme Hello <hello@acme.com>",
  subject: 'Quick question about your hiring',
  plain: 'Hi team,\n\nI help companies like yours hire engineers. Worth a quick call?\n\n' +
    'Best,\nSam Lee\nFounder, Brightwell\nbrightwell.example\n\n' +
    '--\nYou received this message because you are subscribed to the Google Groups "Acme Hello" group.\n' +
    'To unsubscribe from this group and stop receiving emails from it, send an email to hello+unsubscribe@acme.com.\n',
  html: '<p>Worth a quick call?</p><p><a href="https://brightwell.example/about">brightwell.example</a></p>',
  headers: {
    'Authentication-Results': 'mx.google.com; dkim=pass header.i=@acme.com; spf=pass; dmarc=pass header.from=acme.com',
    'X-Original-Authentication-Results': 'mx.google.com; dkim=pass header.i=@mail.com; spf=pass; dmarc=pass',
    'X-Original-Sender': 'sam.lee.sales@mail.com',
    'List-Id': '"Acme Hello" <hello.acme.com>',
    'List-Post': '<mailto:hello@acme.com>',
    'List-Unsubscribe': '<mailto:hello+unsubscribe@acme.com>',
    Sender: 'hello@acme.com'
  },
  raw: 'From: hello@acme.com\r\n\r\nbody'
};

/** B: brand lookalike with a mismatched link (the PHISH fixture in addon.test.js). */
const LOOKALIKE = {
  from: '"PayPal" <alerts@paypa1-support.com>',
  replyTo: 'collect@evil.top',
  subject: 'Final notice: verify your account',
  html: '<a href="https://evil.example/login">www.paypal.com</a> <a href="https://bit.ly/x1">here</a>',
  plain: 'Verify your account within 24 hours.',
  headers: { 'Authentication-Results': 'mx.google.com; spf=softfail; dkim=none; dmarc=fail' },
  attachments: [{ name: 'invoice.html', type: 'text/html', data: '<html>x</html>' }],
  raw: 'From: alerts@paypa1-support.com\r\n\r\nbody'
};

/** C: a newsletter. */
const NEWSLETTER = {
  from: 'Acme Weekly <news@acmeweekly.com>',
  subject: 'This week at Acme Weekly',
  plain: 'Here is what happened this week.',
  html: '<a href="https://acmeweekly.com/story">Read more</a>',
  headers: {
    'Authentication-Results': 'mx.google.com; dkim=pass header.i=@acmeweekly.com; spf=pass; dmarc=pass',
    'List-Unsubscribe': '<https://acmeweekly.com/u/123>'
  },
  raw: 'From: news@acmeweekly.com\r\n\r\nbody'
};

/** D: a colleague's ordinary email. */
const COLLEAGUE = {
  from: 'Jane Doe <jane@acme.com>',
  subject: 'Lunch on Friday?',
  plain: 'Are you free on Friday?',
  headers: { 'Authentication-Results': 'mx.google.com; dkim=pass header.i=@acme.com; spf=pass; dmarc=pass' },
  raw: 'From: jane@acme.com\r\n\r\nbody'
};

/** E: an expected vendor, passing every domain check, asking to change bank details. */
const VENDOR_BANK_CHANGE = {
  from: 'Accounts <accounts@vendor.example>',
  subject: 'Next invoice',
  plain: 'Hello,\n\nPlease update our bank details for the next invoice. New details attached.\n\nThanks',
  headers: { 'Authentication-Results': 'mx.google.com; dkim=pass header.i=@vendor.example; spf=pass; dmarc=pass' },
  attachments: [{ name: 'new-details.pdf', type: 'application/pdf', data: '%PDF' }],
  raw: 'From: accounts@vendor.example\r\n\r\nbody'
};

const ALL = { RELAYED_PITCH, LOOKALIKE, NEWSLETTER, COLLEAGUE, VENDOR_BANK_CHANGE };

/** Analysis through the real read path, as the card gets it. */
function analyse(message, props) {
  const { ctx } = load({ props: props || PROPS, message: fakeMessage(message) });
  const facts = ctx.readMessageFacts(fakeMessage(message));
  return plain(ctx.analyzeFacts(facts, ctx.parseConfig(props || PROPS)));
}

function cardText(message, props) {
  const { ctx } = load({ props: props || PROPS, message: fakeMessage(message) });
  return JSON.stringify(ctx.onGmailMessageOpen(gmailEvent()));
}

/* ------------------------------ the five cards ------------------------------ */

test('A: a relayed pitch signed as a founder, from a personal mailbox', () => {
  const s = analyse(RELAYED_PITCH).summary;
  assert.equal(s.headline_id, 'company_claim');
  assert.equal(s.headline, 'Writes as a company, from a personal mailbox');
  assert.equal(s.next_step, 'Ask them to reply from the company\'s own address.');
  assert.deepEqual(s.reasons, [
    'Signs as "Founder, Brightwell" but sends from a mail.com address.',
    'Came via your Acme Hello group from an outside address.'
  ]);
});

test('B: a brand lookalike leads with the mismatched link', () => {
  const s = analyse(LOOKALIKE).summary;
  assert.equal(s.headline_id, 'link');
  assert.equal(s.headline, 'Links don\'t go where they say');
  assert.deepEqual(s.reasons, [
    'A link shows "www.paypal.com" but goes to evil.example.',
    'invoice.html is a file type often misused.',
    'Name says PayPal; the address is at paypa1-support.com.'
  ]);
});

test('C: a newsletter is bulk mail, with its passing domain', () => {
  const s = analyse(NEWSLETTER).summary;
  assert.equal(s.headline_id, 'bulk');
  assert.equal(s.next_step, 'Ignore or unsubscribe. Don\'t sign in from it.');
  assert.deepEqual(s.reasons, [
    'Has an unsubscribe header, as newsletters do.',
    'Sent from acmeweekly.com; its domain checks passed.'
  ]);
});

test('D: a colleague\'s ordinary email asks the reader, and gives no all-clear', () => {
  const s = analyse(COLLEAGUE).summary;
  assert.equal(s.headline_id, 'unclear');
  assert.equal(s.headline, 'Your call: did you expect this?');
  assert.deepEqual(s.reasons, [
    'Sent from acme.com, your organisation\'s domain; DMARC pass.',
    'No links or attachments.'
  ]);
});

test('E: an expected vendor asking to change bank details: passing checks are not the end of it', () => {
  const s = analyse(VENDOR_BANK_CHANGE).summary;
  assert.equal(s.headline_id, 'ask');
  assert.equal(s.headline, 'Asks for money, a sign-in or details');
  assert.equal(s.next_step, 'Confirm by phone, on a number you already have.');
  assert.deepEqual(s.reasons, [
    'Asks about a payment or bank details ("bank details").',
    'Sent from vendor.example; its domain checks passed.',
    'A taken-over mailbox passes those checks too.'
  ]);
});

/* ------------------------------- precedence -------------------------------- */

test('precedence follows the table: link > attachment > sender > company_claim > ask > bulk > unclear', () => {
  const { ctx } = load();
  const order = plain(ctx.SUMMARY_HEADLINES.map((h) => h.id));
  assert.deepEqual(order, ['link', 'attachment', 'sender', 'company_claim', 'ask', 'bulk', 'unclear']);
  const cfg = ctx.parseConfig(PROPS);
  const headline = (facts) => ctx.analyzeFacts(facts, cfg).summary.headline_id;

  const base = { from: 'Sam <sam@brightwell.example>', plainBody: 'Hello.' };
  assert.equal(headline(Object.assign({}, base, { plainBody: 'Please confirm your password.' })), 'ask');
  assert.equal(headline(Object.assign({}, base, {
    plainBody: 'Please confirm your password.', from: '"Sam · Founder, Brightwell" <sam@gmail.com>'
  })), 'company_claim');
  assert.equal(headline(Object.assign({}, base, {
    plainBody: 'Please confirm your password.', from: '"Sam · Founder, Brightwell" <sam@gmail.com>',
    replyTo: 'x@elsewhere.example'
  })), 'sender');
  assert.equal(headline(Object.assign({}, base, {
    replyTo: 'x@elsewhere.example', attachments: [{ name: 'a.iso' }]
  })), 'attachment');
  assert.equal(headline(Object.assign({}, base, {
    attachments: [{ name: 'a.iso' }], htmlBody: '<a href="http://203.0.113.9/x">x</a>'
  })), 'link');
  assert.equal(headline(Object.assign({}, base, { listUnsubscribe: '<https://x.example/u>' })), 'bulk');
  assert.equal(headline(Object.assign({}, base, {
    listUnsubscribe: '<https://x.example/u>', plainBody: 'Your gift card is waiting.'
  })), 'ask', 'bulk only when nothing above it fired');
});

test('a lookalike domain is a link headline on a link, a sender headline on the sender', () => {
  const { ctx } = load();
  const cfg = ctx.parseConfig(PROPS);
  const onLink = ctx.analyzeFacts({ from: 'x <x@brightwell.example>', htmlBody: '<a href="https://acrne.com/x">Log in</a>' }, cfg);
  assert.equal(onLink.signals.find((s) => s.id === 'lookalike_domain').evidence.where, 'link');
  assert.equal(onLink.summary.headline_id, 'link');
  const onSender = ctx.analyzeFacts({ from: 'IT <it@acrne.com>' }, cfg);
  assert.equal(onSender.signals.find((s) => s.id === 'lookalike_domain').evidence.where, 'sender');
  assert.equal(onSender.summary.headline_id, 'sender');
});

test('minor findings alone are reasons, not headlines', () => {
  const { ctx } = load();
  const cfg = ctx.parseConfig(PROPS);
  const shortened = ctx.analyzeFacts({ from: 'x <x@brightwell.example>', htmlBody: '<a href="https://bit.ly/a">deck</a>' }, cfg);
  assert.equal(shortened.summary.headline_id, 'unclear');
  assert.deepEqual(plain(shortened.summary.reasons), ['A shortened link hides where it leads.']);
  const pressed = ctx.analyzeFacts({ from: 'x <x@brightwell.example>', plainBody: 'This is urgent.' }, cfg);
  assert.equal(pressed.summary.headline_id, 'unclear');
  assert.deepEqual(plain(pressed.summary.reasons), ['Presses you to act quickly ("urgent").', 'No links or attachments.']);
});

test('an SPF failure explained by forwarding does not drive the headline', () => {
  const { ctx } = load();
  const a = ctx.analyzeFacts({
    from: 'Support <support@vendor.example>',
    authenticationResults: 'mx.google.com; dkim=pass header.i=@vendor.example; spf=softfail; dmarc=pass',
    forwardedTo: 'mike@acme.com', to: 'mike.old@example.com'
  }, ctx.parseConfig(PROPS));
  assert.ok(a.signals.some((s) => s.id === 'spf_fail'));
  assert.equal(a.summary.headline_id, 'unclear');
});

/* ---------------------------------- relay ---------------------------------- */

test('a group\'s List-Unsubscribe does not make relayed mail bulk', () => {
  const bare = Object.assign({}, RELAYED_PITCH, { plain: 'Worth a quick call?', html: '' });
  const a = analyse(bare);
  assert.equal(a.relay.via_list, true);
  assert.equal(a.hasListUnsubscribe, true);
  assert.notEqual(a.summary.headline_id, 'bulk');
  assert.equal(a.summary.headline_id, 'unclear');
  assert.deepEqual(a.summary.reasons, ['Came via your Acme Hello group from an outside address.']);
});

test('the relay line survives under every headline a relayed message can get', () => {
  const variants = {
    link: { html: '<a href="https://evil.example/x">www.acme.com</a>' },
    attachment: { attachments: [{ name: 'setup.iso', data: 'x' }] },
    sender: { replyTo: 'x@elsewhere.example' },
    company_claim: {},
    ask: { plain: 'Please update your bank details immediately. Also urgent. Verification code inside.' },
    unclear: { plain: 'Worth a quick call?', html: '' }
  };
  for (const [expected, extra] of Object.entries(variants)) {
    const message = Object.assign({}, RELAYED_PITCH, extra);
    if (expected === 'link' || expected === 'attachment' || expected === 'sender') {
      message.plain = 'Worth a quick call?';
    }
    const s = analyse(message).summary;
    assert.equal(s.headline_id, expected, 'variant ' + expected);
    assert.ok(s.reasons.length <= 3);
    assert.ok(s.reasons.includes('Came via your Acme Hello group from an outside address.'),
      expected + ': ' + JSON.stringify(s.reasons));
    assert.ok(!s.reasons.some((r) => /your organisation/.test(r)), 'a relayed message never reads as internal');
  }
});

test('a relay with no original sender says the headers do not say', () => {
  const noOriginal = {
    from: 'Announcements <announce@acme.com>',
    subject: 'Payroll details have changed',
    plain: 'Please update your bank details immediately.',
    headers: {
      'Authentication-Results': 'mx.google.com; dkim=pass header.i=@acme.com; spf=pass; dmarc=pass',
      'List-Id': '"Announcements" <announce.acme.com>',
      'List-Unsubscribe': '<mailto:announce+unsubscribe@acme.com>'
    },
    raw: 'From: announce@acme.com\r\n\r\nbody'
  };
  const s = analyse(noOriginal).summary;
  assert.equal(s.headline_id, 'ask');
  assert.equal(s.reasons[s.reasons.length - 1], 'Came via your Announcements group; the headers don\'t say who sent it.');
});

test('a list outside the organisation is "the" group, not "your" group', () => {
  const external = Object.assign({}, RELAYED_PITCH, { plain: 'Worth a quick call?', html: '' });
  const s = analyse(external, { REPORT_ADDRESS: 'security@other.example', ORG_DOMAINS: 'other.example' }).summary;
  assert.deepEqual(s.reasons, ['Came via the Acme Hello group from an outside address.']);
});

/* ------------------------------ wording rules ------------------------------ */

test('no headline, next step or reason gives a verdict, and every reason is short', () => {
  const { ctx } = load();
  const strings = [];
  for (const h of plain(ctx.SUMMARY_HEADLINES)) strings.push(h.headline, h.next_step);
  for (const [name, message] of Object.entries(ALL)) {
    const a = analyse(message);
    for (const r of a.summary.reasons) {
      strings.push(r);
      assert.ok(r.split(/\s+/).length < 12, name + ': reason over eleven words: ' + r);
    }
    for (const sig of a.signals) {
      assert.ok(sig.short, name + ': ' + sig.id + ' has no short form');
      assert.ok(sig.category, name + ': ' + sig.id + ' has no category');
      strings.push(sig.short);
    }
  }
  for (const s of strings) {
    for (const re of VERDICT_LANGUAGE) assert.doesNotMatch(s, re, s);
    assert.doesNotMatch(s, NOT_A_VERDICT, s);
  }
});

test('"Nothing stood out" is never the headline, and there is no all-clear state', () => {
  const { ctx } = load();
  for (const h of plain(ctx.SUMMARY_HEADLINES)) {
    assert.doesNotMatch(h.headline + ' ' + h.next_step, /nothing stood out|all clear|no issues|safe/i);
  }
  for (const message of Object.values(ALL).concat([{ from: 'x <x@y.example>', raw: 'x' }])) {
    const card = cardText(message);
    assert.doesNotMatch(card, /Nothing stood out/i);
    // Colour and icons only reinforce: the headline's words are on the card as
    // plain text inside the styling. Colour rules live in card-style.test.js.
    const headline = ctx.escapeHtml(analyse(message).summary.headline);
    assert.ok(card.includes('<b>' + headline + '</b>'), 'headline words on the card: ' + headline);
  }
});

test('unclear is never the headline when a headline-category finding exists', () => {
  for (const [name, message] of Object.entries(ALL)) {
    const a = analyse(message);
    if (a.signals.some((s) => HEADLINE_CATEGORIES.includes(s.category))) {
      assert.notEqual(a.summary.headline_id, 'unclear', name);
    }
  }
});

/* ---------------------------------- card ----------------------------------- */

/** The widgets added to each section, as [sectionIndex, widgetKind, calls]. */
function sections(card) {
  return card.calls.filter((c) => c[0] === 'addSection').map((c) => c[1][0]);
}

test('the card leads with the headline, next step, reasons and Report; Details and the note are collapsed', () => {
  const { ctx } = load({ props: PROPS, message: fakeMessage(RELAYED_PITCH) });
  const card = plain(ctx.onGmailMessageOpen(gmailEvent()));
  const [top, details, note] = sections(card);

  const widgets = top.calls.filter((c) => c[0] === 'addWidget').map((c) => c[1][0]);
  assert.equal(widgets[0].kind, 'DecoratedText');
  assert.match(widgets[0].calls.find((c) => c[0] === 'setText')[1][0],
    /^<font color="#[0-9a-f]{6}"><b>Writes as a company, from a personal mailbox<\/b><\/font>$/);
  assert.deepEqual(widgets[0].calls.find((c) => c[0] === 'setBottomLabel')[1],
    ['Ask them to reply from the company\'s own address.']);
  // Reasons are one row each, not a paragraph.
  assert.equal(widgets[1].kind, 'DecoratedText');
  assert.match(JSON.stringify(widgets[1]), /Signs as &quot;Founder, Brightwell&quot;/);
  assert.equal(widgets[2].kind, 'DecoratedText');
  assert.match(JSON.stringify(widgets[2]), /Came via your Acme Hello group/);
  assert.equal(widgets[3].kind, 'Divider');
  assert.match(JSON.stringify(widgets[4]),
    /Report sends a copy to security@acme.com. Nothing else leaves your mailbox./);

  // Report is in the fixed footer, so it stays in view.
  const footer = card.calls.find((c) => c[0] === 'setFixedFooter')[1][0];
  const report = footer.calls.find((c) => c[0] === 'setPrimaryButton')[1][0];
  assert.ok(report.calls.some((c) => c[0] === 'setText' && c[1][0] === 'Report to security'));
  assert.ok(report.calls.some((c) => c[0] === 'setTextButtonStyle' && c[1][0] === 'TextButtonStyle.FILLED'));

  for (const [section, header] of [[details, 'Details'], [note, 'Add a note for security']]) {
    assert.ok(section.calls.some((c) => c[0] === 'setHeader' && c[1][0] === header));
    assert.ok(section.calls.some((c) => c[0] === 'setCollapsible' && c[1][0] === true), header);
    assert.ok(section.calls.some((c) => c[0] === 'setNumUncollapsibleWidgets' && c[1][0] === 0), header);
  }
  assert.match(JSON.stringify(details), /How this arrived/);
  assert.match(JSON.stringify(details), /These checks are simple and can miss things/);
  assert.match(JSON.stringify(note), /"setFieldName",\["comment"\]/);
});

test('the note typed in its section still reaches the report', () => {
  const { ctx, calls } = load({ props: PROPS, message: fakeMessage(RELAYED_PITCH) });
  ctx.onReport(gmailEvent({ formInput: { comment: 'Never heard of them' } }));
  const attachments = calls.sendEmail[0].options.attachments;
  const packet = JSON.parse(attachments[attachments.length - 1].getDataAsString());
  assert.equal(packet.reporter.comment, 'Never heard of them');
});

/* --------------------------------- packet ---------------------------------- */

test('the packet carries the summary the reporter saw, additively', () => {
  const { ctx, calls } = load({ props: PROPS, message: fakeMessage(VENDOR_BANK_CHANGE) });
  ctx.onReport(gmailEvent());
  const mail = calls.sendEmail[0];
  const attachments = mail.options.attachments;
  const packet = JSON.parse(attachments[attachments.length - 1].getDataAsString());
  assert.equal(packet.schema_version, 1);
  assert.deepEqual(Object.keys(packet.analysis), ['engine', 'findings', 'checks_clear', 'summary']);
  assert.deepEqual(packet.analysis.summary, {
    headline_id: 'ask',
    headline: 'Asks for money, a sign-in or details',
    next_step: 'Confirm by phone, on a number you already have.',
    reasons: [
      'Asks about a payment or bank details ("bank details").',
      'Sent from vendor.example; its domain checks passed.',
      'A taken-over mailbox passes those checks too.'
    ]
  });
  // Findings keep their v1 shape: id, text, evidence.
  for (const f of packet.analysis.findings) assert.deepEqual(Object.keys(f), ['id', 'text', 'evidence']);
  assert.match(mail.body, /Card headline: Asks for money, a sign-in or details/);
});
