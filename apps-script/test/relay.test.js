'use strict';
// Messages that arrived through a mailing list, group or forwarder.
//
// The shape below is the real one, from a cold sales email that reached the
// owner through the hello@obilabs.dev Google Group on 2026-09-20: Google
// Groups rewrote From to "'Chris Wu' via ObiLabs Hello <hello@obilabs.dev>"
// and re-signed with the group's DKIM key, and Baitcheck called an external
// stranger an internal sender.

const test = require('node:test');
const assert = require('node:assert/strict');
const { load, fakeMessage, plain, gmailEvent } = require('./harness');

const PROPS = { REPORT_ADDRESS: 'security@obilabs.dev', ORG_DOMAINS: 'obilabs.dev' };

/** The message as Google Groups delivered it. */
const GROUP_RELAYED = {
  from: "'Chris Wu' via ObiLabs Hello <hello@obilabs.dev>",
  replyTo: 'chris.wu.sales@mail.com',
  subject: 'Quick question about your engineering hiring',
  plain: 'Hi, I help companies like yours hire offshore engineers. Worth a chat?',
  html: '<p><a href="https://calendly.example/chris">book a time</a></p>',
  headers: {
    'Authentication-Results':
      'mx.google.com; dkim=pass header.i=@obilabs.dev header.s=20230601; spf=pass ' +
      'smtp.mailfrom=hello@obilabs.dev; dmarc=pass header.from=obilabs.dev',
    'X-Original-Authentication-Results':
      'mx.google.com; dkim=pass header.i=@cold-outreach-agency.com header.s=s1; spf=pass ' +
      'smtp.mailfrom=chris@cold-outreach-agency.com; dmarc=pass header.from=cold-outreach-agency.com',
    'X-Original-Sender': 'chris@cold-outreach-agency.com',
    'List-Id': '<hello.obilabs.dev>',
    'List-Post': '<https://groups.google.com/a/obilabs.dev/group/hello/post>, <mailto:hello@obilabs.dev>',
    'List-Unsubscribe': '<mailto:hello+unsubscribe@obilabs.dev>',
    'Mailing-list': 'list hello@obilabs.dev; contact hello+owners@obilabs.dev',
    Sender: 'hello@obilabs.dev',
    'Return-Path': '<hello+bncabc@obilabs.dev>'
  },
  raw: 'From: hello@obilabs.dev\r\nSubject: Quick question\r\n\r\nbody'
};

/** The same relay, but nothing says who sent the original. */
const GROUP_NO_ORIGINAL = {
  from: 'Announcements <announce@obilabs.dev>',
  subject: 'Payroll details have changed',
  plain: 'Please update your bank details immediately.',
  headers: {
    'Authentication-Results': 'mx.google.com; dkim=pass header.i=@obilabs.dev; spf=pass; dmarc=pass',
    'List-Id': '"Announcements" <announce.obilabs.dev>',
    'List-Unsubscribe': '<mailto:announce+unsubscribe@obilabs.dev>',
    Sender: 'announce@obilabs.dev'
  },
  raw: 'From: announce@obilabs.dev\r\n\r\nbody'
};

/** An ordinary newsletter: List-Unsubscribe, but the sender is the sender. */
const NEWSLETTER = {
  from: 'Acme Weekly <news@acmeweekly.com>',
  subject: 'This week at Acme',
  plain: 'Here is what happened this week.',
  headers: {
    'Authentication-Results': 'mx.google.com; dkim=pass header.i=@acmeweekly.com; spf=pass; dmarc=pass',
    'List-Unsubscribe': '<https://acmeweekly.com/u/123>, <mailto:u@acmeweekly.com>',
    'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'
  },
  raw: 'From: news@acmeweekly.com\r\n\r\nbody'
};

/** A genuinely internal message: no list anywhere. */
const INTERNAL = {
  from: 'Jane Doe <jane@obilabs.dev>',
  subject: 'Invoice for August',
  plain: 'Attached.',
  headers: { 'Authentication-Results': 'mx.google.com; dkim=pass header.i=@obilabs.dev; spf=pass; dmarc=pass' },
  raw: 'From: jane@obilabs.dev\r\n\r\nbody'
};

/** Facts as Ui.gs reads them, so detection is tested through the real path. */
function analyse(message, props) {
  const { ctx } = load({ props: props || PROPS, message: fakeMessage(message) });
  const facts = ctx.readMessageFacts(fakeMessage(message));
  return { ctx, facts, analysis: ctx.analyzeFacts(facts, ctx.parseConfig(props || PROPS)) };
}

function cardText(message, props) {
  const { ctx } = load({ props: props || PROPS, message: fakeMessage(message) });
  return JSON.stringify(ctx.onGmailMessageOpen(gmailEvent()));
}

function report(message, props) {
  const { ctx, calls } = load({ props: props || PROPS, message: fakeMessage(message) });
  ctx.onReport(gmailEvent());
  const mail = calls.sendEmail[0];
  const attachments = mail.options.attachments;
  return { body: mail.body, packet: JSON.parse(attachments[attachments.length - 1].getDataAsString()) };
}

/* ------------------------------- detection ------------------------------- */

test('a Google Groups relay is detected, and the list is named', () => {
  const { analysis } = analyse(GROUP_RELAYED);
  const relay = plain(analysis.relay);
  assert.equal(relay.via_list, true);
  assert.equal(relay.list.address, 'hello@obilabs.dev');
  assert.equal(relay.list.id, 'hello.obilabs.dev');
  assert.equal(relay.list.name, 'ObiLabs Hello');
  assert.deepEqual(relay.original, {
    name: 'Chris Wu', address: 'chris@cold-outreach-agency.com', domain: 'cold-outreach-agency.com'
  });
});

/* ------------------------- aliases and forwarders ------------------------- */

/** Gmail's own auto-forwarding names the addresses in a header. */
const AUTO_FORWARDED = {
  from: 'Support <support@vendor.example>',
  subject: 'Your ticket was updated',
  plain: 'Ticket 41 was updated.',
  headers: {
    'Authentication-Results': 'mx.google.com; dkim=pass header.i=@vendor.example; spf=softfail; dmarc=pass',
    'X-Forwarded-To': 'mike@obilabs.dev',
    'X-Forwarded-For': 'mike.old@example.com mike@obilabs.dev',
    To: 'mike.old@example.com',
    'Delivered-To': 'mike@obilabs.dev'
  },
  raw: 'From: support@vendor.example\r\n\r\nbody'
};

/** An alias: delivered somewhere that is not on the To line, and nothing says why. */
const ALIAS_DELIVERED = {
  from: 'Support <support@vendor.example>',
  subject: 'Your ticket was updated',
  plain: 'Ticket 41 was updated.',
  headers: {
    'Authentication-Results': 'mx.google.com; dkim=pass header.i=@vendor.example; spf=pass; dmarc=pass',
    To: 'sales@obilabs.dev',
    'Delivered-To': 'mike@obilabs.dev'
  },
  raw: 'From: support@vendor.example\r\n\r\nbody'
};

test('forwarding is reported, and never as a list: the From header still is the sender', () => {
  const { analysis } = analyse(AUTO_FORWARDED);
  assert.equal(analysis.relay.via_list, false);
  assert.deepEqual(plain(analysis.relay.forwarded),
    { evidence: 'header', to: 'mike@obilabs.dev', from: 'mike.old@example.com' });
  assert.equal(analysis.sender.address, 'support@vendor.example');
  const card = cardText(AUTO_FORWARDED);
  assert.match(card, /This was forwarded from mike\.old@example\.com to mike@obilabs\.dev/);
  assert.match(card, /Forwarding does not change who wrote the message/);
  // A forward breaks SPF by design, so the failure is weighed down, not hidden.
  assert.ok(analysis.signals.some((s) => s.id === 'spf_fail'));
  assert.match(card, /Forwarding normally breaks the SPF check/);
});

test('an alias delivery is described as one of several possibilities, not asserted', () => {
  const { analysis } = analyse(ALIAS_DELIVERED);
  assert.deepEqual(plain(analysis.relay.forwarded), { evidence: 'delivered_to', to: 'mike@obilabs.dev', from: '' });
  const card = cardText(ALIAS_DELIVERED);
  assert.match(card, /not on the To or Cc line/);
  assert.match(card, /Baitcheck cannot tell which/);
  assert.match(card, /Bcc looks the same/);
  // The packet carries the same hedge, and the body names the header it read.
  const { body, packet } = report(ALIAS_DELIVERED);
  assert.equal(packet.message.relay.forwarded.evidence, 'delivered_to');
  assert.match(body, /Delivered-To: mike@obilabs\.dev, which is not on the To or Cc line/);
});

test('a message delivered to an address on the To line is not called forwarded', () => {
  const direct = Object.assign({}, ALIAS_DELIVERED, {
    headers: Object.assign({}, ALIAS_DELIVERED.headers, { To: 'Mike <mike@obilabs.dev>' })
  });
  assert.equal(analyse(direct).analysis.relay.forwarded, null);
});

test('a newsletter with List-Unsubscribe is NOT treated as a relay', () => {
  const { analysis } = analyse(NEWSLETTER);
  assert.equal(analysis.relay.via_list, false);
  assert.deepEqual(plain(analysis.relayNotes), []);
  assert.equal(analysis.sender.address, 'news@acmeweekly.com');
  assert.equal(analysis.hasListUnsubscribe, true);
  // A differing Sender alone is ordinary too (bulk senders set their bounce address).
  const bulk = analyse(Object.assign({}, NEWSLETTER, {
    headers: Object.assign({}, NEWSLETTER.headers, { Sender: 'bounces@esp.example' })
  }));
  assert.equal(bulk.analysis.relay.via_list, false);
});

/* ------------------------- the bug this fixes ---------------------------- */

test('a stranger relayed by one of our own groups is never called an internal sender', () => {
  const { analysis } = analyse(GROUP_RELAYED);
  const card = cardText(GROUP_RELAYED);
  assert.equal(analysis.sender.internal, false);
  assert.equal(analysis.sender.address, 'chris@cold-outreach-agency.com');
  assert.equal(analysis.from.address, 'hello@obilabs.dev', 'the delivered From is kept, but it is not the sender');
  for (const line of analysis.context) {
    assert.doesNotMatch(line, /organisation's domains/, 'wrong: ' + line);
  }
  assert.doesNotMatch(card, /organisation&#39;s domains|organisation's domains/);
});

test('the card says a list re-sent the message, names it, and names the original sender', () => {
  const card = cardText(GROUP_RELAYED);
  assert.match(card, /How this arrived/);
  assert.match(card, /reached you through a mailing list or group/);
  assert.match(card, /ObiLabs Hello/);
  assert.match(card, /The original sender is Chris Wu/);
  assert.match(card, /chris@cold-outreach-agency.com/);
});

test('a list re-signature is not presented as the sender\'s own DKIM', () => {
  const { analysis } = analyse(GROUP_RELAYED);
  const dkimLine = analysis.context.find((c) => c.includes('DKIM pass'));
  assert.ok(dkimLine, 'the DKIM pass is still reported');
  assert.match(dkimLine, /added by the list when it re-sent the message/);
  // And the original message's own result is reported, labelled as such.
  assert.ok(analysis.relayNotes.some((n) => /Before the list handled it.*SPF pass.*DKIM pass \(cold-outreach-agency\.com\).*DMARC pass/.test(n)));
});

test('sender checks use the original sender: Reply-To is compared with their domain', () => {
  const { analysis } = analyse(GROUP_RELAYED);
  const replyTo = analysis.signals.find((s) => s.id === 'reply_to_mismatch');
  assert.ok(replyTo);
  assert.match(replyTo.text, /Replies would go to mail\.com, not to the sender's domain cold-outreach-agency\.com\./);
});

test('failed authentication on the original message is reported as a before-the-list result', () => {
  const spoofed = Object.assign({}, GROUP_RELAYED, {
    headers: Object.assign({}, GROUP_RELAYED.headers, {
      'X-Original-Authentication-Results': 'mx.google.com; dkim=none; spf=fail; dmarc=fail header.from=bank.example'
    })
  });
  const { analysis } = analyse(spoofed);
  const ids = analysis.signals.map((s) => s.id);
  assert.ok(ids.includes('original_dmarc_fail'));
  assert.match(analysis.signals.find((s) => s.id === 'original_dmarc_fail').text, /^Before the list re-sent it/);
});

/* ---------------------- relay with no original sender --------------------- */

test('a list message with no X-Original-Sender says so instead of guessing', () => {
  const { analysis } = analyse(GROUP_NO_ORIGINAL);
  const card = cardText(GROUP_NO_ORIGINAL);
  assert.equal(analysis.relay.via_list, true);
  assert.equal(analysis.relay.original, null);
  assert.equal(analysis.sender.unknown, true);
  assert.equal(analysis.sender.address, '');
  assert.equal(analysis.sender.internal, false, 'the list being ours says nothing about the sender');
  assert.match(card, /headers do not say who originally sent it/);
  assert.doesNotMatch(card, /organisation&#39;s domains|organisation's domains/);
});

/* ---------------------------- ordinary messages --------------------------- */

test('a genuinely internal message is still called internal', () => {
  const { analysis } = analyse(INTERNAL);
  const card = cardText(INTERNAL);
  assert.equal(analysis.relay.via_list, false);
  assert.equal(analysis.sender.internal, true);
  assert.ok(analysis.context.some((c) => c.includes("organisation's domains (obilabs.dev)")));
  assert.match(card, /organisation/);
});

/* ------------------------- packet and report email ------------------------ */

test('the packet carries the list, the original sender and both authentication results', () => {
  const { packet } = report(GROUP_RELAYED);
  assert.equal(packet.schema_version, 1);
  // Existing fields keep their meaning: `from` is the header as delivered.
  assert.equal(packet.message.from.address, 'hello@obilabs.dev');
  assert.equal(packet.message.authentication.dkim_domain, 'obilabs.dev');
  const relay = packet.message.relay;
  assert.equal(relay.via_list, true);
  assert.equal(relay.list.address, 'hello@obilabs.dev');
  assert.equal(relay.original_sender.address, 'chris@cold-outreach-agency.com');
  assert.deepEqual(relay.original_authentication,
    { spf: 'pass', dkim: 'pass', dmarc: 'pass', dkim_domain: 'cold-outreach-agency.com' });
});

test('the packet says via_list false for ordinary mail, and null original for an anonymous list', () => {
  assert.deepEqual(report(NEWSLETTER).packet.message.relay,
    { via_list: false, list: null, original_sender: null, original_authentication: null, forwarded: null });
  const relay = report(GROUP_NO_ORIGINAL).packet.message.relay;
  assert.equal(relay.via_list, true);
  assert.equal(relay.original_sender, null);
  assert.equal(relay.original_authentication, null);
});

test('the report email separates the list, the original sender and the two sets of results', () => {
  const { body } = report(GROUP_RELAYED);
  assert.match(body, /Arrived via:  a mailing list or group \(ObiLabs Hello hello@obilabs\.dev\), which re-sent it/);
  assert.match(body, /From header:  'Chris Wu' via ObiLabs Hello <hello@obilabs\.dev>  <- the list, not the sender/);
  assert.match(body, /Original sender: Chris Wu <chris@cold-outreach-agency\.com>/);
  assert.match(body, /Before the list: SPF pass \/ DKIM pass \(cold-outreach-agency\.com\) \/ DMARC pass/);
  assert.match(body, /As delivered:    SPF pass \/ DKIM pass \(obilabs\.dev\).*re-signed/);
  // The suggestions must not aim at the organisation's own group.
  assert.match(body, /a\) Block the sender address \(chris@cold-outreach-agency\.com\)/);
  assert.match(body, /b\) Block the sending domain \(cold-outreach-agency\.com\)/);
  assert.match(body, /Blocking the list address would stop the list itself/);
});

test('the report email for a list with no original sender does not name one', () => {
  const { body } = report(GROUP_NO_ORIGINAL);
  assert.match(body, /Original sender: not stated in the headers/);
  assert.match(body, /Before the list: not recorded in the headers/);
  assert.doesNotMatch(body, /a\) Block the sender address \(/, 'there is no sender address to offer');
});

test('an ordinary message keeps the original FACTS layout', () => {
  const { body } = report(NEWSLETTER);
  assert.match(body, /Display name: Acme Weekly/);
  assert.match(body, /From address: news@acmeweekly\.com/);
  assert.doesNotMatch(body, /Arrived via:/);
  assert.doesNotMatch(body, /Original sender:/);
});
