'use strict';
// A message that writes as a company but was sent from a personal mailbox.
//
// The shape below is the real one, from a cold sales email that reached the
// owner on 2026-09-21: the signature said "Chris Wu · Founder, Anvol" with the
// company's website under it, and the account was carebearvao@mail.com. Neither
// half is worth saying on its own; together they are the gap a reader can act on.

const test = require('node:test');
const assert = require('node:assert/strict');
const { load, fakeMessage, plain, gmailEvent, VERDICT_LANGUAGE } = require('./harness');

const PROPS = { REPORT_ADDRESS: 'security@obilabs.dev', ORG_DOMAINS: 'obilabs.dev' };

const { ctx } = load();
const analyse = (facts, props) =>
  ctx.analyzeFacts(facts, ctx.parseConfig(props || { ORG_DOMAINS: 'obilabs.dev' }));
const signal = (facts, props) =>
  analyse(facts, props).signals.find((s) => s.id === 'company_claim_personal_account');

/** The cold sales email, as delivered straight to the mailbox. */
const ANVOL = {
  from: '"Chris Wu · Founder, Anvol" <carebearvao@mail.com>',
  subject: 'Quick question about your engineering hiring',
  plainBody: 'I help companies like yours hire offshore engineers. Worth a chat?',
  htmlBody: '<p>I help companies like yours hire offshore engineers.</p>' +
    '<p><a href="https://anvol.example/about">anvol.example</a></p>',
  authenticationResults: 'mx.google.com; dkim=pass header.i=@mail.com; spf=pass; dmarc=pass'
};

test('a company role plus a consumer mailbox is reported, with both halves named', () => {
  const s = signal(ANVOL);
  assert.ok(s, 'the finding fires on the real Anvol shape');
  assert.match(s.text, /writes as "Founder, Anvol"/);
  assert.match(s.text, /personal mail\.com account rather than a company domain/);
  assert.match(s.text, /links point at anvol\.example/);
  assert.match(s.text, /Plenty of small businesses send mail this way/);
  assert.match(s.text, /reply from the company domain/);
});

test('the consumer mailbox is not also repeated as neutral context', () => {
  const a = analyse(ANVOL);
  assert.ok(!a.context.some((c) => /personal email service/.test(c)),
    'the finding replaces the weaker Context line rather than doubling it');
  // An ordinary personal message keeps that Context line.
  const plainMail = analyse({ from: 'Jane Smith <jane.smith@gmail.com>', plainBody: 'See you Friday.' });
  assert.ok(plainMail.context.some((c) => c.includes('Sent from a personal email service (gmail.com)')));
});

test('a plain personal Gmail with a personal display name is not reported', () => {
  assert.equal(signal({ from: 'Jane Smith <jane.smith@gmail.com>', plainBody: 'See you Friday.' }), undefined);
  assert.equal(signal({ from: 'jane.smith@gmail.com', plainBody: 'hi' }), undefined);
  assert.equal(ctx.organisationClaimInName('Jane Smith'), null);
});

test('a company-domain sender with a role in the display name is not reported', () => {
  assert.equal(signal({
    from: '"Chris Wu · Founder, Anvol" <chris@anvol.example>',
    htmlBody: '<a href="https://anvol.example/about">anvol.example</a>'
  }), undefined);
  // Nor is the organisation's own staff.
  assert.equal(signal({ from: '"Mike, Director" <mike@obilabs.dev>' }), undefined);
});

test('a relayed message whose original sender is on a company domain is not reported', () => {
  const relayed = {
    from: "'Chris Wu' via ObiLabs Hello <hello@obilabs.dev>",
    originalSender: 'chris@cold-outreach-agency.com',
    originalFrom: '"Chris Wu · Founder, Anvol" <chris@cold-outreach-agency.com>',
    listId: '<hello.obilabs.dev>',
    htmlBody: '<a href="https://anvol.example/about">anvol.example</a>'
  };
  const a = analyse(relayed);
  assert.equal(a.relay.via_list, true);
  assert.equal(a.sender.domain, 'cold-outreach-agency.com');
  assert.equal(a.signals.find((s) => s.id === 'company_claim_personal_account'), undefined);

  // But a relay whose ORIGINAL sender is on a consumer mailbox still is.
  const viaGroup = analyse(Object.assign({}, relayed, {
    originalSender: 'carebearvao@mail.com',
    originalFrom: '"Chris Wu · Founder, Anvol" <carebearvao@mail.com>'
  }));
  assert.ok(viaGroup.signals.some((s) => s.id === 'company_claim_personal_account'));
});

test('the wording carries no verdict', () => {
  const s = signal(ANVOL);
  for (const re of VERDICT_LANGUAGE) assert.doesNotMatch(s.text, re, 'verdict language: ' + re);
  assert.doesNotMatch(s.text, /\b(scam|phish|spoof|fake|impersonat)/i);
});

test('the card shows the finding, and the packet carries it as a reason', () => {
  const message = fakeMessage({
    from: ANVOL.from,
    subject: ANVOL.subject,
    plain: ANVOL.plainBody,
    html: ANVOL.htmlBody,
    headers: { 'Authentication-Results': ANVOL.authenticationResults },
    raw: 'From: carebearvao@mail.com\r\n\r\nbody'
  });
  const run = load({ props: PROPS, message });
  assert.match(JSON.stringify(run.ctx.onGmailMessageOpen(gmailEvent())), /writes as &quot;Founder, Anvol&quot;/);

  run.ctx.onReport(gmailEvent());
  const mail = run.calls.sendEmail[0];
  const packet = JSON.parse(mail.options.attachments[mail.options.attachments.length - 1].getDataAsString());
  assert.ok(packet.verdict.reasons.some((r) => /personal mail\.com account/.test(r)));
});

/* --------------------- the two halves, on their own ---------------------- */

test('the consumer-mail list matches provider families and sub-domains, and leaves Zoho out', () => {
  assert.equal(ctx.consumerMailProvider('mail.com'), 'mail.com');
  assert.equal(ctx.consumerMailProvider('yahoo.co.uk'), 'yahoo.co.uk');
  assert.equal(ctx.consumerMailProvider('gmx.de'), 'gmx.de');
  assert.equal(ctx.consumerMailProvider('mail.yandex.ru'), 'yandex.ru');
  assert.equal(ctx.consumerMailProvider('zoho.com'), '', 'free and paid Zoho look the same in the headers');
  assert.equal(ctx.consumerMailProvider('anvol.example'), '');
  assert.equal(ctx.consumerMailProvider('notgmail.com'), '');
});

test('organisation claims: roles, company suffixes and the "person at company" shape', () => {
  assert.deepEqual(plain(ctx.organisationClaimInName('Chris Wu · Founder, Anvol')),
    { marker: 'Founder, Anvol', kind: 'role' });
  assert.equal(ctx.organisationClaimInName('Anvol Ltd').kind, 'company_suffix');
  assert.deepEqual(plain(ctx.organisationClaimInName('Chris Wu at Anvol')),
    { marker: 'Anvol', kind: 'organisation_shape' });
  assert.deepEqual(plain(ctx.organisationClaimInName('Chris Wu | Anvol')),
    { marker: 'Anvol', kind: 'organisation_shape' });
  assert.equal(ctx.organisationClaimInName('Billing Team').kind, 'role');
  assert.equal(ctx.organisationClaimInName(''), null);
});

test('link corroboration ignores shorteners, trackers and the sender\'s own domain', () => {
  const links = (html) => ctx.extractLinks(html);
  assert.equal(ctx.outsideLinkDomain_(links('<a href="https://bit.ly/x">x</a>'), 'mail.com'), '');
  assert.equal(ctx.outsideLinkDomain_(links('<a href="https://x.list-manage.com/u">x</a>'), 'mail.com'), '');
  assert.equal(ctx.outsideLinkDomain_(links('<a href="https://mail.com/inbox">x</a>'), 'mail.com'), '');
  assert.equal(ctx.outsideLinkDomain_(links('<a href="https://www.anvol.example/a">x</a>'), 'mail.com'), 'anvol.example');
});

test('a claim with no corroborating link still reports, without naming one', () => {
  const s = signal({ from: '"Chris Wu · Founder, Anvol" <carebearvao@mail.com>', plainBody: 'Worth a chat?' });
  assert.ok(s);
  assert.doesNotMatch(s.text, /links point at/);
});

/* ------------------------- the claim in the signature ------------------------ */

// The shape that slipped through the display-name check: a plain name on the
// From line, a consumer mailbox, relayed by the organisation's own Google Group,
// and the title only in the signature. Names and domains are fictional.
const SIGNATURE_ONLY = {
  from: "'Sam Lee' via Example Hello <hello@obilabs.dev>",
  originalSender: 'sam.lee.sales@mail.com',
  listId: '"Example Hello" <hello.obilabs.dev>',
  listUnsubscribe: '<mailto:hello+unsubscribe@obilabs.dev>',
  plainBody: 'Hi,\n\nI help teams like yours hire engineers. Worth a quick call?\n\nBest,\nSam Lee\nFounder\n' +
    'Brightwell\nbrightwell.example\n\n--\nYou received this message because you are subscribed to the ' +
    'Google Groups "Example Hello" group.\nTo unsubscribe from this group and stop receiving emails from it, ' +
    'send an email to hello+unsubscribe@obilabs.dev.\n',
  htmlBody: '<a href="https://brightwell.example/">brightwell.example</a>'
};

test('a title in the signature counts, when the display name is only a name', () => {
  const a = analyse(SIGNATURE_ONLY);
  assert.equal(a.relay.via_list, true);
  assert.equal(a.sender.name, 'Sam Lee');
  const s = a.signals.find((x) => x.id === 'company_claim_personal_account');
  assert.ok(s, 'the signature carries the claim');
  assert.equal(s.evidence.claim_source, 'signature');
  assert.equal(s.evidence.claim, 'Founder');
  assert.match(s.text, /signs as "Founder", but the message was sent from a personal mail\.com account/);
  assert.equal(a.summary.headline_id, 'company_claim');
  assert.ok(!a.context.some((c) => /personal email service/.test(c)));
  for (const re of VERDICT_LANGUAGE) assert.doesNotMatch(s.text + ' ' + s.short, re);
  assert.doesNotMatch(s.short, /\b(scam|phish|spoof|fake|impersonat)/i);
});

test('a display-name claim is still recorded as such', () => {
  assert.equal(signal(ANVOL).evidence.claim_source, 'display_name');
});

test('"Name, Role, Company" and "Role at Company" signature lines are read line by line', () => {
  assert.deepEqual(plain(ctx.organisationClaimInSignature('Thanks for your time.\n\nSam Lee · Founder, Brightwell')),
    { marker: 'Founder, Brightwell', kind: 'role' });
  assert.equal(ctx.organisationClaimInSignature('Regards\nSam Lee\nDirector at Brightwell').kind, 'role');
  assert.equal(ctx.organisationClaimInSignature('Sam Lee\nBrightwell Ltd').kind, 'company_suffix');
});

test('a signature in the quoted text of a reply does not count', () => {
  const reply = 'Sounds good, see you then.\n\nOn Mon, 14 Sep 2026 at 10:00, Sam Lee <sam@brightwell.example> wrote:\n' +
    '> Worth a quick call?\n>\n> Sam Lee\n> Founder, Brightwell\n';
  assert.equal(ctx.organisationClaimInSignature(reply), null);
  assert.equal(signal({ from: 'Jane Smith <jane.smith@gmail.com>', plainBody: reply }), undefined);
  // Clients that wrap the attribution line, and Outlook's separator, are cut too.
  const wrapped = 'Thanks!\n\nOn Mon, 14 Sep 2026 at 10:00, Sam Lee\n<sam@brightwell.example> wrote:\nSam Lee\nCEO, Brightwell';
  assert.equal(ctx.organisationClaimInSignature(wrapped), null);
  const outlook = 'Thanks!\n\n-----Original Message-----\nFrom: Sam Lee\nSam Lee\nCEO, Brightwell';
  assert.equal(ctx.organisationClaimInSignature(outlook), null);
});

test('role words in ordinary prose do not count', () => {
  const prose = 'Hi,\n\nI spoke to the manager about the flat.\nAsk your manager\nOur director said yes\n' +
    'Our sales team will call.\n\nJane';
  assert.equal(ctx.organisationClaimInSignature(prose), null);
  assert.equal(signal({ from: 'Jane Smith <jane.smith@gmail.com>', plainBody: prose }), undefined);
  // Nor a phone footer, a newsletter's "note from our CEO", or a long line.
  assert.equal(ctx.organisationClaimInSignature('See you soon\n\nSent from my iPhone'), null);
  assert.equal(ctx.organisationClaimInSignature('A note from our CEO\nRead more below'), null);
  assert.equal(ctx.organisationClaimInSignature(
    'Kind words from the president of the residents association about the garden party'), null);
  // "support" and "billing" are team names in a From line, but prose in a signature.
  assert.equal(ctx.organisationClaimInSignature('Jane\nThanks for the support'), null);
});

test('a company-domain sender with a title in the signature is not reported', () => {
  assert.equal(signal({ from: 'Sam Lee <sam@brightwell.example>', plainBody: 'Hi\n\nSam Lee\nFounder, Brightwell' }),
    undefined);
});
