'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { load, plain } = require('./harness');

const { ctx } = load();
const cfg = (props) => ctx.parseConfig(props || {});
const ids = (facts, props) => plain(ctx.analyzeFacts(facts, cfg(props)).signals.map((s) => s.id));

test('brand in display name from an unrelated domain is flagged', () => {
  assert.ok(ids({ from: 'PayPal Service <alerts@secure-mail.xyz>' }).includes('brand_name_mismatch'));
  assert.ok(ids({ from: '"Microsoft 365" <no-reply@gmail.com>' }).includes('brand_name_mismatch'));
});

test('brand from its own domain or sub-domain is not flagged', () => {
  assert.ok(!ids({ from: 'PayPal <service@paypal.com>' }).includes('brand_name_mismatch'));
  assert.ok(!ids({ from: 'PayPal <service@mail.paypal.com>' }).includes('brand_name_mismatch'));
  // "ups" must match as a word, not inside "groups".
  assert.ok(!ids({ from: 'Google Groups <noreply@googlegroups.com>' }).includes('brand_name_mismatch'));
  assert.equal(ctx.brandInName('Support Groups'), '');
});

test('brand check is skipped for internal senders', () => {
  assert.ok(!ids({ from: 'Apple Team <team@acme.com>' }, { ORG_DOMAINS: 'acme.com' }).includes('brand_name_mismatch'));
});

test('Reply-To on a different domain is flagged, same organisation is not', () => {
  assert.ok(ids({ from: 'Billing <billing@acme.com>', replyTo: 'billing@acme-payments.top' }).includes('reply_to_mismatch'));
  assert.ok(!ids({ from: 'News <news@acme.com>', replyTo: 'help@support.acme.com' }).includes('reply_to_mismatch'));
  assert.ok(!ids({ from: 'News <news@acme.co.uk>', replyTo: 'help@mail.acme.co.uk' }).includes('reply_to_mismatch'));
});

test('link text that names a different site than the href is flagged', () => {
  const html = '<p><a href="https://login.evil.example/p?a=1&amp;b=2">www.paypal.com</a></p>';
  const a = ctx.analyzeFacts({ from: 'x <x@y.com>', htmlBody: html }, cfg());
  assert.ok(plain(a.signals.map((s) => s.id)).includes('link_text_mismatch'));
  assert.equal(a.links[0].href, 'https://login.evil.example/p?a=1&b=2');
});

test('matching or non-domain link text is not flagged', () => {
  const html = '<a href="https://www.paypal.com/signin">paypal.com</a> <a href="https://t.example.net/x">Click here</a>' +
    '<a href="mailto:a@b.com">a@b.com</a>';
  assert.ok(!ids({ from: 'x <x@y.com>', htmlBody: html }).includes('link_text_mismatch'));
});

test('URL shorteners and IP-literal links are flagged', () => {
  const html = '<a href="https://bit.ly/abc">here</a><a href="http://203.0.113.9/login">login</a>';
  const got = ids({ from: 'x <x@y.com>', htmlBody: html });
  assert.ok(got.includes('url_shortener'));
  assert.ok(got.includes('ip_literal_link'));
});

test('lookalike domains are flagged', () => {
  assert.equal(ctx.lookalikeOf('paypa1.com', ['paypal.com']), 'paypal.com');
  assert.equal(ctx.lookalikeOf('rnicrosoft.com', ['microsoft.com']), 'microsoft.com');
  assert.equal(ctx.lookalikeOf('paypal.com.account-check.net', ['paypal.com']), 'paypal.com');
  assert.equal(ctx.lookalikeOf('docusiqn.com', ['docusign.com']), 'docusign.com');
  assert.ok(ids({ from: 'CEO <ceo@examp1e.com>' }, { ORG_DOMAINS: 'example.com' }).includes('lookalike_domain'));
});

test('real domains, sub-domains and regional variants are not lookalikes', () => {
  assert.equal(ctx.lookalikeOf('paypal.com', ['paypal.com']), '');
  assert.equal(ctx.lookalikeOf('mail.paypal.com', ['paypal.com']), '');
  assert.equal(ctx.lookalikeOf('amazon.cn', ['amazon.ca', 'amazon.com']), '');
  assert.equal(ctx.lookalikeOf('github.com', ['google.com', 'apple.com']), '');
  assert.deepEqual(ids({ from: 'Jane <jane@example.com>' }, { ORG_DOMAINS: 'example.com' }), []);
});

test('punycode domains are flagged', () => {
  assert.ok(ids({ from: 'Bank <info@xn--pypal-4ve.com>' }).includes('punycode_domain'));
});

test('pressure language is flagged; ordinary text is not', () => {
  assert.ok(ids({ from: 'x <x@y.com>', subject: 'Final notice', plainBody: 'Verify your account within 24 hours' }).includes('pressure_language'));
  assert.deepEqual(ids({ from: 'Jane <jane@y.com>', subject: 'Lunch', plainBody: 'See you at noon.' }), []);
});

test('authentication results: failures flagged, DKIM pass shown as context', () => {
  const failing = 'mx.google.com; spf=softfail smtp.mailfrom=x.com; dkim=none; dmarc=fail (p=REJECT) header.from=x.com';
  assert.ok(ids({ from: 'x <a@x.com>', authenticationResults: failing }).includes('dmarc_fail'));
  const passing = 'mx.google.com; dkim=pass header.i=@mailchimpapp.net header.s=k1; spf=pass; dmarc=pass header.from=news.com';
  const a = ctx.analyzeFacts({ from: 'News <n@news.com>', authenticationResults: passing }, cfg());
  assert.deepEqual(plain(a.signals), []);
  assert.ok(a.context.some((c) => c.includes('mailchimpapp.net')));
  assert.deepEqual(plain(ctx.parseAuthenticationResults(passing)),
    { spf: 'pass', dkim: 'pass', dmarc: 'pass', dkim_domain: 'mailchimpapp.net' });
});

test('risky attachment types are flagged; ordinary documents are not', () => {
  assert.ok(ids({ from: 'x <x@y.com>', attachments: [{ name: 'Invoice.HTML' }] }).includes('risky_attachment'));
  assert.ok(!ids({ from: 'x <x@y.com>', attachments: [{ name: 'report.pdf' }, { name: 'README' }] }).includes('risky_attachment'));
});

test('List-Unsubscribe is neutral context, not a signal', () => {
  const a = ctx.analyzeFacts({ from: 'News <n@news.com>', listUnsubscribe: '<https://news.com/u>' }, cfg());
  assert.equal(a.signals.length, 0);
  assert.equal(a.hasListUnsubscribe, true);
});

test('config enables a lookup only when listed AND keyed', () => {
  const c = plain(cfg({ LOOKUP_SERVICES: 'urlhaus, webrisk ,virustotal,unknown', URLHAUS_AUTH_KEY: 'k1', WEBRISK_API_KEY: '' }));
  assert.deepEqual(c.lookupNames, ['urlhaus']);
  assert.deepEqual(plain(cfg({ URLHAUS_AUTH_KEY: 'k1' })).lookupNames, []);
  assert.deepEqual(plain(cfg({ ORG_DOMAINS: 'Acme.com, acme.co.uk' })).orgDomains, ['acme.com', 'acme.co.uk']);
});

test('report packet follows schema v1 field layout', () => {
  const facts = {
    from: 'PayPal <alerts@paypa1.com>', replyTo: 'x@evil.top', subject: 'Verify your account',
    date: '2026-09-10T12:00:00.000Z', htmlBody: '<a href="https://bit.ly/z">paypal.com</a>', plainBody: 'urgent',
    authenticationResults: 'spf=softfail; dkim=none; dmarc=fail', listUnsubscribe: ''
  };
  const a = ctx.analyzeFacts(facts, cfg());
  const p = plain(ctx.buildReportPacket(facts, a, {
    reportId: 'r-1', reportedAt: '2026-09-10T12:01:00Z', messageId: 'm-1', comment: 'odd',
    orgDomains: ['acme.com'], attachments: [{ name: 'a.htm', type: 'text/html', size: 3, sha256: 'ab' }],
    eml: { sha256: 'cd', size: 99 }
  }));
  assert.equal(p.schema_version, 1);
  assert.deepEqual(Object.keys(p), ['schema_version', 'report_id', 'reported_at', 'tenant', 'reporter', 'message',
    'indicators', 'analysis', 'headers', 'verdict', 'eml']);
  assert.deepEqual(p.message.from, { name: 'PayPal', address: 'alerts@paypa1.com' });
  assert.equal(p.message.authentication.spf, 'fail');
  assert.equal(p.message.authentication.dmarc, 'fail');
  assert.equal(p.indicators.urls[0].shortener, true);
  assert.equal(p.indicators.domains[0].lookalike_of, 'paypal.com');
  assert.deepEqual(p.indicators.hashes, ['ab']);
  assert.equal(p.verdict.label, 'suspicious');
  assert.equal(p.verdict.ai.provider, 'none');
  assert.equal(p.reporter.comment, 'odd');
  assert.equal(p.eml.data, undefined, '.eml travels as an attachment, not inline');
});

test('asks and pressure are separate findings: only the ask can lead the card', () => {
  const a = ctx.analyzeFacts({ from: 'x <x@y.com>', plainBody: 'Please update our bank details.' }, cfg());
  assert.deepEqual(plain(a.signals.map((s) => s.id)), ['payment_or_credential_ask']);
  assert.equal(a.signals[0].category, 'ask');
  const b = ctx.analyzeFacts({ from: 'x <x@y.com>', plainBody: 'This is urgent, please reply immediately.' }, cfg());
  assert.deepEqual(plain(b.signals.map((s) => s.id)), ['pressure_language']);
  assert.equal(b.signals[0].category, 'other');
  assert.deepEqual(plain(b.signals[0].evidence.terms), ['urgent', 'immediately']);
  // Both checks record that they ran, fired or not.
  const clean = ctx.analyzeFacts({ from: 'x <x@y.com>', plainBody: 'Lunch?' }, cfg());
  assert.ok(clean.checksRun.includes('payment_or_credential_ask'));
  assert.ok(clean.checksRun.includes('pressure_language'));
});

test('asks and pressure in quoted text are ignored', () => {
  const reply = 'Is this real?\n\nOn Tue, 15 Sep 2026, Billing <billing@x.example> wrote:\n' +
    '> Verify your account within 24 hours or send a gift card.\n';
  assert.deepEqual(ids({ from: 'Jane <jane@y.com>', plainBody: reply }), []);
  const forwarded = 'FYI\n\n---------- Forwarded message ---------\nFrom: x\nUpdate your payment immediately.';
  assert.deepEqual(ids({ from: 'Jane <jane@y.com>', plainBody: forwarded }), []);
  // The subject still counts: it is not quoted text.
  assert.ok(ids({ from: 'Jane <jane@y.com>', subject: 'Verify your account', plainBody: reply })
    .includes('payment_or_credential_ask'));
});

test('every signal carries a category and a short form', () => {
  const a = ctx.analyzeFacts({
    from: 'PayPal <alerts@paypa1.com>', replyTo: 'x@evil.top', subject: 'Final notice: verify your account',
    htmlBody: '<a href="https://evil.example/x">www.paypal.com</a><a href="https://bit.ly/z">z</a>' +
      '<a href="http://203.0.113.9/x">x</a><a href="https://xn--pypal-4ve.com/">p</a>',
    authenticationResults: 'spf=fail; dkim=none; dmarc=fail', attachments: [{ name: 'a.iso' }]
  }, cfg());
  assert.ok(a.signals.length >= 8);
  for (const s of a.signals) {
    assert.ok(['link', 'attachment', 'sender', 'company_claim', 'ask', 'other'].includes(s.category), s.id);
    assert.ok(s.short, s.id);
  }
});
