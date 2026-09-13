'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { load, fakeMessage, plain, gmailEvent, gsFiles, SCRIPT_DIR } = require('./harness');

const manifest = JSON.parse(fs.readFileSync(path.join(SCRIPT_DIR, 'appsscript.json'), 'utf8'));

const ALL_LOOKUPS = {
  LOOKUP_SERVICES: 'urlhaus,webrisk,safebrowsing,virustotal',
  URLHAUS_AUTH_KEY: 'uh-key',
  WEBRISK_API_KEY: 'wr-key',
  SAFEBROWSING_API_KEY: 'sb-key',
  VIRUSTOTAL_API_KEY: 'vt-key',
  REPORT_ADDRESS: 'security@acme.com',
  ORG_DOMAINS: 'acme.com'
};

const PHISH = {
  from: '"PayPal" <alerts@paypa1-support.com>',
  replyTo: 'collect@evil.top',
  subject: 'Final notice: verify your account',
  html: '<a href="https://evil.example/login?id=SECRET-TOKEN">www.paypal.com</a> <a href="https://bit.ly/x1">here</a>',
  plain: 'Verify your account within 24 hours. Private body text.',
  headers: { 'Authentication-Results': 'mx.google.com; spf=softfail; dkim=none; dmarc=fail' },
  attachments: [{ name: 'invoice.html', type: 'text/html', data: '<html>x</html>' }],
  raw: 'From: alerts@paypa1-support.com\r\nSubject: Final notice\r\n\r\nPrivate body text.'
};

const text = (card) => JSON.stringify(card);

test('opening a message makes no external request, even with every lookup enabled', () => {
  const { ctx, calls } = load({ props: ALL_LOOKUPS, message: fakeMessage(PHISH) });
  const card = ctx.onGmailMessageOpen(gmailEvent());
  assert.equal(calls.fetch.length, 0, 'UrlFetchApp must not be called on open');
  assert.equal(calls.sendEmail.length, 0);
  assert.deepEqual(calls.tokens, ['token-abc']);
  assert.match(text(card), /worth a closer look/);
  assert.match(text(card), /Check links/);
  assert.match(text(card), /Nothing has left your mailbox/);
});

test('opening a message with no configuration still works and offers no lookups or report', () => {
  const { ctx, calls } = load({ props: {}, message: fakeMessage(PHISH) });
  const card = text(ctx.onGmailMessageOpen(gmailEvent()));
  assert.equal(calls.fetch.length, 0);
  assert.doesNotMatch(card, /Check links/);
  assert.doesNotMatch(card, /Report to security/);
  assert.match(card, /REPORT_ADDRESS/);
});

test('card text is HTML-escaped', () => {
  const { ctx } = load({ props: {}, message: fakeMessage({ from: '"PayPal <b>x</b>" <a@evil.top>' }) });
  const card = text(ctx.onGmailMessageOpen(gmailEvent()));
  assert.doesNotMatch(card, /<b>x<\/b>/);
});

test('"Check links" sends only link URLs, only to enabled services, only to whitelisted hosts', () => {
  const props = { LOOKUP_SERVICES: 'urlhaus,webrisk', URLHAUS_AUTH_KEY: 'uh-key', WEBRISK_API_KEY: 'wr-key' };
  const responder = (req) => {
    if (req.url.startsWith('https://urlhaus-api.abuse.ch/')) {
      return req.payload.url.includes('evil.example')
        ? { code: 200, body: JSON.stringify({ query_status: 'ok', threat: 'malware_download' }) }
        : { code: 200, body: JSON.stringify({ query_status: 'no_results' }) };
    }
    return { code: 200, body: '{}' };
  };
  const { ctx, calls } = load({ props, message: fakeMessage(PHISH), fetchResponder: responder });
  const res = ctx.onCheckLinks(gmailEvent());

  assert.equal(calls.fetch.length, 4, '2 URLs x 2 services');
  const hosts = new Set(calls.fetch.map((r) => new URL(r.url).origin + '/'));
  for (const h of hosts) assert.ok(manifest.urlFetchWhitelist.includes(h), h + ' must be whitelisted');
  assert.ok(![...hosts].some((h) => h.includes('virustotal') || h.includes('safebrowsing')));
  const sent = JSON.stringify(calls.fetch);
  assert.doesNotMatch(sent, /Private body text/);
  assert.doesNotMatch(sent, /Final notice/);
  assert.equal(calls.fetch.filter((r) => r.headers && r.headers['Auth-Key'] === 'uh-key').length, 2);
  assert.match(text(res), /URLhaus/);
  assert.match(text(res), /malware_download/);
});

test('lookup results are cached per user and reused', () => {
  const props = { LOOKUP_SERVICES: 'urlhaus', URLHAUS_AUTH_KEY: 'uh-key' };
  const responder = () => ({ code: 200, body: JSON.stringify({ query_status: 'no_results' }) });
  const { ctx, calls } = load({ props, message: fakeMessage(PHISH), fetchResponder: responder });
  ctx.onCheckLinks(gmailEvent());
  const first = calls.fetch.length;
  ctx.onCheckLinks(gmailEvent());
  assert.equal(calls.fetch.length, first, 'second check is served from cache');
  assert.ok(calls.cachePut.every((p) => p.ttl > 0 && p.ttl <= 21600));
});

test('failed lookups are shown as incomplete and not cached', () => {
  const props = { LOOKUP_SERVICES: 'virustotal', VIRUSTOTAL_API_KEY: 'vt' };
  const { ctx, calls } = load({ props, message: fakeMessage(PHISH), fetchResponder: () => ({ code: 500, body: 'x' }) });
  const res = text(ctx.onCheckLinks(gmailEvent()));
  assert.equal(calls.cachePut.length, 0);
  assert.match(res, /could not be completed/);
});

test('Safe Browsing batches URLs in one request', () => {
  const props = { LOOKUP_SERVICES: 'safebrowsing', SAFEBROWSING_API_KEY: 'sb' };
  const responder = (req) => ({
    code: 200,
    body: JSON.stringify({ matches: [{ threatType: 'SOCIAL_ENGINEERING', threat: { url: JSON.parse(req.payload).threatInfo.threatEntries[0].url } }] })
  });
  const { ctx, calls } = load({ props, message: fakeMessage(PHISH), fetchResponder: responder });
  const res = text(ctx.onCheckLinks(gmailEvent()));
  assert.equal(calls.fetch.length, 1);
  assert.match(res, /SOCIAL_ENGINEERING/);
});

test('"Report to security" emails the .eml and packet to REPORT_ADDRESS, with no external request', () => {
  const { ctx, calls } = load({ props: ALL_LOOKUPS, message: fakeMessage(PHISH) });
  const res = ctx.onReport(gmailEvent({ formInput: { comment: 'Not expecting this' } }));

  assert.equal(calls.fetch.length, 0);
  assert.equal(calls.sendEmail.length, 1);
  const mail = calls.sendEmail[0];
  assert.equal(mail.to, 'security@acme.com');
  assert.match(mail.subject, /^\[Baitcheck\] User report: Final notice/);
  const names = mail.options.attachments.map((b) => b.getName());
  assert.deepEqual(plain(names), ['reported-message.eml', 'baitcheck-report.json']);
  assert.equal(mail.options.attachments[0].getContentType(), 'message/rfc822');
  assert.equal(mail.options.attachments[0].getDataAsString(), PHISH.raw);

  const packet = JSON.parse(mail.options.attachments[1].getDataAsString());
  assert.equal(packet.schema_version, 1);
  assert.equal(packet.message.gmail_message_id, 'msg-123');
  assert.equal(packet.reporter.comment, 'Not expecting this');
  assert.equal(packet.tenant.domain, 'acme.com');
  assert.match(packet.eml.sha256, /^[0-9a-f]{64}$/);
  assert.equal(packet.message.attachments[0].name, 'invoice.html');
  assert.match(packet.message.attachments[0].sha256, /^[0-9a-f]{64}$/);
  assert.ok(packet.verdict.reasons.length >= 3);
  assert.match(mail.body, /Not expecting this/);
  assert.match(text(res), /Sent to your security team/);
  assert.match(text(res), /did not move or delete/);
});

test('report still sends (without .eml) if the raw message cannot be read', () => {
  const msg = fakeMessage(PHISH);
  msg.getRawContent = () => { throw new Error('insufficient scope'); };
  const { ctx, calls } = load({ props: { REPORT_ADDRESS: 'security@acme.com' }, message: msg });
  const res = text(ctx.onReport(gmailEvent()));
  assert.equal(calls.sendEmail.length, 1);
  assert.deepEqual(plain(calls.sendEmail[0].options.attachments.map((b) => b.getName())), ['baitcheck-report.json']);
  assert.match(res, /could not be attached/);
});

test('report without REPORT_ADDRESS sends nothing and says why', () => {
  const { ctx, calls } = load({ props: {}, message: fakeMessage(PHISH) });
  const res = text(ctx.onReport(gmailEvent()));
  assert.equal(calls.sendEmail.length, 0);
  assert.match(res, /REPORT_ADDRESS/);
});

test('manifest requests only the documented scopes', () => {
  assert.deepEqual([...manifest.oauthScopes].sort(), [
    'https://www.googleapis.com/auth/gmail.addons.current.message.readonly',
    'https://www.googleapis.com/auth/gmail.addons.execute',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/script.external_request'
  ]);
  assert.equal(manifest.addOns.gmail.contextualTriggers[0].onTriggerFunction, 'onGmailMessageOpen');
  assert.equal(manifest.addOns.common.homepageTrigger.runFunction, 'onHomepage');
});

test('source never trashes, deletes or modifies mail, and network calls live only in Lookups.gs', () => {
  for (const f of gsFiles()) {
    const src = fs.readFileSync(path.join(SCRIPT_DIR, f), 'utf8');
    assert.doesNotMatch(src, /moveToTrash|\.trash\(|deleteMessage|markRead|addLabel|getScriptCache/, f);
    if (f !== 'Lookups.gs') assert.doesNotMatch(src, /UrlFetchApp\s*\./, f + ' must not call UrlFetchApp');
  }
});
