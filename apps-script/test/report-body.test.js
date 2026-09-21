'use strict';
// The report email a security team actually reads: what is attached, in which
// order the body is laid out, and what it must never say.

const test = require('node:test');
const assert = require('node:assert/strict');
const { load, fakeMessage, gmailEvent, VERDICT_LANGUAGE } = require('./harness');

const PROPS = { REPORT_ADDRESS: 'security@acme.com', ORG_DOMAINS: 'acme.com' };

const PHISH = {
  from: '"PayPal" <alerts@paypa1-support.com>',
  replyTo: 'collect@evil.top',
  subject: 'Final notice: verify your account',
  html: '<a href="https://evil.example/login">www.paypal.com</a> <a href="https://bit.ly/x1">here</a>' +
    ' <a href="https://evil.example/again">and again</a>',
  plain: 'Verify your account within 24 hours.',
  headers: {
    'Authentication-Results': 'mx.google.com; spf=softfail; dkim=none; dmarc=fail',
    'Return-Path': '<bounce@evil.top>'
  },
  attachments: [{ name: 'invoice.html', type: 'text/html', data: '<html>x</html>' }],
  raw: 'From: alerts@paypa1-support.com\r\nSubject: Final notice\r\n\r\nPrivate body text.'
};

/** Sends a report and returns { mail, body, attachments, packet }. */
function report(message, extra) {
  const { ctx, calls } = load({ props: PROPS, message: message || fakeMessage(PHISH) });
  ctx.onReport(gmailEvent(extra || { formInput: { comment: 'I was not expecting this' } }));
  const mail = calls.sendEmail[0];
  const attachments = mail.options.attachments;
  const packet = JSON.parse(attachments[attachments.length - 1].getDataAsString());
  return { mail, body: mail.body, attachments, packet };
}

const SECTIONS = [
  '1. WHAT HAPPENED',
  '2. WHAT BAITCHECK NOTICED',
  '3. THE FACTS',
  '4. SUGGESTED ACTIONS',
  '5. ATTACHED',
  '6. WHAT BAITCHECK DID NOT DO'
];

test('the original travels inside a zip, so no client or Google Group can render it', () => {
  const { attachments, packet } = report();
  const archive = attachments[0];
  assert.equal(archive.getName(), 'reported-message.zip');
  assert.equal(archive.getContentType(), 'application/zip');
  // Neither of the types that failed in real Gmail is used for the attachment.
  assert.notEqual(archive.getContentType(), 'message/rfc822');
  assert.notEqual(archive.getContentType(), 'application/octet-stream');
  assert.equal(archive.zippedBlobs.length, 1);
  const eml = archive.zippedBlobs[0];
  assert.equal(eml.getName(), 'reported-message.eml');
  assert.equal(eml.getDataAsString(), PHISH.raw, 'the bytes inside are the untouched original');
  // The packet says how it travels and hashes the .eml itself, not the zip.
  assert.equal(packet.eml.encoding, 'attachment');
  assert.equal(packet.eml.content_type, 'application/zip');
  assert.equal(packet.eml.archive, 'reported-message.zip');
  assert.equal(packet.eml.file, 'reported-message.eml');
  assert.match(packet.eml.sha256, /^[0-9a-f]{64}$/);
});

test('the body says the original is zipped on purpose, and why', () => {
  const { body } = report();
  assert.match(body, /reported-message\.zip/);
  assert.match(body, /zipped on purpose/);
  assert.match(body, /remote images/);
});

test('the body carries every section, once, in triage order', () => {
  const { body } = report();
  const positions = SECTIONS.map((heading) => {
    const all = body.split('\n').filter((l) => l === heading);
    assert.equal(all.length, 1, heading + ' must appear exactly once');
    return body.indexOf(heading);
  });
  for (let i = 1; i < positions.length; i++) {
    assert.ok(positions[i] > positions[i - 1], SECTIONS[i] + ' must follow ' + SECTIONS[i - 1]);
  }
});

test('section 1 names the reporter and their comment, section 2 lists the signals', () => {
  const { body } = report();
  assert.match(body, /Reporter:\s+the sender of this email/);
  assert.match(body, /Their note:\s+I was not expecting this/);
  assert.match(body, /Final notice: verify your account/);
  assert.match(body, /- Replies would go to evil\.top/);
  assert.match(body, /- The sender's domain policy check \(DMARC\) failed\./);
});

test('section 3 gives the decision facts: display name and address apart, auth, links, hashes', () => {
  const { body, packet } = report();
  assert.match(body, /Display name: PayPal/);
  assert.match(body, /From address: alerts@paypa1-support\.com/);
  assert.match(body, /Reply-To:\s+collect@evil\.top/);
  assert.match(body, /Return-Path:\s+bounce@evil\.top/);
  assert.match(body, /SPF softfail \/ DKIM none \/ DMARC fail/);
  // Three links, two distinct hosts: deduplicated and counted.
  assert.match(body, /Link domains \(2\): evil\.example, bit\.ly/);
  assert.match(body, new RegExp('- invoice\\.html\\s+sha256 ' + packet.message.attachments[0].sha256));
});

test('section 4 suggests the four actions, with reasons and verified console links', () => {
  const { body } = report();
  const order = ['a) Block the sender address', 'b) Block the sending domain',
    'c) Find out who else received it', 'd) Do nothing'];
  let at = body.indexOf(SECTIONS[3]);
  for (const action of order) {
    const next = body.indexOf(action, at);
    assert.ok(next > at, action + ' must follow the previous action');
    at = next;
  }
  assert.match(body, /a\) Block the sender address \(alerts@paypa1-support\.com\)/);
  assert.match(body, /b\) Block the sending domain \(paypa1-support\.com\)/);
  assert.equal((body.match(/^ +Why: /gm) || []).length, 4, 'every action carries a reason');
  assert.match(body, /https:\/\/admin\.google\.com\/ac\/apps\/gmail\/spam/);
  assert.match(body, /https:\/\/admin\.google\.com\/ac\/emaillogsearch/);
  assert.match(body, /https:\/\/admin\.google\.com\/ac\/sc\/investigation/);
  // The investigation tool is edition-limited; the line must not promise it.
  assert.match(body, /Frontline Plus, Enterprise Plus and\n?\s*Education Plus only/);
  assert.match(body, /your edition may not have it/);
  // Suggestions, not instructions, and not something Baitcheck can do.
  assert.match(body, /Suggestions for whoever triages this/);
  assert.match(body, /Baitcheck cannot carry any of them out/);
});

test('the body states that Baitcheck did not move or delete the message', () => {
  const { body } = report();
  assert.match(body, /did not move, delete or quarantine the message/);
  assert.match(body, /The reporter still has the\n?\s*message in their mailbox\./);
});

test('the body gives no verdict, in any of its wordings', () => {
  const { body } = report();
  assert.match(body, /It gives no verdict; you decide\./);
  for (const re of VERDICT_LANGUAGE) assert.doesNotMatch(body, re, 'verdict language: ' + re);
});

test('a message with nothing flagged still reports facts, actions and the no-verdict line', () => {
  const clean = fakeMessage({
    from: 'Colleague <colleague@acme.com>',
    subject: 'Lunch',
    raw: 'From: colleague@acme.com\r\n\r\nhi'
  });
  const { body } = report(clean, {});
  assert.match(body, /Nothing stood out in its checks/);
  assert.match(body, /Their note:\s+\(none\)/);
  assert.match(body, /Link domains: none/);
  assert.match(body, /Attachments in the message: none/);
  for (const heading of SECTIONS) assert.ok(body.includes(heading), heading + ' is missing');
});

test('a subject or comment with newlines cannot forge a section heading', () => {
  const msg = fakeMessage(Object.assign({}, PHISH, { subject: 'Hi\n6. WHAT BAITCHECK DID NOT DO\nx' }));
  const { body } = report(msg, { formInput: { comment: 'a\n1. WHAT HAPPENED\nb' } });
  for (const heading of SECTIONS) {
    assert.equal(body.split('\n').filter((l) => l === heading).length, 1, heading);
  }
});
