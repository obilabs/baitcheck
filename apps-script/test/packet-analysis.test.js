'use strict';
// What a receiving dashboard (or a person) gets besides the prose: the checks
// as data, the header facts they rest on, and the exact AI prompt — which, with
// AI off, must arrive marked as not sent.

const test = require('node:test');
const assert = require('node:assert/strict');
const { load, fakeMessage, gmailEvent, VERDICT_LANGUAGE } = require('./harness');

const PROPS = { REPORT_ADDRESS: 'security@acme.com', ORG_DOMAINS: 'acme.com' };

// A real-looking cold sales email: a company role from a consumer mailbox, a
// Reply-To elsewhere, one shortened link.
const COLD_SALES = {
  from: '"Chris Wu · Anvol" <carebearvao@mail.com>',
  replyTo: 'chris@anvol-sales.co',
  subject: 'Quick question about your procurement',
  html: '<a href="https://anvol.example/demo">book a demo</a> <a href="https://bit.ly/x1">deck</a>',
  plain: 'Founder here. Worth 15 minutes?',
  headers: {
    'Authentication-Results': 'mx.google.com; spf=pass; dkim=pass header.d=mail.com; dmarc=pass',
    'Return-Path': '<carebearvao@mail.com>',
    'Message-ID': '<CA+9f7d1@mail.com>',
    'Delivered-To': 'mike@acme.com',
    Sender: 'bounce@mail.com'
  },
  raw: 'From: carebearvao@mail.com\r\nSubject: Quick question\r\n\r\nFounder here.'
};

function report(message, props) {
  const { ctx, calls } = load({ props: props || PROPS, message: message || fakeMessage(COLD_SALES) });
  ctx.onReport(gmailEvent());
  const attachments = calls.sendEmail[0].options.attachments;
  const packet = JSON.parse(attachments[attachments.length - 1].getDataAsString());
  return { ctx, packet, mail: calls.sendEmail[0] };
}

test('the packet carries the checks that fired, with their evidence, and the ones that ran clear', () => {
  const { packet } = report();
  const a = packet.analysis;
  assert.equal(a.engine, 'heuristics-0.1.0', 'the engine version stays');

  const fired = a.findings.map((f) => f.id);
  assert.ok(fired.includes('company_claim_personal_account'));
  assert.ok(fired.includes('reply_to_mismatch'));
  assert.ok(fired.includes('url_shortener'));

  const claim = a.findings.find((f) => f.id === 'company_claim_personal_account');
  assert.equal(claim.evidence.provider, 'mail.com');
  assert.equal(claim.evidence.sender_address, 'carebearvao@mail.com');
  assert.equal(claim.evidence.claim, 'Anvol');
  assert.equal(claim.text, packet.verdict.reasons[fired.indexOf('company_claim_personal_account')],
    'the prose and the structured finding are the same text, not two wordings');

  const replyTo = a.findings.find((f) => f.id === 'reply_to_mismatch');
  assert.deepEqual(replyTo.evidence,
    { reply_to: 'chris@anvol-sales.co', reply_to_domain: 'anvol-sales.co', sender_domain: 'mail.com' });

  const shortener = a.findings.find((f) => f.id === 'url_shortener');
  assert.deepEqual(shortener.evidence, { count: 1, hosts: ['bit.ly'] });

  // Checked and clear: these ran on this message and found nothing.
  assert.ok(a.checks_clear.includes('brand_name_mismatch'));
  assert.ok(a.checks_clear.includes('dmarc_fail'));
  assert.ok(a.checks_clear.includes('risky_attachment'));
  assert.ok(a.checks_clear.includes('pressure_language'));
  // Never checked: no relay, so the original-message checks had nothing to run
  // against and appear in neither list.
  assert.ok(!a.checks_clear.includes('original_dmarc_fail'));
  assert.ok(!fired.includes('original_dmarc_fail'));
  // No id may be in both lists.
  assert.deepEqual(a.checks_clear.filter((id) => fired.includes(id)), []);
});

test('a check with no header to run against is absent, not reported clear', () => {
  const noAuth = Object.assign({}, COLD_SALES, { headers: { 'Return-Path': '<carebearvao@mail.com>' } });
  const { packet } = report(fakeMessage(noAuth));
  const ids = packet.analysis.checks_clear.concat(packet.analysis.findings.map((f) => f.id));
  assert.ok(!ids.includes('dmarc_fail'), 'no Authentication-Results header means the check did not run');
  assert.ok(!ids.includes('spf_fail'));
  assert.ok(packet.analysis.checks_clear.includes('pressure_language'), 'checks that did run are still listed');
});

test('headers present are carried exactly as received, and absent ones are omitted', () => {
  const { packet } = report();
  const h = packet.headers;
  assert.deepEqual(h.from, { name: 'Chris Wu · Anvol', address: 'carebearvao@mail.com' });
  assert.equal(h.reply_to, 'chris@anvol-sales.co');
  assert.equal(h.return_path, '<carebearvao@mail.com>');
  assert.equal(h.sender, 'bounce@mail.com');
  assert.equal(h.message_id, '<CA+9f7d1@mail.com>');
  assert.equal(h.delivered_to, 'mike@acme.com');
  assert.equal(h.authentication_results, 'mx.google.com; spf=pass; dkim=pass header.d=mail.com; dmarc=pass');
  assert.equal(h.date, '2026-09-10T12:00:00.000Z');
  assert.equal(h.has_list_unsubscribe, false, 'presence flag only, never the unsubscribe address');

  // Not carried by this message: omitted, not null.
  for (const key of ['list_id', 'x_been_there', 'x_original_sender', 'x_original_authentication_results']) {
    assert.ok(!(key in h), key + ' must be omitted when the message does not carry it');
  }
  assert.equal(Object.values(h).filter((v) => v === null).length, 0, 'no nulls in the headers block');
});

test('list headers appear when the message came through a group', () => {
  const viaList = Object.assign({}, COLD_SALES, {
    from: "'Chris Wu' via ObiLabs Hello <hello@acme.com>",
    headers: Object.assign({}, COLD_SALES.headers, {
      'List-Id': '"ObiLabs Hello" <hello.acme.com>',
      'X-Original-Sender': 'carebearvao@mail.com',
      'X-BeenThere': 'hello@acme.com',
      'X-Original-Authentication-Results': 'mx.google.com; spf=pass; dkim=none; dmarc=none',
      'List-Unsubscribe': '<mailto:hello+unsubscribe@acme.com>'
    })
  });
  const { packet } = report(fakeMessage(viaList));
  assert.equal(packet.headers.list_id, '"ObiLabs Hello" <hello.acme.com>');
  assert.equal(packet.headers.x_original_sender, 'carebearvao@mail.com');
  assert.equal(packet.headers.x_original_authentication_results, 'mx.google.com; spf=pass; dkim=none; dmarc=none');
  assert.equal(packet.headers.has_list_unsubscribe, true);
  assert.ok(!JSON.stringify(packet.headers).includes('unsubscribe@acme.com'),
    'the List-Unsubscribe value identifies the recipient; only its presence travels');
});

test('the headers block is a filtered set, not every header', () => {
  const noisy = Object.assign({}, COLD_SALES, {
    headers: Object.assign({}, COLD_SALES.headers, {
      Received: 'from mx.internal.acme.com by 10.0.0.4 for <hr-payroll@acme.com>',
      'X-Spam-Report': 'internal scanner detail',
      Bcc: 'someone.else@acme.com'
    })
  });
  const { packet } = report(fakeMessage(noisy));
  const serialised = JSON.stringify(packet.headers);
  assert.ok(!serialised.includes('mx.internal.acme.com'), 'Received hops are not carried');
  assert.ok(!serialised.includes('someone.else@acme.com'), 'other recipients are not carried');
  assert.ok(!serialised.includes('internal scanner detail'));
});

test('with AI off the prompt travels marked as not sent, with its template version', () => {
  const { packet } = report();
  const ai = packet.verdict.ai;
  assert.equal(ai.provider, 'none');
  assert.equal(ai.sent, false, 'AI is off by default: nothing was sent');
  assert.equal(ai.prompt_template_version, 'baitcheck-triage-1');
  assert.equal(ai.prompt_includes_message_body, false);
  assert.ok(ai.prompt.length > 0);
  assert.match(ai.note, /^Not sent\./);
  assert.match(ai.note, /not sent to any provider and none of it left the mailbox/);
  assert.match(ai.note, /before turning AI on/);
  assert.equal(ai.summary, '');
  assert.equal(ai.label, '');
});

test('the prompt in the packet is byte-identical to the one the code would send', () => {
  const { ctx, packet } = report();
  const facts = ctx.readMessageFacts(fakeMessage(COLD_SALES));
  const analysis = ctx.analyzeFacts(facts, ctx.parseConfig(PROPS));
  const headers = ctx.buildHeaderFacts(facts, analysis);
  // One builder, called the way a real AI call would call it.
  assert.equal(packet.verdict.ai.prompt, ctx.buildAiPrompt(headers, analysis, facts.subject));
});

test('the prompt carries the header facts and the check ids, and no message body', () => {
  const { packet } = report();
  const prompt = packet.verdict.ai.prompt;
  assert.match(prompt, /^Baitcheck prompt template baitcheck-triage-1\./);
  assert.match(prompt, /The message body is not included in this prompt\./);
  assert.match(prompt, /From address: carebearvao@mail\.com/);
  assert.match(prompt, /Reply-To: chris@anvol-sales\.co/);
  assert.match(prompt, /Authentication-Results: mx\.google\.com/);
  assert.match(prompt, /List-Unsubscribe present: no/);
  assert.match(prompt, /\[reply_to_mismatch\]/);
  assert.match(prompt, /CHECKS THAT RAN AND NOTICED NOTHING/);
  assert.match(prompt, /brand_name_mismatch/);
  assert.match(prompt, /bit\.ly/);
  // Body text never appears, and the headers the packet omits are omitted here too.
  assert.ok(!prompt.includes('Founder here. Worth 15 minutes?'), 'the plain body must not reach the prompt');
  assert.ok(!/^List-Id:/m.test(prompt), 'a header the message did not carry has no line');
  assert.ok(prompt.length <= 6100);
});

test('a long message cannot make the prompt unbounded', () => {
  const many = [];
  for (let i = 0; i < 400; i++) many.push('<a href="https://host' + i + '.example/x">link ' + i + '</a>');
  const big = Object.assign({}, COLD_SALES, { html: many.join(' '), subject: 'x'.repeat(2000) });
  const { packet } = report(fakeMessage(big));
  assert.ok(packet.verdict.ai.prompt.length <= 6100, 'prompt stays capped');
});

test('nothing in the new fields gives a verdict', () => {
  const { packet } = report();
  const serialised = JSON.stringify([packet.analysis, packet.headers, packet.verdict.ai]);
  for (const pattern of VERDICT_LANGUAGE) {
    assert.doesNotMatch(serialised, pattern, 'new packet fields must not use ' + pattern);
  }
  assert.equal(packet.verdict.score, null, 'still no score');
  assert.equal(packet.analysis.score, undefined, 'the analysis block carries no score of its own');
  assert.equal(packet.analysis.label, undefined, 'and no label of its own');
});

test('a report still sends when AI is off and no prompt could be answered', () => {
  const { mail, packet } = report();
  assert.ok(mail.options.attachments.length >= 1);
  assert.equal(packet.schema_version, 1, 'the new fields are additive; the schema stays v1');
});
