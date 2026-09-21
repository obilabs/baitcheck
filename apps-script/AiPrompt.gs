/**
 * Baitcheck: the AI prompt.
 *
 * THIS FILE IS THE SINGLE SOURCE OF THE PROMPT. The report packet publishes
 * exactly what `buildAiPrompt` returns, and any AI call added later must send
 * exactly what `buildAiPrompt` returns — one function, so the published text
 * and the sent text cannot drift. Do not write a second prompt anywhere.
 *
 * Why the packet publishes it at all: AI is off by default and nothing leaves
 * the mailbox when a message is opened (docs/DECISIONS.md, 2026-09-13). An
 * administrator deciding whether to turn AI on should be able to read the exact
 * words that would leave the mailbox, on a real message, before turning it on
 * — not a description of them. So the prompt travels in the packet marked as
 * not sent. It is a privacy feature, not a debug field.
 *
 * Bump AI_PROMPT_TEMPLATE_VERSION whenever the wording or the fields change:
 * receivers compare prompts across reports, and an unversioned change makes
 * that comparison silently wrong.
 *
 * Pure: no Google services, so it runs and is tested in plain Node.
 *
 * Licence: Apache-2.0. Copyright 2026 Obilabs.
 */

var AI_PROMPT_TEMPLATE_VERSION = 'baitcheck-triage-1';

/**
 * The prompt carries header facts and the local checks' own output. It does
 * NOT carry the message body, the subject aside, and it does not carry
 * attachments. If that ever changes, set this to true and say so in
 * docs/REPORT-PACKET.md: the packet's `prompt_includes_message_body` field is
 * how an administrator learns that turning AI on would send the text people
 * wrote to each other.
 */
var AI_PROMPT_INCLUDES_BODY = false;

/** Assembled prompts are capped so one enormous message cannot bloat a report. */
var AI_PROMPT_MAX_CHARS = 6000;

/**
 * What the packet says about a prompt it carries. The first is the default and
 * the one that matters: it must be unmistakable that nothing was sent, since
 * the prompt sitting in a report otherwise reads like evidence that it was.
 */
var AI_PROMPT_NOT_SENT_NOTE = 'Not sent. AI is off, so this prompt was not sent to any provider and ' +
  'none of it left the mailbox. It is included so an administrator can read exactly what would be ' +
  'sent before turning AI on.';

var AI_PROMPT_SENT_NOTE = 'Sent. This is the text that went to the provider named above. Its reply is ' +
  'an opinion from that provider, not a verdict, and is recorded in summary and label.';

/**
 * Builds the prompt for one message.
 *
 * headers: the output of buildHeaderFacts (Report.gs) — the same filtered set
 *          of headers the packet carries, so the prompt can never quietly
 *          include a header the packet does not disclose.
 * analysis: the output of analyzeFacts.
 * subject: the message subject (the one piece of message content included).
 */
function buildAiPrompt(headers, analysis, subject) {
  headers = headers || {};
  analysis = analysis || {};
  var lines = [];

  lines.push('Baitcheck prompt template ' + AI_PROMPT_TEMPLATE_VERSION + '.');
  lines.push('');
  lines.push('A person received the email described below and is deciding what to do with it.');
  lines.push('Baitcheck has already run local checks on it. Use only the facts given here.');
  lines.push('');
  lines.push('Write at most five short sentences, in plain language, covering:');
  lines.push('1. what these facts do and do not show about who sent the message;');
  lines.push('2. the one question the reader could ask that would settle it.');
  lines.push('');
  lines.push('Rules: give no verdict, no score and no rating. Do not tell the reader to delete,');
  lines.push('report or trust the message. Where the facts are not enough to tell, say so. A');
  lines.push('field that is missing below was not in the headers; treat it as unknown.');
  lines.push('The message body is not included in this prompt.');
  lines.push('');

  lines.push('HEADER FACTS');
  lines.push('Subject: ' + promptLine_(subject || '(none)'));
  var from = headers.from || {};
  if (from.name) lines.push('From name: ' + promptLine_(from.name));
  if (from.address) lines.push('From address: ' + promptLine_(from.address));
  appendHeaderLine_(lines, 'Reply-To', headers.reply_to);
  appendHeaderLine_(lines, 'Return-Path', headers.return_path);
  appendHeaderLine_(lines, 'Sender', headers.sender);
  appendHeaderLine_(lines, 'Date', headers.date);
  appendHeaderLine_(lines, 'Message-ID', headers.message_id);
  appendHeaderLine_(lines, 'List-Id', headers.list_id);
  appendHeaderLine_(lines, 'X-BeenThere', headers.x_been_there);
  appendHeaderLine_(lines, 'X-Original-Sender', headers.x_original_sender);
  appendHeaderLine_(lines, 'Delivered-To', headers.delivered_to);
  appendHeaderLine_(lines, 'Authentication-Results', headers.authentication_results);
  appendHeaderLine_(lines, 'X-Original-Authentication-Results', headers.x_original_authentication_results);
  lines.push('List-Unsubscribe present: ' + (headers.has_list_unsubscribe ? 'yes' : 'no'));
  lines.push('');

  lines.push('WHAT BAITCHECK\'S CHECKS NOTICED');
  var signals = analysis.signals || [];
  if (signals.length) {
    signals.forEach(function (s) { lines.push('- [' + s.id + '] ' + promptLine_(s.text)); });
  } else {
    lines.push('- Nothing. Its checks are simple and miss things.');
  }
  lines.push('');

  lines.push('CHECKS THAT RAN AND NOTICED NOTHING');
  var fired = {};
  signals.forEach(function (s) { fired[s.id] = true; });
  var clear = (analysis.checksRun || []).filter(function (id) { return !fired[id]; });
  lines.push(clear.length ? clear.join(', ') : 'None.');
  lines.push('');
  lines.push('Any other check was not run, because the headers did not carry what it needs.');
  lines.push('');

  var hosts = uniq((analysis.links || []).map(function (l) { return l.host; }));
  lines.push('LINK HOSTS (' + hosts.length + ')');
  lines.push(hosts.length ? hosts.slice(0, 20).join(', ') +
    (hosts.length > 20 ? ', +' + (hosts.length - 20) + ' more' : '') : 'None.');

  var prompt = lines.join('\n');
  return prompt.length > AI_PROMPT_MAX_CHARS
    ? prompt.slice(0, AI_PROMPT_MAX_CHARS) + '\n[truncated by Baitcheck at ' + AI_PROMPT_MAX_CHARS + ' characters]'
    : prompt;
}

/** Headers absent from the message are left out entirely, as in the packet. */
function appendHeaderLine_(lines, label, value) {
  if (value) lines.push(label + ': ' + promptLine_(value));
}

function promptLine_(value) {
  return String(value == null ? '' : value).replace(/[\r\n]+/g, ' ').slice(0, 400);
}
