'use strict';
// The card's icons and colours. They only reinforce the words, so the rules
// here are about not getting them wrong: an unknown icon name renders nothing,
// green would read as an all-clear Baitcheck never gives, and a fixed colour
// has to be readable on both Gmail themes.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { load, fakeMessage, plain, gmailEvent, SCRIPT_DIR } = require('./harness');

/**
 * Icon names the card may use, each checked on 2026-09-21 against both of
 * Google's published name lists (present in each):
 * - Material Symbols: github.com/google/material-design-icons,
 *   variablefont/MaterialSymbolsOutlined[FILL,GRAD,opsz,wght].codepoints
 * - Material Icons: the same repo, font/MaterialIcons-Regular.codepoints
 * MaterialIcon.setName takes "the icon name defined in Google Font Icon"
 * (developers.google.com/apps-script/reference/card-service/material-icon).
 * Adding an icon to Ui.gs means checking it there and adding it here.
 */
const VERIFIED_MATERIAL_ICONS = new Set([
  'link_off', 'attach_file', 'alternate_email', 'badge', 'payments', 'campaign', 'help',
  'arrow_right', 'send'
]);

const CAUTION = ['link', 'attachment', 'sender', 'company_claim', 'ask'];
const NEUTRAL = ['bulk', 'unclear'];

// White, and the dark greys Gmail's dark theme uses behind the side panel.
const LIGHT_BG = '#ffffff';
const DARK_BG = '#202124';
const DARKEST_SURFACE = '#2d2e30';

function rgb(hex) {
  return [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
}
function luminance(hex) {
  const [r, g, b] = rgb(hex).map((v) => (v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4)));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrast(a, b) {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}
/** Hue in degrees and HSL saturation. */
function hueSat(hex) {
  const [r, g, b] = rgb(hex);
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const d = max - min;
  const l = (max + min) / 2;
  if (d === 0) return { hue: 0, sat: 0 };
  const sat = d / (1 - Math.abs(2 * l - 1));
  let hue;
  if (max === r) hue = 60 * (((g - b) / d) % 6);
  else if (max === g) hue = 60 * ((b - r) / d + 2);
  else hue = 60 * ((r - g) / d + 4);
  return { hue: (hue + 360) % 360, sat };
}
/** Yellow-green through green to green-cyan. Brand teal (about 174 degrees) sits outside. */
function isGreenFamily(hex) {
  const { hue, sat } = hueSat(hex);
  return sat > 0.15 && hue >= 70 && hue <= 165;
}

/** An analysis that produces the given headline, for rendering the card directly. */
function analysisFor(ctx, headlineId) {
  const h = plain(ctx.SUMMARY_HEADLINES).find((x) => x.id === headlineId);
  return {
    summary: { headline_id: h.id, headline: h.headline, next_step: h.next_step, reasons: ['A reason.'] },
    signals: [], context: [], urls: [], relayNotes: [], checksRun: []
  };
}

function iconNames(json) {
  return [...json.matchAll(/"setName",\["([^"]*)"\]/g)].map((m) => m[1]);
}

test('each of the seven headlines has its own icon, and every icon name is a real Material name', () => {
  const { ctx } = load();
  const ids = plain(ctx.SUMMARY_HEADLINES).map((h) => h.id);
  const style = plain(ctx.HEADLINE_STYLE);
  assert.deepEqual(Object.keys(style).sort(), [...ids].sort(), 'one style per headline, no strays');
  const icons = ids.map((id) => style[id].icon);
  assert.equal(new Set(icons).size, ids.length, 'no two headlines share an icon');
  for (const name of icons.concat([ctx.REASON_ICON, ctx.REPORTED_ICON])) {
    assert.ok(VERIFIED_MATERIAL_ICONS.has(name), name + ' is not a verified Material icon name');
  }
});

test('the rendered card shows the headline icon, and uses no unverified icon anywhere', () => {
  const { ctx } = load();
  const config = ctx.parseConfig({ REPORT_ADDRESS: 'security@acme.com' });
  for (const id of CAUTION.concat(NEUTRAL)) {
    const json = JSON.stringify(ctx.buildMessageCard(analysisFor(ctx, id), config, null));
    const names = iconNames(json);
    assert.equal(names[0], plain(ctx.HEADLINE_STYLE)[id].icon, id);
    for (const n of names) assert.ok(VERIFIED_MATERIAL_ICONS.has(n), id + ': ' + n);
  }
  const reported = JSON.stringify(ctx.buildReportedCard({ message: 'Sent to your security team.', reportId: 'r1' }));
  for (const n of iconNames(reported)) assert.ok(VERIFIED_MATERIAL_ICONS.has(n), n);
  // Every setName literal in the source is covered too.
  const src = fs.readFileSync(path.join(SCRIPT_DIR, 'Ui.gs'), 'utf8');
  for (const m of src.matchAll(/(?:icon|_ICON)\s*[:=]\s*'([a-z0-9_]+)'/g)) {
    assert.ok(VERIFIED_MATERIAL_ICONS.has(m[1]), 'Ui.gs names ' + m[1]);
  }
});

test('caution headlines are warm and filled, bulk and "your call" are grey and outlined', () => {
  const { ctx } = load();
  const config = ctx.parseConfig({});
  const tones = plain(ctx.CARD_TONES);
  for (const [ids, tone, filled] of [[CAUTION, 'caution', true], [NEUTRAL, 'neutral', false]]) {
    for (const id of ids) {
      assert.equal(plain(ctx.HEADLINE_STYLE)[id].tone, tone, id);
      const json = JSON.stringify(ctx.buildMessageCard(analysisFor(ctx, id), config, null));
      assert.ok(json.includes('<font color=\\"' + tones[tone] + '\\"><b>'), id + ' headline colour');
      assert.ok(json.includes('"setFill",[' + filled + ']'), id + ' icon fill');
    }
  }
  const { hue } = hueSat(tones.caution);
  assert.ok(hue <= 45, 'caution is red to amber, got hue ' + hue.toFixed(0));
  assert.ok(hueSat(tones.neutral).sat < 0.05, 'neutral is grey');
});

test('no colour on the card is green-family', () => {
  const src = fs.readFileSync(path.join(SCRIPT_DIR, 'Ui.gs'), 'utf8');
  const colours = new Set((src.match(/#[0-9a-fA-F]{6}\b/g) || []).map((c) => c.toLowerCase()));
  // And whatever the cards actually render, across the fixtures and every headline.
  const { ctx } = load();
  const configs = [ctx.parseConfig({ REPORT_ADDRESS: 'security@acme.com' }), ctx.parseConfig({})];
  for (const config of configs) {
    for (const h of plain(ctx.SUMMARY_HEADLINES)) {
      const json = JSON.stringify(ctx.buildMessageCard(analysisFor(ctx, h.id), config, null));
      for (const c of json.match(/#[0-9a-fA-F]{6}\b/g) || []) colours.add(c.toLowerCase());
    }
  }
  assert.ok(colours.size >= 3, 'expected the two tones and the brand colour, got ' + [...colours]);
  for (const c of colours) assert.ok(!isGreenFamily(c), c + ' is green-family');
  // The check itself catches green, including Google's "safe" green.
  for (const g of ['#188038', '#34a853', '#00ff00', '#2e7d32', '#9acd32']) assert.ok(isGreenFamily(g), g);
});

test('coloured text reads on both Gmail themes; the Report label reads on the brand colour', () => {
  const { ctx } = load();
  for (const [tone, hex] of Object.entries(plain(ctx.CARD_TONES))) {
    assert.ok(contrast(hex, LIGHT_BG) >= 4, tone + ' on light: ' + contrast(hex, LIGHT_BG).toFixed(2));
    assert.ok(contrast(hex, DARK_BG) >= 3.7, tone + ' on dark: ' + contrast(hex, DARK_BG).toFixed(2));
    assert.ok(contrast(hex, DARKEST_SURFACE) >= 3, tone + ' on dark surface');
  }
  // Gmail sets the label to "a contrasting color" on a coloured button
  // (google.apps.card.v1 Button.color); white on the brand teal:
  assert.ok(contrast(ctx.CARD_BRAND_COLOR, '#ffffff') >= 4.5);
});

test('only the headline is coloured; next step, reasons and the privacy line keep the theme colour', () => {
  const { ctx } = load({ props: { REPORT_ADDRESS: 'security@acme.com' }, message: fakeMessage() });
  const card = plain(ctx.onGmailMessageOpen(gmailEvent()));
  const json = JSON.stringify(card);
  assert.equal((json.match(/<font color/g) || []).length, 1);
});

test('the note input has one short label and no hint', () => {
  const { ctx } = load({ props: { REPORT_ADDRESS: 'security@acme.com' }, message: fakeMessage() });
  const json = JSON.stringify(ctx.onGmailMessageOpen(gmailEvent()));
  assert.equal(json.split(ctx.NOTE_TITLE).length - 1, 1, 'the title is set once');
  assert.doesNotMatch(json, /"setHint"/);
  assert.doesNotMatch(json, /Note for your security team/);
});

test('Report is a filled brand-colour button in the fixed footer, with Check links as the outlined secondary', () => {
  const props = { REPORT_ADDRESS: 'security@acme.com', LOOKUP_SERVICES: 'urlhaus', URLHAUS_AUTH_KEY: 'k' };
  const message = fakeMessage({ html: '<a href="https://example.org/x">example.org</a>' });
  const { ctx } = load({ props, message });
  const card = plain(ctx.onGmailMessageOpen(gmailEvent()));
  const footer = card.calls.find((c) => c[0] === 'setFixedFooter')[1][0];
  const primary = footer.calls.find((c) => c[0] === 'setPrimaryButton')[1][0].calls;
  const secondary = footer.calls.find((c) => c[0] === 'setSecondaryButton')[1][0].calls;
  assert.deepEqual(primary.find((c) => c[0] === 'setBackgroundColor')[1], [ctx.CARD_BRAND_COLOR]);
  assert.deepEqual(primary.find((c) => c[0] === 'setTextButtonStyle')[1], ['TextButtonStyle.FILLED']);
  assert.deepEqual(secondary.find((c) => c[0] === 'setText')[1], ['Check links']);
  assert.deepEqual(secondary.find((c) => c[0] === 'setTextButtonStyle')[1], ['TextButtonStyle.OUTLINED']);
  assert.doesNotMatch(JSON.stringify(card.calls.filter((c) => c[0] === 'addSection')), /"ButtonSet"/,
    'no second copy of the buttons in the body');
});

test('without a report address there is no footer, and Check links stays in the card', () => {
  const props = { LOOKUP_SERVICES: 'urlhaus', URLHAUS_AUTH_KEY: 'k' };
  const message = fakeMessage({ html: '<a href="https://example.org/x">example.org</a>' });
  const { ctx } = load({ props, message });
  const json = JSON.stringify(ctx.onGmailMessageOpen(gmailEvent()));
  assert.doesNotMatch(json, /setFixedFooter/);
  assert.match(json, /"ButtonSet".*Check links/);
});
