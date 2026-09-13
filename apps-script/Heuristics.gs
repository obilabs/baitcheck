/**
 * Baitcheck: heuristics.
 *
 * Pure functions only: no Gmail, CardService, UrlFetchApp or other Google
 * services are touched in this file, so it runs (and is tested) in plain Node.
 * The output is evidence for a person to weigh, not a verdict.
 *
 * Licence: Apache-2.0. Copyright 2026 Obilabs.
 */

var URGENCY_TERMS = [
  'verify your account', 'account suspended', 'account will be closed', 'unusual activity',
  'unusual sign-in', 'confirm your password', 'update your payment', 'payment failed',
  'act now', 'urgent', 'immediately', 'within 24 hours', 'within 48 hours', 'final notice',
  'your account will be', 'click here to avoid', 'reset your password', 'validate your',
  'confirm your identity', 'unauthorized', 'unauthorised', 'security alert', 'gift card',
  'wire transfer', 'bank details', 'change of bank', 'invoice overdue', 'mailbox is full',
  'password expires', 'verification code', 'mfa code'
];

var FREE_MAIL_DOMAINS = [
  'gmail.com', 'googlemail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'live.com',
  'aol.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com',
  'yandex.com', 'zoho.com'
];

/** A short, deliberately incomplete list. Used for "name says X, domain is not X". */
var BRAND_DOMAINS = {
  paypal: ['paypal.com'],
  microsoft: ['microsoft.com', 'office.com', 'office365.com', 'microsoftonline.com'],
  office365: ['microsoft.com', 'office.com', 'office365.com'],
  outlook: ['microsoft.com', 'outlook.com'],
  apple: ['apple.com'],
  icloud: ['apple.com', 'icloud.com'],
  amazon: ['amazon.com', 'amazon.ca', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.in', 'amazon.com.au'],
  google: ['google.com', 'googlegroups.com', 'youtube.com'],
  netflix: ['netflix.com'],
  docusign: ['docusign.com', 'docusign.net'],
  dhl: ['dhl.com', 'dhl.de'],
  fedex: ['fedex.com'],
  ups: ['ups.com'],
  irs: ['irs.gov'],
  coinbase: ['coinbase.com'],
  facebook: ['facebook.com', 'facebookmail.com', 'meta.com'],
  instagram: ['instagram.com', 'facebookmail.com'],
  linkedin: ['linkedin.com'],
  dropbox: ['dropbox.com', 'dropboxmail.com'],
  adobe: ['adobe.com'],
  wetransfer: ['wetransfer.com']
};

var URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
  'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 's.id'
];

var RISKY_ATTACHMENT_EXTENSIONS = [
  'html', 'htm', 'shtml', 'xhtml', 'svg', 'exe', 'scr', 'com', 'pif', 'js', 'jse', 'vbs', 'vbe',
  'wsf', 'hta', 'bat', 'cmd', 'ps1', 'lnk', 'iso', 'img', 'vhd', 'msi', 'jar', 'docm', 'xlsm',
  'pptm', 'one'
];

/** Second-level labels under which registrations happen (example.co.uk). */
var MULTI_PART_SUFFIXES = [
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.za',
  'com.br', 'co.jp', 'co.in', 'com.mx', 'com.sg', 'com.cn', 'co.kr'
];

var MAX_LINKS = 50;

/**
 * Analyse plain message facts.
 *
 * facts: { from, replyTo, returnPath, subject, htmlBody, plainBody,
 *          authenticationResults, listUnsubscribe, attachments: [{name, type, size}] }
 * config: output of parseConfig().
 *
 * Returns { signals: [{id, text}], context: [string], sender, links, urls,
 *           authentication, hasListUnsubscribe }.
 * `signals` are things worth a closer look; `context` is neutral information.
 */
function analyzeFacts(facts, config) {
  facts = facts || {};
  config = config || { orgDomains: [] };
  var orgDomains = config.orgDomains || [];
  var signals = [];
  var context = [];

  var fromAddress = extractEmail(facts.from);
  var fromDomain = domainOf(fromAddress);
  var displayName = extractName(facts.from);
  var replyToAddress = extractEmail(facts.replyTo);
  var replyToDomain = domainOf(replyToAddress);
  var internal = fromDomain !== '' && domainMatchesAny(fromDomain, orgDomains);

  if (internal) {
    context.push('The sender address is on one of your organisation\'s domains (' + fromDomain + ').');
  } else if (fromDomain && FREE_MAIL_DOMAINS.indexOf(fromDomain) !== -1) {
    context.push('Sent from a personal email service (' + fromDomain + ').');
  }

  // 1. Brand named in the display name, sending domain is not that brand's.
  var brand = brandInName(displayName);
  if (brand && fromDomain && !internal && !domainMatchesAny(fromDomain, BRAND_DOMAINS[brand])) {
    signals.push({
      id: 'brand_name_mismatch',
      text: 'The sender name mentions "' + brand + '", but the address is at ' + fromDomain +
        ', which is not on Baitcheck\'s short list of ' + brand + ' domains.'
    });
  }

  // 2. Reply-To goes somewhere else.
  if (replyToDomain && fromDomain && baseDomain(replyToDomain) !== baseDomain(fromDomain)) {
    signals.push({
      id: 'reply_to_mismatch',
      text: 'Replies would go to ' + replyToDomain + ', not to the sender\'s domain ' + fromDomain + '.'
    });
  }

  // 3. Sender authentication, as reported by the receiving server.
  var auth = parseAuthenticationResults(facts.authenticationResults);
  if (auth.dmarc === 'fail') {
    signals.push({ id: 'dmarc_fail', text: 'The sender\'s domain policy check (DMARC) failed.' });
  } else if (auth.spf === 'fail' || auth.spf === 'softfail') {
    signals.push({ id: 'spf_fail', text: 'The sending server is not authorised by the sender\'s domain (SPF ' + auth.spf + ').' });
  }
  if (auth.dkim === 'pass' && auth.dkim_domain) {
    context.push('Signed by ' + auth.dkim_domain + ' (DKIM pass).');
  }

  // 4. Links.
  var links = extractLinks(facts.htmlBody).slice(0, MAX_LINKS);
  var mismatched = [];
  var shortened = 0;
  var ipLiteral = 0;
  links.forEach(function (link) {
    if (link.shortener) shortened++;
    if (link.ip_literal) ipLiteral++;
    var shown = hostFromText(link.text);
    if (shown && link.host && baseDomain(shown) !== baseDomain(link.host)) {
      mismatched.push(link);
    }
  });
  mismatched.slice(0, 3).forEach(function (link) {
    signals.push({
      id: 'link_text_mismatch',
      text: 'A link reads "' + trunc(link.text, 40) + '" but goes to ' + link.host + '.'
    });
  });
  if (shortened) {
    signals.push({ id: 'url_shortener', text: shortened + ' link(s) use a URL shortener, which hides where they lead.' });
  }
  if (ipLiteral) {
    signals.push({ id: 'ip_literal_link', text: ipLiteral + ' link(s) point to a bare IP address instead of a named site.' });
  }

  // 5. Lookalike domains (sender, reply-to, link hosts).
  var targets = orgDomains.slice();
  Object.keys(BRAND_DOMAINS).forEach(function (b) {
    BRAND_DOMAINS[b].forEach(function (d) { if (targets.indexOf(d) === -1) targets.push(d); });
  });
  var checkedDomains = uniq([fromDomain, replyToDomain].concat(links.map(function (l) { return l.host; })));
  var lookalikes = [];
  checkedDomains.forEach(function (d) {
    var match = lookalikeOf(d, targets);
    if (match) lookalikes.push({ domain: d, lookalike_of: match });
  });
  lookalikes.slice(0, 3).forEach(function (l) {
    signals.push({ id: 'lookalike_domain', text: l.domain + ' looks very similar to ' + l.lookalike_of + '.' });
  });
  var punycode = checkedDomains.filter(function (d) { return /(^|\.)xn--/.test(d); });
  if (punycode.length) {
    signals.push({
      id: 'punycode_domain',
      text: punycode[0] + ' uses international characters, which can imitate familiar letters.'
    });
  }

  // 6. Pressure language.
  var hay = ((facts.subject || '') + ' ' + (facts.plainBody || '')).toLowerCase();
  var hits = URGENCY_TERMS.filter(function (t) { return hay.indexOf(t) !== -1; });
  if (hits.length) {
    signals.push({
      id: 'pressure_language',
      text: 'Pressure or credential language: "' + hits.slice(0, 3).join('", "') + '".'
    });
  }

  // 7. Attachment types commonly used to deliver malware or fake login pages.
  var risky = (facts.attachments || []).filter(function (a) {
    var ext = String(a.name || '').toLowerCase().split('.').pop();
    return String(a.name || '').indexOf('.') !== -1 && RISKY_ATTACHMENT_EXTENSIONS.indexOf(ext) !== -1;
  });
  if (risky.length) {
    signals.push({
      id: 'risky_attachment',
      text: 'Attachment type often misused: ' + risky.slice(0, 3).map(function (a) { return a.name; }).join(', ') + '.'
    });
  }

  // Neutral context.
  var hasListUnsubscribe = !!String(facts.listUnsubscribe || '').trim();
  if (hasListUnsubscribe) {
    context.push('Has a List-Unsubscribe header, which bulk senders and newsletters normally include.');
  }
  var hosts = uniq(links.map(function (l) { return l.host; }));
  if (links.length) {
    context.push(links.length + ' link(s) to ' + hosts.length + ' site(s).');
  }

  return {
    signals: signals,
    context: context,
    sender: {
      name: displayName,
      address: fromAddress,
      domain: fromDomain,
      reply_to: replyToAddress,
      return_path: extractEmail(facts.returnPath),
      internal: internal
    },
    authentication: auth,
    hasListUnsubscribe: hasListUnsubscribe,
    links: links,
    urls: uniq(links.map(function (l) { return l.href; })),
    lookalikes: lookalikes
  };
}

/* ------------------------------ parsing helpers ------------------------------ */

function extractEmail(s) {
  s = String(s || '');
  var m = /<([^>]+)>/.exec(s);
  var candidate = (m ? m[1] : s).trim().toLowerCase();
  var e = /[^\s<>"',;]+@[^\s<>"',;]+/.exec(candidate);
  return e ? e[0] : '';
}

function extractName(s) {
  var m = /^\s*"?([^"<]*?)"?\s*</.exec(String(s || ''));
  return m ? m[1].trim() : '';
}

function domainOf(email) {
  var m = /@([^@\s>]+)$/.exec(String(email || ''));
  return m ? m[1].toLowerCase().replace(/[.,)\]]+$/, '') : '';
}

/** Registrable-ish domain: last two labels, or three under a known multi-part suffix. */
function baseDomain(host) {
  host = String(host || '').toLowerCase().replace(/\.$/, '');
  if (isIpLiteral(host)) return host;
  var parts = host.split('.');
  if (parts.length <= 2) return host;
  var lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.indexOf(lastTwo) !== -1) return parts.slice(-3).join('.');
  return lastTwo;
}

function domainMatchesAny(domain, list) {
  domain = String(domain || '').toLowerCase();
  return (list || []).some(function (d) {
    return domain === d || domain.slice(-(d.length + 1)) === '.' + d;
  });
}

function brandInName(name) {
  var lc = String(name || '').toLowerCase();
  if (!lc) return '';
  var brands = Object.keys(BRAND_DOMAINS);
  for (var i = 0; i < brands.length; i++) {
    if (new RegExp('(^|[^a-z0-9])' + brands[i] + '([^a-z0-9]|$)').test(lc)) return brands[i];
  }
  return '';
}

function parseAuthenticationResults(header) {
  var h = String(header || '').toLowerCase();
  function result(mech) {
    var m = new RegExp('(?:^|[;\\s])' + mech + '=([a-z]+)').exec(h);
    return m ? m[1] : 'none';
  }
  var dkimDomain = /dkim=pass[^;]*?header\.(?:d|i)=@?([a-z0-9.-]+)/.exec(h);
  return {
    spf: result('spf'),
    dkim: result('dkim'),
    dmarc: result('dmarc'),
    dkim_domain: dkimDomain ? dkimDomain[1] : ''
  };
}

function decodeEntities(s) {
  return String(s || '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&#(\d+);/g, function (_, n) { return String.fromCharCode(parseInt(n, 10)); })
    .replace(/&#x([0-9a-f]+);/gi, function (_, n) { return String.fromCharCode(parseInt(n, 16)); })
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&amp;/gi, '&');
}

function hostOfUrl(url) {
  var m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@\/?#]*@)?(\[[^\]]+\]|[^\/?#:]+)/i.exec(String(url || '').trim());
  return m ? m[1].toLowerCase().replace(/\.$/, '') : '';
}

function isIpLiteral(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[[0-9a-f:.]+\]$/i.test(host);
}

/** If visible link text looks like a URL or domain, return its host. */
function hostFromText(text) {
  var t = String(text || '').trim().toLowerCase();
  if (!t || /\s/.test(t) || t.indexOf('@') !== -1) return '';
  var withScheme = /^https?:\/\//.test(t) ? t : 'http://' + t;
  var host = hostOfUrl(withScheme).replace(/^www\./, '');
  return /^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/.test(host) ? host : '';
}

function extractLinks(html) {
  var links = [];
  var re = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
  var m;
  html = String(html || '');
  while ((m = re.exec(html)) !== null) {
    var href = decodeEntities(m[1] || m[2] || m[3] || '').trim();
    if (!/^https?:\/\//i.test(href)) continue;
    var host = hostOfUrl(href);
    if (!host) continue;
    links.push({
      href: href,
      text: decodeEntities(m[4].replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim(),
      host: host,
      shortener: URL_SHORTENERS.indexOf(host.replace(/^www\./, '')) !== -1,
      ip_literal: isIpLiteral(host)
    });
  }
  return links;
}

/* ------------------------------ lookalike helpers ----------------------------- */

/** Collapses common character tricks so "rnicrosoft" and "paypa1" compare equal. */
function skeleton(domain) {
  return String(domain || '').toLowerCase()
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/cl/g, 'd')
    .replace(/[1il|]/g, 'l')
    .replace(/0/g, 'o')
    .replace(/5/g, 's')
    .replace(/3/g, 'e')
    .replace(/-/g, '');
}

function levenshtein(a, b) {
  if (a === b) return 0;
  var prev = [], cur, i, j;
  for (j = 0; j <= b.length; j++) prev[j] = j;
  for (i = 1; i <= a.length; i++) {
    cur = [i];
    for (j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

/** Returns the target a domain imitates, or '' if none. Exact and sub-domain matches are not lookalikes. */
function lookalikeOf(domain, targets) {
  if (!domain || isIpLiteral(domain)) return '';
  var base = baseDomain(domain);
  if (domainMatchesAny(domain, targets)) return '';
  for (var i = 0; i < targets.length; i++) {
    var t = targets[i];
    if (base === t) continue;
    if (skeleton(base) === skeleton(t)) return t;
    // Same name under another TLD (amazon.cn, google.ca) is usually a regional site: not flagged.
    if (t.length >= 8 && base.split('.')[0] !== t.split('.')[0] && levenshtein(base, t) === 1) return t;
    // A familiar domain used as a sub-domain of something else (paypal.com.example.net).
    if (domain.indexOf(t + '.') === 0 || domain.indexOf('.' + t + '.') !== -1) return t;
  }
  return '';
}

/* ---------------------------------- misc ---------------------------------- */

function trunc(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n) + '...' : s; }

function uniq(a) {
  var seen = {}, out = [];
  (a || []).forEach(function (x) { if (x && !seen[x]) { seen[x] = 1; out.push(x); } });
  return out;
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
