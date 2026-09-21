'use strict';
// Loads the Apps Script .gs files into a Node vm context with stubbed Google
// services, so the add-on can be tested without a Google account.

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');

const SCRIPT_DIR = path.join(__dirname, '..');

function gsFiles() {
  return fs.readdirSync(SCRIPT_DIR).filter((f) => f.endsWith('.gs')).sort();
}

function toSigned(buf) {
  return Array.from(buf, (b) => (b > 127 ? b - 256 : b));
}

function fromSigned(arr) {
  return Buffer.from(arr.map((b) => (b + 256) % 256));
}

/** Chainable recorder standing in for every CardService builder. */
function makeBuilder(kind) {
  const calls = [];
  const snapshot = () => ({ kind, calls });
  const proxy = new Proxy(function () {}, {
    get(_t, prop) {
      if (prop === 'build') return () => snapshot();
      if (prop === 'toJSON') return () => snapshot();
      if (typeof prop === 'symbol') return undefined;
      return (...args) => { calls.push([prop, args]); return proxy; };
    }
  });
  return proxy;
}

function makeCardService() {
  return new Proxy({}, {
    get(_t, prop) {
      if (typeof prop === 'string' && prop.startsWith('new')) return () => makeBuilder(prop.slice(3));
      return new Proxy({}, { get: (_x, p) => String(prop) + '.' + String(p) });
    }
  });
}

function fakeMessage(opts) {
  const o = Object.assign({
    from: 'Sender <sender@example.org>',
    replyTo: '',
    subject: 'Hello',
    html: '',
    plain: '',
    headers: {},
    attachments: [],
    raw: 'From: sender@example.org\r\nSubject: Hello\r\n\r\nbody'
  }, opts || {});
  return {
    getFrom: () => o.from,
    getReplyTo: () => o.replyTo,
    getSubject: () => o.subject,
    getDate: () => new Date('2026-09-10T12:00:00Z'),
    getBody: () => o.html,
    getPlainBody: () => o.plain,
    getHeader: (name) => o.headers[name] || '',
    getRawContent: () => o.raw,
    getAttachments: () => o.attachments.map((a) => ({
      getName: () => a.name,
      getContentType: () => a.type || 'application/octet-stream',
      getSize: () => (a.data || '').length,
      getBytes: () => toSigned(Buffer.from(a.data || ''))
    })),
    moveToTrash: () => { throw new Error('moveToTrash must never be called'); }
  };
}

/**
 * Returns { ctx, calls } where ctx holds every global from the .gs files.
 * options: { props, message, fetchResponder(request) -> {code, body} }
 */
function load(options) {
  const opts = options || {};
  const calls = { fetch: [], sendEmail: [], cachePut: [], tokens: [] };
  const cacheStore = new Map();
  const message = opts.message || fakeMessage();
  const responder = opts.fetchResponder || (() => ({ code: 200, body: '{}' }));

  const response = (r) => ({ getResponseCode: () => r.code, getContentText: () => r.body });

  const sandbox = {
    console: { log() {}, warn() {}, error() {}, info() {} },
    CardService: makeCardService(),
    PropertiesService: {
      getScriptProperties: () => ({
        getProperties: () => Object.assign({}, opts.props || {}),
        getProperty: (k) => (opts.props || {})[k] || null
      })
    },
    CacheService: {
      getUserCache: () => ({
        get: (k) => (cacheStore.has(k) ? cacheStore.get(k) : null),
        put: (k, v, ttl) => { calls.cachePut.push({ k, ttl }); cacheStore.set(k, v); }
      }),
      getScriptCache: () => { throw new Error('script cache is shared across users; use the user cache'); }
    },
    UrlFetchApp: {
      fetch: (url, params) => {
        const req = Object.assign({ url }, params || {});
        calls.fetch.push(req);
        return response(responder(req));
      },
      fetchAll: (requests) => requests.map((req) => {
        calls.fetch.push(req);
        return response(responder(req));
      })
    },
    Utilities: {
      DigestAlgorithm: { SHA_256: 'SHA_256' },
      Charset: { UTF_8: 'UTF_8' },
      computeDigest: (_alg, value) => {
        const buf = typeof value === 'string' ? Buffer.from(value, 'utf8') : fromSigned(value);
        return toSigned(crypto.createHash('sha256').update(buf).digest());
      },
      base64EncodeWebSafe: (s) => Buffer.from(s, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_'),
      getUuid: () => crypto.randomUUID(),
      newBlob: (data, type, name) => {
        const buf = Buffer.from(data, 'utf8');
        return {
          getBytes: () => toSigned(buf),
          getName: () => name,
          getContentType: () => type,
          getDataAsString: () => buf.toString('utf8')
        };
      },
      // Records its inputs so tests can see what went into the archive; the
      // bytes are not a real zip.
      zip: (blobs, name) => ({
        getName: () => name,
        getContentType: () => 'application/zip',
        getBytes: () => [],
        zippedBlobs: blobs
      })
    },
    GmailApp: {
      setCurrentMessageAccessToken: (t) => calls.tokens.push(t),
      getMessageById: () => message,
      sendEmail: (to, subject, body, options2) => calls.sendEmail.push({ to, subject, body, options: options2 })
    }
  };

  const ctx = vm.createContext(sandbox);
  for (const f of gsFiles()) {
    vm.runInContext(fs.readFileSync(path.join(SCRIPT_DIR, f), 'utf8'), ctx, { filename: f });
  }
  return { ctx, calls };
}

/** Plain JSON copy (drops vm realm prototypes so deepStrictEqual works). */
function plain(v) {
  return JSON.parse(JSON.stringify(v));
}

function gmailEvent(extra) {
  return Object.assign({ gmail: { messageId: 'msg-123', accessToken: 'token-abc' } }, extra || {});
}

/**
 * Wordings Baitcheck must never use: it reports evidence, and the reader
 * decides. Kept here so the report email and the card are held to one list.
 */
const VERDICT_LANGUAGE = [
  /\bverdict:/i, /\bconfirmed\b/i, /\bmalicious\b/i, /\bfraudulent\b/i,
  /\bthis (message|email) is\b/i, /\bwe (believe|think|assess)\b/i,
  /\b(definitely|certainly|clearly) (a |an )?(scam|phish)/i,
  /\b(high|medium|low) risk\b/i, /\brisk score\b/i, /\blooks safe\b/i, /\bis safe\b/i
];

module.exports = { load, fakeMessage, plain, gmailEvent, gsFiles, SCRIPT_DIR, VERDICT_LANGUAGE };
