/**
 * Baitcheck: optional external URL reputation lookups.
 *
 * Nothing in this file runs when a message is opened. `checkUrls` is called
 * only from the "Check links" button, and only for services the admin listed
 * in LOOKUP_SERVICES with a key. Only the link URLs are sent, never the
 * message itself. Results are cached per user for a short time.
 *
 * Licence: Apache-2.0. Copyright 2026 Obilabs.
 */

var LOOKUP_CACHE_SECONDS = 3600;
var MAX_LOOKUP_URLS = 20;

var LOOKUP_LABELS = {
  urlhaus: 'URLhaus',
  webrisk: 'Google Web Risk',
  safebrowsing: 'Google Safe Browsing',
  virustotal: 'VirusTotal'
};

/**
 * Looks up URLs with each enabled service.
 * Returns [{ url, service, status: 'listed'|'not_listed'|'error', detail }].
 */
function checkUrls(urls, config) {
  var names = (config && config.lookupNames) || [];
  urls = uniq(urls || []).slice(0, MAX_LOOKUP_URLS);
  if (!names.length || !urls.length) return [];

  var cache = CacheService.getUserCache();
  var results = [];

  names.forEach(function (service) {
    var key = config.lookups[service];
    var pending = [];
    urls.forEach(function (url) {
      var cached = cache.get(lookupCacheKey_(service, url));
      if (cached) {
        var c = JSON.parse(cached);
        results.push({ url: url, service: service, status: c.status, detail: c.detail, cached: true });
      } else {
        pending.push(url);
      }
    });
    if (!pending.length) return;

    var fresh;
    try {
      fresh = service === 'safebrowsing' ? safeBrowsingLookup_(pending, key) : perUrlLookup_(service, pending, key);
    } catch (err) {
      fresh = pending.map(function (url) {
        return { url: url, service: service, status: 'error', detail: String(err && err.message || err) };
      });
    }
    fresh.forEach(function (r) {
      if (r.status !== 'error') {
        cache.put(lookupCacheKey_(service, r.url), JSON.stringify({ status: r.status, detail: r.detail }), LOOKUP_CACHE_SECONDS);
      }
      results.push(r);
    });
  });
  return results;
}

function perUrlLookup_(service, urls, key) {
  var requests = urls.map(function (url) { return buildLookupRequest_(service, url, key); });
  var responses = UrlFetchApp.fetchAll(requests);
  return urls.map(function (url, i) {
    return parseLookupResponse_(service, url, responses[i].getResponseCode(), responses[i].getContentText());
  });
}

function buildLookupRequest_(service, url, key) {
  if (service === 'urlhaus') {
    return {
      url: 'https://urlhaus-api.abuse.ch/v1/url/',
      method: 'post',
      headers: { 'Auth-Key': key },
      payload: { url: url },
      muteHttpExceptions: true
    };
  }
  if (service === 'webrisk') {
    return {
      url: 'https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING' +
        '&threatTypes=UNWANTED_SOFTWARE&uri=' + encodeURIComponent(url) + '&key=' + encodeURIComponent(key),
      method: 'get',
      muteHttpExceptions: true
    };
  }
  if (service === 'virustotal') {
    var id = Utilities.base64EncodeWebSafe(url).replace(/=+$/, '');
    return {
      url: 'https://www.virustotal.com/api/v3/urls/' + id,
      method: 'get',
      headers: { 'x-apikey': key },
      muteHttpExceptions: true
    };
  }
  throw new Error('Unknown lookup service: ' + service);
}

function parseLookupResponse_(service, url, code, text) {
  var base = { url: url, service: service };
  function out(status, detail) { base.status = status; base.detail = detail || ''; return base; }
  var body;
  try { body = JSON.parse(text || '{}'); } catch (e) { body = null; }

  if (service === 'virustotal' && code === 404) return out('not_listed', 'Not seen by VirusTotal');
  if (code !== 200 || !body) return out('error', 'HTTP ' + code);

  if (service === 'urlhaus') {
    if (body.query_status === 'ok') return out('listed', body.threat || 'listed');
    if (body.query_status === 'no_results') return out('not_listed');
    return out('error', String(body.query_status || 'unexpected response'));
  }
  if (service === 'webrisk') {
    if (body.threat && body.threat.threatTypes) return out('listed', body.threat.threatTypes.join(', '));
    return out('not_listed');
  }
  if (service === 'virustotal') {
    var stats = body.data && body.data.attributes && body.data.attributes.last_analysis_stats;
    if (!stats) return out('error', 'unexpected response');
    if (stats.malicious > 0) return out('listed', stats.malicious + ' engine(s) flag it');
    return out('not_listed');
  }
  return out('error', 'unknown service');
}

function safeBrowsingLookup_(urls, key) {
  var payload = {
    client: { clientId: 'baitcheck', clientVersion: BAITCHECK_VERSION },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: urls.map(function (u) { return { url: u }; })
    }
  };
  var res = UrlFetchApp.fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + encodeURIComponent(key), {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  });
  var code = res.getResponseCode();
  if (code !== 200) {
    return urls.map(function (url) { return { url: url, service: 'safebrowsing', status: 'error', detail: 'HTTP ' + code }; });
  }
  var matches = (JSON.parse(res.getContentText() || '{}').matches) || [];
  return urls.map(function (url) {
    var hit = matches.filter(function (m) { return m.threat && m.threat.url === url; });
    return hit.length
      ? { url: url, service: 'safebrowsing', status: 'listed', detail: hit.map(function (m) { return m.threatType; }).join(', ') }
      : { url: url, service: 'safebrowsing', status: 'not_listed', detail: '' };
  });
}

function lookupCacheKey_(service, url) {
  return 'bc:' + service + ':' + sha256Hex(url);
}

/** SHA-256 of a string or byte array, as lowercase hex. */
function sha256Hex(input) {
  var bytes = typeof input === 'string'
    ? Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, input, Utilities.Charset.UTF_8)
    : Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, input);
  return bytesToHex(bytes);
}

function bytesToHex(bytes) {
  return bytes.map(function (b) { return ('0' + ((b + 256) % 256).toString(16)).slice(-2); }).join('');
}
