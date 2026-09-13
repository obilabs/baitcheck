/**
 * Baitcheck: configuration.
 *
 * Everything is read from Script Properties (Apps Script editor:
 * Project Settings -> Script properties). Nothing here is required for the
 * checks to run; reporting and link lookups stay off until configured.
 *
 *   REPORT_ADDRESS        Mailbox that receives reports. Empty = no Report button.
 *   ORG_DOMAINS           Comma-separated domains that belong to you
 *                         (for "internal sender" and lookalike checks).
 *   LOOKUP_SERVICES       Comma-separated external URL lookups to offer behind
 *                         the "Check links" button: urlhaus, webrisk,
 *                         safebrowsing, virustotal. Empty = no lookups, no
 *                         external requests at all.
 *   URLHAUS_AUTH_KEY      Free key from https://auth.abuse.ch/
 *   WEBRISK_API_KEY       API key from your own Google Cloud project
 *   SAFEBROWSING_API_KEY  API key from your own Google Cloud project
 *   VIRUSTOTAL_API_KEY    Your VirusTotal key
 *
 * Licence: Apache-2.0. Copyright 2026 Obilabs.
 */

var BAITCHECK_VERSION = '0.1.0';

var LOOKUP_KEY_PROPERTY = {
  urlhaus: 'URLHAUS_AUTH_KEY',
  webrisk: 'WEBRISK_API_KEY',
  safebrowsing: 'SAFEBROWSING_API_KEY',
  virustotal: 'VIRUSTOTAL_API_KEY'
};

/** Reads Script Properties into a config object. */
function getConfig() {
  return parseConfig(PropertiesService.getScriptProperties().getProperties() || {});
}

/**
 * Pure: turns a plain property map into config. A lookup service is enabled
 * only when it is listed in LOOKUP_SERVICES AND its key is present.
 */
function parseConfig(props) {
  props = props || {};
  var lookups = {};
  splitList_(props.LOOKUP_SERVICES).forEach(function (name) {
    var keyProp = LOOKUP_KEY_PROPERTY[name];
    var key = keyProp ? String(props[keyProp] || '').trim() : '';
    if (key) lookups[name] = key;
  });
  return {
    reportAddress: String(props.REPORT_ADDRESS || '').trim(),
    orgDomains: splitList_(props.ORG_DOMAINS),
    lookups: lookups,
    lookupNames: Object.keys(lookups)
  };
}

function splitList_(value) {
  return String(value || '')
    .split(',')
    .map(function (s) { return s.trim().toLowerCase(); })
    .filter(function (s) { return s.length > 0; });
}
